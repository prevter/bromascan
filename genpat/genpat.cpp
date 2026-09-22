#include "genpat.hpp"

#include <fstream>
#include <ThreadPool.hpp>
#include <fmt/format.h>

#include <tools.hpp>
#include <binaries/Mach-O.hpp>
#include <binaries/PE.hpp>
#include <broma/Reader.hpp>

#include <nlohmann/json.hpp>

#include "asm/aarch64.hpp"
#include "asm/amd64.hpp"

namespace genpat {
    static std::string makeQualifiedName(std::string_view cls, std::string_view fn) {
        return fmt::format("{}::{}", cls, fn);
    }

    std::unordered_map<uintptr_t, Generator::VtableSlotInfo> Generator::computeVtableSlots(std::vector<bromascan::Class> const& classes) {
        (void)classes;
        std::unordered_map<uintptr_t, VtableSlotInfo> out;
        if (!m_vtableList) return out;

        for (auto const& vt : m_vtableList->entries()) {
            for (size_t i = 0; i < vt.slots.size(); ++i) {
                auto slotRva = vt.slots[i];
                if (slotRva == 0) continue;
                out.emplace(slotRva, VtableSlotInfo{
                    vt.className,
                    i,
                    vt.slots.size()
                });
            }
        }
        return out;
    }

    Result<Platform> Generator::resolvePlatform() {
        if (m_platform == "auto") {
            if (bin::pe::isPE64(m_binaryData)) {
                return Ok(Platform::WIN);
            }

            if (bin::mach::isFatBinary(m_binaryData)) {
                return Ok(Platform::M1); // leave intel mac as explicit option
            }

            if (bin::mach::isMachO64(m_binaryData)) {
                return Ok(Platform::IOS);
            }

            return Err("Failed to auto-detect platform from binary");
        }
        if (m_platform == "m1") {
            return Ok(Platform::M1);
        }
        if (m_platform == "imac") {
            return Ok(Platform::IMAC);
        }
        if (m_platform == "win") {
            return Ok(Platform::WIN);
        }
        if (m_platform == "ios") {
            return Ok(Platform::IOS);
        }
        return Err(fmt::format("Unknown platform: {}", m_platform));
    }

    Result<> Generator::savePatternFile() {
        nlohmann::json jsonData;
        jsonData["platform"] = format_as(m_platformType);
        jsonData["classes"] = nlohmann::json::array();
        for (auto const& classBinding : m_classBindings) {
            jsonData["classes"].emplace_back(classBinding);
        }

        std::ofstream file(m_outputFile);
        if (!file.is_open()) {
            return Err(fmt::format("Failed to open output pattern file: {}", m_outputFile));
        }

        file << jsonData.dump(2);
        if (m_verbose) {
            fmt::println("Saved pattern file: {}", m_outputFile);
        }

        return Ok();
    }

    Result<> Generator::prepare() {
        GEODE_UNWRAP(this->readBinaryFile());
        if (m_verbose) {
            fmt::println("Read binary file: {} ({} bytes)", m_binaryFile, m_binaryData.size());
        }

        GEODE_UNWRAP_INTO(m_platformType, this->resolvePlatform());
        if (m_verbose) {
            fmt::println("Resolved platform: {}", m_platformType);
        }

        switch (m_platformType) {
            case Platform::M1: {
                GEODE_UNWRAP_INTO(m_targetSegment, bin::mach::getSegment(m_binaryData, bin::mach::CPUType::ARM64));
                break;
            }
            case Platform::IMAC: {
                GEODE_UNWRAP_INTO(m_targetSegment, bin::mach::getSegment(m_binaryData, bin::mach::CPUType::X86_64));
                break;
            }
            case Platform::WIN: {
                GEODE_UNWRAP_INTO(auto virtSection, bin::pe::getSection(m_binaryData));
                m_targetSegment = virtSection.data;
                m_baseCorrection = virtSection.virtualAddress;
                break;
            }
            case Platform::IOS: {
                GEODE_UNWRAP_INTO(m_targetSegment, bin::mach::getSegment(m_binaryData, bin::mach::CPUType::ARM64));
                auto segmentStart = reinterpret_cast<uintptr_t>(m_targetSegment.data());
                auto dataStart = reinterpret_cast<uintptr_t>(m_binaryData.data());
                m_baseCorrection = segmentStart - dataStart;
                break;
            }
            default:
                return Err("Unsupported platform");
        }

        if (m_verbose) {
            fmt::println("Extracted target segment (start: {}, size: {})",
                reinterpret_cast<uintptr_t>(m_targetSegment.data()) - reinterpret_cast<uintptr_t>(m_binaryData.data()),
                m_targetSegment.size()
            );
        }

        return Ok();
    }

    Result<> Generator::generate() {
        GEODE_UNWRAP_INTO(auto bindings, bromascan::readCodegenData(m_inputFile));
        if (m_verbose) {
            fmt::println("Read Broma codegen data: {} classes", bindings.size());
        }

        static auto const getBinding = [](bromascan::Function const& method, Platform platform) -> bromascan::Address {
            switch (platform) {
                case Platform::M1:
                    return method.binding.macosArm;
                case Platform::IMAC:
                    return method.binding.macosIntel;
                case Platform::WIN:
                    return method.binding.windows;
                case Platform::IOS:
                    return method.binding.ios;
                default:
                    return bromascan::Address{};
            }
        };

        auto vtableSlots = this->computeVtableSlots(bindings);

        std::unordered_map<uintptr_t, std::string> addrToName;
        if (m_callGraph.size()) {
            for (auto const& cls : bindings) {
                for (auto const& method : cls.methods) {
                    auto address = getBinding(method, m_platformType);
                    if (address.type != bromascan::AddressType::Offset) continue;
                    addrToName.emplace(address.offset, makeQualifiedName(cls.name, method.name));
                }
            }
        }

        bromascan::FunctionList const* funcListPtr = m_functionList.get();
        std::unordered_map<uintptr_t, std::vector<uintptr_t>> const& callGraph = m_callGraph;
        std::unordered_map<uintptr_t, VtableSlotInfo> const& vtableSlotsRef = vtableSlots;
        std::unordered_map<uintptr_t, std::string> const& addrToNameRef = addrToName;

        bool const isArm = (m_platformType == Platform::M1 || m_platformType == Platform::IOS);
        uintptr_t const altOffset = isArm ? 4 : 5;
        size_t const altMaxSize = isArm ? 32 : 20;

        utils::ThreadPool pool{};

        for (auto& cls : bindings) {
            if (cls.methods.empty()) continue; // skip empty classes to save on thread
            m_totalMethods += std::ranges::count_if(cls.methods,
                [&](bromascan::Function const& method) {
                    auto address = getBinding(method, m_platformType);
                    return address.type == bromascan::AddressType::Offset;
                }
            );

            pool.enqueue([
                this, cls = std::move(cls), altOffset, altMaxSize, funcListPtr,
                &callGraph, &vtableSlotsRef, &addrToNameRef
            ]() mutable {
                std::vector<sinaps::token_t> outTokens;
                std::vector<sinaps::token_t> altTokens;
                ClassBinding classBinding;
                classBinding.name = std::move(cls.name);

                for (auto const& method : cls.methods) {
                    auto address = getBinding(method, m_platformType);
                    if (address.type != bromascan::AddressType::Offset) {
                        continue;
                    }

                    auto correctedOffset = address.offset - m_baseCorrection;

                    using namespace assembly;
                    Result<void, GenerateError> res = Err(GenerateError::NotFound);
                    outTokens.clear();

                    if (m_platformType == Platform::M1 || m_platformType == Platform::IOS) {
                        res = generatePattern<aarch64::Generator>(
                            outTokens,
                            m_targetSegment,
                            correctedOffset
                        );
                    } else {
                        res = generatePattern<amd64::Generator>(
                            outTokens,
                            m_targetSegment,
                            correctedOffset
                        );
                    }

                    if (m_verbose) {
                        fmt::println("Method: {}::{} @ 0x{:x}",
                            classBinding.name,
                            method.name,
                            address.offset
                        );
                        if (!res) {
                            fmt::println("Failed to generate pattern: {}", res.unwrapErr());
                        } else {
                            fmt::println(
                                "Generated pattern ({} tokens): {}",
                                outTokens.size(),
                                sinaps::to_string(outTokens)
                            );
                        }
                    }

                    if (res) {
                        ++m_successfulMethods;
                        auto& methodBinding = classBinding.methods.emplace_back();
                        methodBinding.method = method;
                        methodBinding.pattern = sinaps::to_string(outTokens);

                        altTokens.clear();
                        auto altRes = (m_platformType == Platform::M1 || m_platformType == Platform::IOS)
                            ? generatePattern<aarch64::Generator>(altTokens, m_targetSegment, correctedOffset + altOffset, altMaxSize)
                            : generatePattern<amd64::Generator>(altTokens, m_targetSegment, correctedOffset + altOffset, altMaxSize);
                        if (altRes) {
                            methodBinding.altPattern = sinaps::to_string(altTokens);
                            methodBinding.altPatternOffset = altOffset;
                        }

                        if (method.isVirtual) {
                            auto it = vtableSlotsRef.find(address.offset);
                            if (it != vtableSlotsRef.end()) {
                                methodBinding.vtableName = it->second.vtableName;
                                methodBinding.vtableSlot = it->second.slotIndex;
                                methodBinding.vtableSlotCount = it->second.slotCount;
                            }
                        }

                        if (funcListPtr) {
                            if (auto* entry = funcListPtr->findAt(address.offset)) {
                                if (entry->size != 0) {
                                    methodBinding.funcSize = entry->size;
                                }
                            }
                        }

                        if (!callGraph.empty()) {
                            auto it = callGraph.find(address.offset);
                            if (it != callGraph.end()) {
                                for (auto calleeRva : it->second) {
                                    auto nit = addrToNameRef.find(calleeRva);
                                    if (nit != addrToNameRef.end()) {
                                        methodBinding.callTargets.push_back(nit->second);
                                    }
                                }
                            }
                        }
                    } else {
                        ++m_failedMethods;
                    }
                }

                if (classBinding.methods.empty()) {
                    return;
                }

                std::scoped_lock lock(m_mutex);
                m_classBindings.emplace_back(std::move(classBinding));
            });
        }

        pool.waitAll();

        fmt::println("Pattern generation complete: {} / {} ({:.2f}%) methods successful",
            m_successfulMethods.load(),
            m_totalMethods,
            (static_cast<double>(m_successfulMethods.load()) / static_cast<double>(m_totalMethods)) * 100.0
        );

        GEODE_UNWRAP(this->savePatternFile());

        return Ok();
    }

    Result<> Generator::readBinaryFile() {
        std::ifstream file(m_binaryFile, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            return Err(fmt::format("Failed to open file: {}", m_binaryFile));
        }

        auto size = file.tellg();
        file.seekg(0, std::ios::beg);
        m_binaryData.resize(size);

        if (!file.read(reinterpret_cast<char*>(m_binaryData.data()), size)) {
            return Err(fmt::format("Failed to read file: {}", m_binaryFile));
        }

        return Ok();
    }
}
