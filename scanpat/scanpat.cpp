#include "scanpat.hpp"

#include <algorithm>
#include <fstream>
#include <unordered_set>

#include <sinaps.hpp>
#include <ThreadPool.hpp>
#include <binaries/Mach-O.hpp>
#include <binaries/PE.hpp>
#include <fmt/format.h>

#include <asm/common.hpp>

using namespace geode;

namespace scanpat {
    static std::string qualify(std::string_view cls, std::string_view fn) {
        return fmt::format("{}::{}", cls, fn);
    }

    Result<> Scanner::prepare() {
        GEODE_UNWRAP(this->readBinaryFile());
        if (m_verbose) {
            fmt::println("Read binary file: {} ({} bytes)", m_binaryFile, m_binaryData.size());
        }

        GEODE_UNWRAP(this->readPatternsFile());
        if (m_verbose) {
            fmt::println("Target platform: {}", m_platformType);
        }

        switch (m_platformType) {
            case Platform::M1: {
                GEODE_UNWRAP_INTO(m_targetSegment, bin::mach::getSegment(m_binaryData, bin::mach::CPUType::ARM64));
                m_imageBase = bin::mach::getImageBase(m_binaryData);
                break;
            }
            case Platform::IMAC: {
                GEODE_UNWRAP_INTO(m_targetSegment, bin::mach::getSegment(m_binaryData, bin::mach::CPUType::X86_64));
                m_imageBase = bin::mach::getImageBase(m_binaryData);
                break;
            }
            case Platform::WIN: {
                GEODE_UNWRAP_INTO(auto virtSection, bin::pe::getSection(m_binaryData));
                m_targetSegment = virtSection.data;
                m_baseCorrection = virtSection.virtualAddress;
                m_imageBase = bin::pe::getImageBase(m_binaryData);
                break;
            }
            case Platform::IOS: {
                GEODE_UNWRAP_INTO(m_targetSegment, bin::mach::getSegment(m_binaryData, bin::mach::CPUType::ARM64));
                auto segmentStart = reinterpret_cast<uintptr_t>(m_targetSegment.data());
                auto dataStart = reinterpret_cast<uintptr_t>(m_binaryData.data());
                m_baseCorrection = segmentStart - dataStart;
                m_imageBase = bin::mach::getImageBase(m_binaryData);
                break;
            }
            default:
                return Err("Unsupported platform");
        }

        if (m_verbose) {
            fmt::println(
                "Extracted target segment (start: {}, size: {})",
                reinterpret_cast<uintptr_t>(m_targetSegment.data()) - reinterpret_cast<uintptr_t>(m_binaryData.data()),
                m_targetSegment.size()
            );

            fmt::print("Image base: 0x{:x}\n", m_imageBase);
        }

        return Ok();
    }

    Result<> Scanner::scan() {
        GEODE_UNWRAP(this->performScan());
        GEODE_UNWRAP(this->saveResults());

        auto total = m_successfulMethods.load() + m_failedMethods.load();
        fmt::println("Scan complete: {} methods found, {} methods not found ({:.2f}%)",
            m_successfulMethods.load(),
            m_failedMethods.load(),
            total ? (static_cast<double>(m_successfulMethods.load()) / static_cast<double>(total)) * 100.0 : 0.0
        );

        return Ok();
    }

    Result<> Scanner::readBinaryFile() {
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

    Result<> Scanner::readPatternsFile() {
        std::ifstream file(m_patternsFile);
        if (!file.is_open()) {
            return Err(fmt::format("Failed to open patterns file: {}", m_patternsFile));
        }

        auto jsonData = nlohmann::json::parse(file, nullptr, false);
        if (jsonData.is_discarded()) {
            return Err(fmt::format("Failed to parse patterns file: {}", m_patternsFile));
        }

        auto& classes = jsonData["classes"];
        m_classBindings.reserve(classes.size());

        try {
            for (auto& jsonClass : classes) {
                m_classBindings.emplace_back(jsonClass.get<ClassBinding>());
            }
        } catch (std::exception& e) {
            return Err(fmt::format("Failed to deserialize patterns file: {}: {}", m_patternsFile, e.what()));
        }

        if (m_verbose) {
            fmt::println("Loaded {} class bindings from patterns file: {}",
                m_classBindings.size(),
                m_patternsFile
            );
        }

        auto platformStr = jsonData["platform"].get<std::string_view>();
        if (platformStr == "Windows") {
            m_platformType = Platform::WIN;
        } else if (platformStr == "iMac") {
            m_platformType = Platform::IMAC;
        } else if (platformStr == "M1") {
            m_platformType = Platform::M1;
        } else if (platformStr == "iOS") {
            m_platformType = Platform::IOS;
        } else {
            return Err(fmt::format("Unsupported platform in patterns file: {}", platformStr));
        }

        return Ok();
    }

    Result<> Scanner::performScan() {
        if (!m_functionList) {
            bool isMach = (m_platformType == Platform::M1 ||
                           m_platformType == Platform::IMAC ||
                           m_platformType == Platform::IOS);
            if (isMach) {
                auto type = (m_platformType == Platform::IMAC)
                    ? bin::mach::CPUType::X86_64
                    : bin::mach::CPUType::ARM64;
                auto starts = bin::mach::getFunctionStarts(m_binaryData, type);
                if (!starts.empty()) {
                    auto list = std::make_shared<bromascan::FunctionList>();
                    for (size_t i = 0; i < starts.size(); ++i) {
                        uintptr_t vm = starts[i];
                        uintptr_t rva = (m_imageBase && vm >= m_imageBase) ? vm - m_imageBase : vm;
                        size_t size = (i + 1 < starts.size() && starts[i + 1] > vm)
                            ? static_cast<size_t>(starts[i + 1] - vm) : 0;
                        list->add({rva, std::nullopt, std::nullopt, size});
                    }
                    list->finalize();
                    m_functionList = std::move(list);
                    if (m_verbose) {
                        fmt::println("Auto-extracted {} function starts from LC_FUNCTION_STARTS", m_functionList->entries().size());
                    }
                }
            }
        }

        size_t stepSize = (m_platformType == Platform::WIN || m_platformType == Platform::IMAC) ? 16 : 4;
        auto baseCorrection = static_cast<uintptr_t>(m_baseCorrection);

        auto* data = m_targetSegment.data();
        size_t dataSize = m_targetSegment.size();
        bromascan::FunctionList const* funcList = m_functionList.get();
        bromascan::VtableList const* vtableList = m_vtableList.get();
        std::unordered_map<uintptr_t, std::vector<uintptr_t>> const& callGraph = m_callGraph;
        bool fuzzyEnabled = m_fuzzyEnabled;
        bool verbose = m_verbose;

        auto passesGuardrail = [&](uintptr_t rva) -> bool {
            return !funcList || funcList->empty() || funcList->isFunctionStart(rva);
        };

        utils::ThreadPool pool{};

        for (auto& classBinding : m_classBindings) {
            if (classBinding.methods.empty()) continue;
            pool.enqueue([
                this, &classBinding, data, dataSize, stepSize, baseCorrection,
                funcList, vtableList, fuzzyEnabled, verbose, &passesGuardrail
            ]() {
                for (auto& mb : classBinding.methods) {
                    if (mb.vtableName && mb.vtableSlot && mb.vtableSlotCount && vtableList) {
                        auto const* vt = vtableList->findByClass(*mb.vtableName);
                        if (vt && vt->slots.size() == *mb.vtableSlotCount &&
                            *mb.vtableSlot < vt->slots.size()) {
                            mb.offset = vt->slots[*mb.vtableSlot];
                            ++m_successfulMethods;
                            if (verbose) {
                                fmt::println("Vtable match: {}::{} -> 0x{:X}", classBinding.name, mb.method.name, *mb.offset);
                            }
                            continue;
                        }
                    }

                    if (mb.pattern) {
                        auto tokens = sinaps::impl::tokenizePatternStringRuntime(*mb.pattern);
                        if (!tokens.empty()) {
                            auto found = assembly::findFirstMatch(data, dataSize, tokens.data(), tokens.size(), stepSize);
                            if (found) {
                                uintptr_t rva = *found + baseCorrection;
                                if (passesGuardrail(rva)) {
                                    mb.offset = rva;
                                    ++m_successfulMethods;
                                    if (verbose) {
                                        fmt::println("Pattern match: {}::{} -> 0x{:X}", classBinding.name, mb.method.name, rva);
                                    }
                                    continue;
                                }
                            }
                        }
                    }

                    if (mb.altPattern && mb.altPatternOffset) {
                        auto tokens = sinaps::impl::tokenizePatternStringRuntime(*mb.altPattern);
                        if (!tokens.empty()) {
                            auto found = assembly::findFirstMatch(data, dataSize, tokens.data(), tokens.size(), stepSize);
                            if (found && *found >= *mb.altPatternOffset) {
                                uintptr_t funcStart = *found - *mb.altPatternOffset;
                                uintptr_t rva = funcStart + baseCorrection;
                                if (passesGuardrail(rva)) {
                                    mb.offset = rva;
                                    ++m_successfulMethods;
                                    if (verbose) {
                                        fmt::println("Alt pattern match: {}::{} -> 0x{:X}", classBinding.name, mb.method.name, rva);
                                    }
                                    continue;
                                }
                            }
                        }
                    }

                    if (fuzzyEnabled && mb.pattern && funcList && !funcList->empty()) {
                        auto tokens = sinaps::impl::tokenizePatternStringRuntime(*mb.pattern);
                        if (!tokens.empty()) {
                            size_t nonWildcard = 0;
                            for (auto const& t : tokens) {
                                if (t.type != sinaps::token_t::type_t::wildcard) ++nonWildcard;
                            }
                            size_t threshold = nonWildcard * 10 / 100;
                            if (threshold < 1) threshold = 1;
                            if (threshold > 12) threshold = 12;
                            auto found = assembly::fuzzyMatchAtFunctionStarts(
                                data, dataSize, tokens.data(), tokens.size(),
                                funcList, baseCorrection, threshold, 2
                            );
                            if (found) {
                                uintptr_t rva = *found + baseCorrection;
                                mb.offset = rva;
                                ++m_successfulMethods;
                                if (verbose) {
                                    fmt::println("Fuzzy match: {}::{} -> 0x{:X}", classBinding.name, mb.method.name, rva);
                                }
                                continue;
                            }
                        }
                    }

                    ++m_failedMethods;
                }
            });
        }

        pool.waitAll();

        if (vtableList) {
            for (auto& classBinding : m_classBindings) {
                std::vector<std::pair<size_t, uintptr_t>> foundVfuncs;
                for (auto const& mb : classBinding.methods) {
                    if (mb.offset && mb.vtableSlot) {
                        foundVfuncs.emplace_back(*mb.vtableSlot, *mb.offset);
                    }
                }
                if (foundVfuncs.size() < 2) continue;

                for (auto& mb : classBinding.methods) {
                    if (mb.offset || !mb.vtableSlot) continue;
                    size_t targetSlot = *mb.vtableSlot;

                    std::unordered_map<uintptr_t, size_t> votes;
                    for (auto const& vt : vtableList->entries()) {
                        if (!vt.className.empty()) continue;
                        if (targetSlot >= vt.slots.size()) continue;

                        size_t matchCount = 0;
                        for (auto const& [slot, rva] : foundVfuncs) {
                            if (slot < vt.slots.size() && vt.slots[slot] == rva) {
                                ++matchCount;
                            }
                        }
                        if (matchCount >= 2) {
                            ++votes[vt.slots[targetSlot]];
                        }
                    }

                    uintptr_t bestAddr = 0;
                    size_t bestVotes = 0;
                    size_t secondBest = 0;
                    for (auto const& [addr, count] : votes) {
                        if (count > bestVotes) {
                            secondBest = bestVotes;
                            bestVotes = count;
                            bestAddr = addr;
                        } else if (count > secondBest) {
                            secondBest = count;
                        }
                    }

                    if (bestVotes >= 2 && bestVotes > secondBest) {
                        mb.offset = bestAddr;
                        ++m_successfulMethods;
                        --m_failedMethods;
                        if (verbose) {
                            fmt::println("Vtable fallback: {}::{} -> 0x{:X} ({} votes)", classBinding.name, mb.method.name, bestAddr, bestVotes);
                        }
                    }
                }
            }
        }

        if (!callGraph.empty()) {
            auto rebuildAddrMap = [&]() {
                std::unordered_map<uintptr_t, std::string> map;
                for (auto const& cb : m_classBindings) {
                    for (auto const& mb : cb.methods) {
                        if (mb.offset) {
                            map.emplace(*mb.offset, qualify(cb.name, mb.method.name));
                        }
                    }
                }
                return map;
            };

            auto addrToName = rebuildAddrMap();
            std::unordered_set<uintptr_t> assigned;
            for (auto const& cb : m_classBindings) {
                for (auto const& mb : cb.methods) {
                    if (mb.offset) assigned.insert(*mb.offset);
                }
            }

            for (auto& cb : m_classBindings) {
                for (auto& mb : cb.methods) {
                    if (!mb.offset || mb.callTargets.empty()) continue;
                    auto it = callGraph.find(*mb.offset);
                    if (it == callGraph.end()) continue;
                    size_t matches = 0;
                    for (auto calleeRva : it->second) {
                        auto nit = addrToName.find(calleeRva);
                        if (nit == addrToName.end()) continue;
                        if (std::ranges::find(mb.callTargets, nit->second) != mb.callTargets.end()) {
                            ++matches;
                        }
                    }
                    double rate = mb.callTargets.empty()
                        ? 1.0
                        : static_cast<double>(matches) / static_cast<double>(mb.callTargets.size());
                    if (rate < 0.5) {
                        assigned.erase(*mb.offset);
                        mb.offset = std::nullopt;
                        --m_successfulMethods;
                        ++m_failedMethods;
                        if (verbose) {
                            fmt::println("Call-graph reject: {}::{} ({}/{})", cb.name, mb.method.name, matches, mb.callTargets.size());
                        }
                    }
                }
            }

            addrToName = rebuildAddrMap();

            for (auto& cb : m_classBindings) {
                for (auto& mb : cb.methods) {
                    if (mb.offset || mb.callTargets.empty()) continue;

                    uintptr_t bestAddr = 0;
                    size_t bestMatches = 0;
                    size_t secondBest = 0;
                    for (auto const& [callerRva, callees] : callGraph) {
                        if (assigned.contains(callerRva)) continue;
                        size_t matches = 0;
                        for (auto calleeRva : callees) {
                            auto nit = addrToName.find(calleeRva);
                            if (nit == addrToName.end()) continue;
                            if (std::ranges::find(mb.callTargets, nit->second) != mb.callTargets.end()) {
                                ++matches;
                            }
                        }
                        if (matches > bestMatches) {
                            secondBest = bestMatches;
                            bestMatches = matches;
                            bestAddr = callerRva;
                        } else if (matches > secondBest) {
                            secondBest = matches;
                        }
                    }

                    if (bestMatches >= 3 && (bestMatches - secondBest) >= 2) {
                        mb.offset = bestAddr;
                        assigned.insert(bestAddr);
                        ++m_successfulMethods;
                        --m_failedMethods;
                        if (verbose) {
                            fmt::println(
                                "Call-graph recover: {}::{} -> 0x{:X} ({})",
                                cb.name, mb.method.name, bestAddr, bestMatches
                            );
                        }
                    }
                }
            }
        }

        return Ok();
    }

    Result<> Scanner::saveResults() {
        std::vector<ClassBinding> filteredBindings;
        filteredBindings.reserve(m_classBindings.size());

        for (auto& classBinding : m_classBindings) {
            ClassBinding filteredClass;
            filteredClass.methods.reserve(classBinding.methods.size());
            filteredClass.name = std::move(classBinding.name);

            for (auto& methodBinding : classBinding.methods) {
                if (methodBinding.offset.has_value()) {
                    methodBinding.pattern = std::nullopt;
                    methodBinding.altPattern = std::nullopt;
                    methodBinding.altPatternOffset = std::nullopt;
                    filteredClass.methods.emplace_back(std::move(methodBinding));
                }
            }

            if (!filteredClass.methods.empty()) {
                filteredBindings.emplace_back(std::move(filteredClass));
            }
        }

        nlohmann::json jsonData;
        jsonData["platform"] = format_as(m_platformType);
        jsonData["classes"] = filteredBindings;

        std::ofstream file(m_outputFile);
        if (!file.is_open()) {
            return Err(fmt::format("Failed to open output file: {}", m_outputFile));
        }

        file << jsonData.dump(2);

        if (m_verbose) {
            fmt::println("Saved scan results to output file: {}", m_outputFile);
        }

        return Ok();
    }
}
