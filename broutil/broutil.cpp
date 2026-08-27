#include "broutil.hpp"
#include <broma.hpp>
#include <bromascan.hpp>
#include <fstream>
#include <broma/Writer.hpp>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <fmt/std.h>

using namespace geode;

namespace broutil {
    BroUtil::BroUtil(std::filesystem::path inputBro, std::filesystem::path outputBro, bool format)
        : m_inputBro(std::move(inputBro)), m_outputBro(std::move(outputBro)), m_format(format) {}

    BroUtil::BroUtil(std::filesystem::path inputBro, std::filesystem::path outputBro, UninlineTag) {
        m_inputBro = std::move(inputBro);
        m_outputBro = std::move(outputBro);
        m_uninline = true;
    }

    BroUtil::BroUtil(std::filesystem::path inputBro, std::filesystem::path scanResults, std::filesystem::path outputBro)
        : m_inputBro(std::move(inputBro)),
          m_outputBro(std::move(outputBro)),
          m_scanResults(std::move(scanResults)),
          m_useScanResults(true) {}

    BroUtil::BroUtil(std::filesystem::path originalBro, std::filesystem::path extraBro, std::filesystem::path outputBro, MergeTag) {
        m_inputBro = std::move(originalBro);
        m_outputBro = std::move(outputBro);
        m_scanResults = std::move(extraBro);
        m_merge = true;
    }

    Result<> BroUtil::clearBindings(broma::Root root) const {
        auto clearBindings = [](broma::PlatformNumber& binds) {
            if (binds.win >= 0) binds.win = -1;
            if (binds.imac >= 0) binds.imac = -1;
            if (binds.m1 >= 0) binds.m1 = -1;
            if (binds.ios >= 0) binds.ios = -1;
            if (binds.android32 >= 0) binds.android32 = -1;
            if (binds.android64 >= 0) binds.android64 = -1;
        };

        // clear all bindings except inline definitions
        for (auto& cls : root.classes) {
            for (auto& field : cls.fields) {
                if (auto fn = field.get_as<broma::FunctionBindField>()) {
                    clearBindings(fn->binds);
                }
            }
        }

        for (auto& fn : root.functions) {
            clearBindings(fn.binds);
        }

        return bromascan::writeBromaFile(m_outputBro, root);
    }

    Result<> BroUtil::mergeScanResults(broma::Root root) const {
        // load scan results
        std::ifstream file(m_scanResults);
        if (!file.is_open()) {
            return Err(fmt::format("Failed to open patterns file: {}", m_scanResults));
        }

        auto jsonData = nlohmann::json::parse(file, nullptr, false);
        if (jsonData.is_discarded()) {
            return Err(fmt::format("Failed to parse patterns file: {}", m_scanResults));
        }

        std::vector<ClassBinding> classBindings;
        auto& classes = jsonData["classes"];
        classBindings.reserve(classes.size());

        try {
            for (auto& jsonClass : classes) {
                classBindings.emplace_back(jsonClass.get<ClassBinding>());
            }
        } catch (std::exception& e) {
            return Err(fmt::format("Failed to deserialize patterns file: {}: {}", m_scanResults, e.what()));
        }

        auto platformStr = jsonData["platform"].get<std::string_view>();
        Platform platformType;
        if (platformStr == "Windows") {
            platformType = Platform::WIN;
        } else if (platformStr == "iMac") {
            platformType = Platform::IMAC;
        } else if (platformStr == "M1") {
            platformType = Platform::M1;
        } else if (platformStr == "iOS") {
            platformType = Platform::IOS;
        } else {
            return Err(fmt::format("Unsupported platform in patterns file: {}", platformStr));
        }

        auto setBinding = [platformType](broma::PlatformNumber& binds, uintptr_t offset) {
            switch (platformType) {
                case Platform::WIN:
                    binds.win = static_cast<ptrdiff_t>(offset);
                    break;
                case Platform::IMAC:
                    binds.imac = static_cast<ptrdiff_t>(offset);
                    break;
                case Platform::M1:
                    binds.m1 = static_cast<ptrdiff_t>(offset);
                    break;
                case Platform::IOS:
                    binds.ios = static_cast<ptrdiff_t>(offset);
                    break;
                default:
                    break;
            }
        };

        for (auto& classBinding : classBindings) {
            auto cls = std::ranges::find_if(
                root.classes,
                [&classBinding](broma::Class const& c) {
                    return c.name == classBinding.name;
                }
            );

            if (cls == root.classes.end()) {
                continue;
            }

            fmt::println("Class: {}", classBinding.name);
            for (auto& methodBinding : classBinding.methods) {
                fmt::println("  Method: {}", methodBinding.method.name);
                // find by name, filter by args if overloaded
                auto methodIt = std::ranges::find_if(
                    cls->fields,
                    [&methodBinding](broma::Field const& f) {
                        if (auto fn = f.get_as<broma::FunctionBindField>()) {
                            if (fn->prototype.name != methodBinding.method.name) {
                                return false;
                            }
                            if (fn->prototype.args.size() != methodBinding.method.args.size()) {
                                return false;
                            }
                            for (size_t i = 0; i < fn->prototype.args.size(); ++i) {
                                if (fn->prototype.args[i].first.name != methodBinding.method.args[i].type) {
                                    return false;
                                }
                            }
                            return true;
                        }
                        return false;
                    }
                );

                if (methodIt == cls->fields.end()) {
                    fmt::println("    Method not found in Broma file.");
                    continue;
                }

                if (methodBinding.offset.has_value()) {
                    auto fn = methodIt->get_as<broma::FunctionBindField>();
                    setBinding(fn->binds, methodBinding.offset.value());
                    fmt::println("    Set binding to offset: 0x{:X}", methodBinding.offset.value());
                } else {
                    fmt::println("    No offset found in scan results.");
                }
            }
        }

        return bromascan::writeBromaFile(m_outputBro, root);
    }

    Result<> BroUtil::mergeBromas(broma::Root root) const {
        // load extra bro file
        auto parseRes = broma::parse_file(m_scanResults);
        if (!parseRes) {
            return Err(fmt::format("Failed to parse extra Broma file:\n - {}", fmt::join(parseRes.unwrapErr().messages, "\n - ")));
        }

        broma::Root extraRoot = std::move(parseRes).unwrap();

        auto const mergeBinds = [](broma::PlatformNumber& base, broma::PlatformNumber const& extra) {
            if (extra.win >= 0 && base.win != -2) base.win = extra.win;
            if (extra.imac >= 0 && base.imac != -2) base.imac = extra.imac;
            if (extra.m1 >= 0 && base.m1 != -2) base.m1 = extra.m1;
            if (extra.ios >= 0 && base.ios != -2) base.ios = extra.ios;
            if (extra.android32 >= 0 && base.android32 != -2) base.android32 = extra.android32;
            if (extra.android64 >= 0 && base.android64 != -2) base.android64 = extra.android64;
        };

        auto const compareFuncs = [](broma::FunctionBindField const& a, broma::FunctionBindField const& b) {
            if (a.prototype.name != b.prototype.name) {
                return false;
            }
            if (a.prototype.args.size() != b.prototype.args.size()) {
                return false;
            }
            for (size_t i = 0; i < a.prototype.args.size(); ++i) {
                if (a.prototype.args[i].first.name != b.prototype.args[i].first.name) {
                    return false;
                }
            }
            return true;
        };

        // merge classes
        for (auto& extraClass : extraRoot.classes) {
            auto clsIt = std::ranges::find_if(
                root.classes,
                [&extraClass](broma::Class const& c) {
                    return c.name == extraClass.name;
                }
            );

            if (clsIt == root.classes.end()) {
                // class not found, add it
                // root.classes.push_back(extraClass);
                continue;
            }

            // merge fields
            for (auto& extraField : extraClass.fields) {
                auto extraFn = extraField.get_as<broma::FunctionBindField>();
                if (!extraFn) continue;

                // check if field exists
                auto fieldIt = std::ranges::find_if(
                    clsIt->fields,
                    [&](broma::Field const& f) {
                        if (auto fn = f.get_as<broma::FunctionBindField>()) {
                            return compareFuncs(*fn, *extraFn);
                        }
                        return false;
                    }
                );

                if (fieldIt == clsIt->fields.end()) {
                    // field not found, add it
                    // clsIt->fields.push_back(extraField);
                } else {
                    // field found, merge bindings
                    auto fn = fieldIt->get_as<broma::FunctionBindField>();
                    mergeBinds(fn->binds, extraFn->binds);
                }
            }
        }

        return bromascan::writeBromaFile(m_outputBro, root);
    }

    Result<> BroUtil::process() {
        auto parseRes = broma::parse_file(m_inputBro);
        if (!parseRes) {
            return Err(fmt::format("Failed to parse Broma file:\n - {}", fmt::join(parseRes.unwrapErr().messages, "\n - ")));
        }

        broma::Root root = std::move(parseRes).unwrap();

        if (m_uninline) {
            // remove all inline definitions from the file
            for (auto& cls : root.classes) {
                for (auto& field : cls.fields) {
                    if (auto fn = field.get_as<broma::FunctionBindField>()) {
                        fn->inner.clear();
                    }
                }
            }

            for (auto& fn : root.functions) {
                fn.inner.clear();
            }

            return bromascan::writeBromaFile(m_outputBro, root);
        }

        if (m_merge) {
            return mergeBromas(std::move(root));
        }

        if (m_format) {
            return bromascan::writeBromaFile(m_outputBro, root);
        }

        if (m_useScanResults) {
            return mergeScanResults(std::move(root));
        }

        return clearBindings(std::move(root));
    }
}
