#include "FunctionList.hpp"

#include <algorithm>
#include <fstream>
#include <nlohmann/json.hpp>
#include <fmt/format.h>

namespace bromascan {
    namespace {
        uintptr_t readAddress(nlohmann::json const& j) {
            if (j.is_number_unsigned() || j.is_number_integer()) {
                return static_cast<uintptr_t>(j.get<uint64_t>());
            }
            if (j.is_string()) {
                auto s = j.get<std::string_view>();
                if (s.empty()) return 0;
                try {
                    if (s.starts_with("0x") || s.starts_with("0X")) {
                        return std::stoull(std::string(s.substr(2)), nullptr, 16);
                    }
                    return std::stoull(std::string(s), nullptr, 16);
                } catch (...) {
                    try {
                        return std::stoull(std::string(s), nullptr, 10);
                    } catch (...) {
                        return 0;
                    }
                }
            }
            return 0;
        }

        uintptr_t readAddressKey(nlohmann::json const& j, std::initializer_list<char const*> keys) {
            for (auto* key : keys) {
                if (j.contains(key) && !j[key].is_null()) {
                    auto addr = readAddress(j[key]);
                    if (addr != 0) return addr;
                }
            }
            return 0;
        }

        std::optional<std::string> readStringOpt(nlohmann::json const& j, std::string const& key) {
            if (j.contains(key) && j[key].is_string()) {
                auto s = j[key].get<std::string>();
                if (!s.empty()) return s;
            }
            return std::nullopt;
        }
    }

    void FunctionList::finalize() {
        if (!m_sorted) {
            std::sort(m_entries.begin(), m_entries.end(),
                [](FunctionEntry const& a, FunctionEntry const& b) { return a.address < b.address; });
            m_sorted = true;
        }
        m_addressSet.clear();
        m_addressSet.reserve(m_entries.size());
        for (auto const& e : m_entries) {
            m_addressSet.insert(e.address);
        }
    }

    FunctionEntry const* FunctionList::findAt(uintptr_t addr) const {
        for (auto const& e : m_entries) {
            if (e.address == addr) return &e;
        }
        return nullptr;
    }

    geode::Result<FunctionList> readFunctionList(std::filesystem::path const& path, uintptr_t imageBase) {
        std::ifstream file(path);
        if (!file.is_open()) {
            return geode::Err(fmt::format("Failed to open function list: {}", path.string()));
        }

        auto jsonData = nlohmann::json::parse(file, nullptr, false);
        if (jsonData.is_discarded()) {
            return geode::Err(fmt::format("Failed to parse function list JSON: {}", path.string()));
        }

        nlohmann::json const* arr = nullptr;
        if (jsonData.is_array()) {
            arr = &jsonData;
        } else if (jsonData.is_object() && jsonData.contains("functions") && jsonData["functions"].is_array()) {
            arr = &jsonData["functions"];
        } else {
            return geode::Err(fmt::format("Function list JSON has no \"functions\" array: {}", path.string()));
        }

        FunctionList list;
        for (auto const& fn : *arr) {
            FunctionEntry e;
            e.address = readAddressKey(fn, {"address", "start", "start_ea"});
            if (e.address == 0) continue;
            if (imageBase) e.address -= imageBase;
            e.name = readStringOpt(fn, "name");
            e.demangled = readStringOpt(fn, "demangled");
            if (fn.contains("size") && !fn["size"].is_null()) {
                if (fn["size"].is_number()) {
                    e.size = fn["size"].get<size_t>();
                } else if (fn["size"].is_string()) {
                    try { e.size = std::stoull(fn["size"].get<std::string>(), nullptr, 0); } catch (...) {}
                }
            }
            list.add(std::move(e));
        }

        list.finalize();
        return geode::Ok(std::move(list));
    }

    geode::Result<VtableList> readVtableList(std::filesystem::path const& path, uintptr_t imageBase) {
        std::ifstream file(path);
        if (!file.is_open()) {
            return geode::Err(fmt::format("Failed to open vtable list: {}", path.string()));
        }

        auto jsonData = nlohmann::json::parse(file, nullptr, false);
        if (jsonData.is_discarded()) {
            return geode::Err(fmt::format("Failed to parse vtable list JSON: {}", path.string()));
        }

        nlohmann::json const* arr = nullptr;
        if (jsonData.is_array()) {
            arr = &jsonData;
        } else if (jsonData.is_object() && jsonData.contains("vtables") && jsonData["vtables"].is_array()) {
            arr = &jsonData["vtables"];
        } else {
            return geode::Err(fmt::format("Vtable list JSON has no \"vtables\" array: {}", path.string()));
        }

        VtableList list;
        for (auto const& vt : *arr) {
            VtableEntry e;
            e.address = readAddressKey(vt, {"address", "start", "start_ea"});
            if (imageBase && e.address != 0) e.address -= imageBase;
            e.className = readStringOpt(vt, "class_name")
                .or_else([&] { return readStringOpt(vt, "demangled"); })
                .value_or(std::string{});

            if (vt.contains("members") && vt["members"].is_array()) {
                for (auto const& m : vt["members"]) {
                    auto slotAddr = readAddressKey(m, {"address", "ptr"});
                    if (imageBase && slotAddr != 0) slotAddr -= imageBase;
                    e.slots.push_back(slotAddr);
                    e.slotNames.push_back(readStringOpt(m, "function")
                        .or_else([&] { return readStringOpt(m, "name"); })
                        .value_or(std::string{}));
                }
            }
            list.add(std::move(e));
        }

        list.finalize();
        return geode::Ok(std::move(list));
    }
}
