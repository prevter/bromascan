#pragma once
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <Geode/Result.hpp>

namespace bromascan {
    struct FunctionEntry {
        uintptr_t address = 0;
        std::optional<std::string> name;
        std::optional<std::string> demangled;
        size_t size = 0;
    };

    class FunctionList {
    public:
        void add(FunctionEntry e) { m_entries.push_back(std::move(e)); m_sorted = false; m_addressSet.clear(); }
        void finalize();
        bool isFunctionStart(uintptr_t addr) const { return !m_addressSet.empty() && m_addressSet.count(addr); }
        FunctionEntry const* findAt(uintptr_t addr) const;
        bool empty() const { return m_entries.empty(); }
        std::vector<FunctionEntry> const& entries() const { return m_entries; }
        std::vector<FunctionEntry>& mutableEntries() { return m_entries; }
        bool& mutableSorted() { return m_sorted; }
    private:
        std::vector<FunctionEntry> m_entries;
        std::unordered_set<uintptr_t> m_addressSet;
        bool m_sorted = false;
    };

    struct VtableEntry {
        uintptr_t address = 0;
        std::string className;
        std::vector<uintptr_t> slots;
        std::vector<std::string> slotNames;
    };

    class VtableList {
    public:
        void add(VtableEntry e) { m_entries.push_back(std::move(e)); }
        void finalize() { for (auto const& e : m_entries) m_byClass[e.className] = &e; }
        VtableEntry const* findByClass(std::string const& n) const { auto it = m_byClass.find(n); return it != m_byClass.end() ? it->second : nullptr; }
        std::vector<VtableEntry> const& entries() const { return m_entries; }
        bool empty() const { return m_entries.empty(); }
    private:
        std::vector<VtableEntry> m_entries;
        std::unordered_map<std::string, VtableEntry const*> m_byClass;
    };

    geode::Result<FunctionList> readFunctionList(std::filesystem::path const& path, uintptr_t imageBase = 0);
    geode::Result<VtableList> readVtableList(std::filesystem::path const& path, uintptr_t imageBase = 0);
}
