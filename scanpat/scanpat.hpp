#pragma once
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <bromascan.hpp>
#include <broma/FunctionList.hpp>
#include <Geode/Result.hpp>

namespace scanpat {
    class Scanner {
    public:
        Scanner(
            std::string binaryFile,
            std::string patternsFile,
            std::string outputFile,
            bool verbose
        ) : m_binaryFile(std::move(binaryFile)),
            m_patternsFile(std::move(patternsFile)), m_outputFile(std::move(outputFile)),
            m_verbose(verbose) {}

        void setFunctionList(bromascan::FunctionList l) { m_functionList = std::make_shared<bromascan::FunctionList>(std::move(l)); }
        void setVtableList(bromascan::VtableList l) { m_vtableList = std::make_shared<bromascan::VtableList>(std::move(l)); }
        void setCallGraph(std::unordered_map<uintptr_t, std::vector<uintptr_t>> cg) { m_callGraph = std::move(cg); }
        void setFuzzyEnabled(bool enabled) { m_fuzzyEnabled = enabled; }

        uintptr_t getImageBase() const { return m_imageBase; }

        geode::Result<> prepare();
        geode::Result<> scan();

    private:
        geode::Result<> readBinaryFile();
        geode::Result<> readPatternsFile();
        geode::Result<> performScan();
        geode::Result<> saveResults();

    private:
        std::vector<uint8_t> m_binaryData;
        std::vector<ClassBinding> m_classBindings;
        std::span<uint8_t const> m_targetSegment;
        std::mutex m_mutex;
        intptr_t m_baseCorrection = 0;
        Platform m_platformType = Platform::WIN;

        std::shared_ptr<bromascan::FunctionList> m_functionList;
        std::shared_ptr<bromascan::VtableList> m_vtableList;
        uintptr_t m_imageBase = 0;
        std::unordered_map<uintptr_t, std::vector<uintptr_t>> m_callGraph;
        bool m_fuzzyEnabled = true;

        std::atomic<size_t> m_successfulMethods = 0;
        std::atomic<size_t> m_failedMethods = 0;

        std::string m_binaryFile;
        std::string m_patternsFile;
        std::string m_outputFile;
        bool m_verbose;
    };
}
