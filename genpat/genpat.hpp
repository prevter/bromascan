#pragma once
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <bromascan.hpp>
#include <broma/Types.hpp>
#include <broma/FunctionList.hpp>
#include <Geode/Result.hpp>

namespace genpat {
    using namespace geode;

    class Generator {
    public:
        Generator(
            std::string platform,
            std::string binaryFile,
            std::string inputFile,
            std::string outputFile,
            bool verbose
        ) : m_platform(std::move(platform)), m_binaryFile(std::move(binaryFile)), m_inputFile(std::move(inputFile)),
            m_outputFile(std::move(outputFile)), m_verbose(verbose) {}

        void setFunctionList(bromascan::FunctionList l) { m_functionList = std::make_shared<bromascan::FunctionList>(std::move(l)); }
        void setVtableList(bromascan::VtableList l) { m_vtableList = std::make_shared<bromascan::VtableList>(std::move(l)); }
        void setCallGraph(std::unordered_map<uintptr_t, std::vector<uintptr_t>> cg) { m_callGraph = std::move(cg); }

        uintptr_t getImageBase() const { return m_imageBase; }

        Result<> prepare();
        Result<> generate();

    private:
        struct VtableSlotInfo {
            std::string vtableName;
            size_t slotIndex;
            size_t slotCount;
        };

        Result<> readBinaryFile();
        Result<Platform> resolvePlatform();
        Result<> savePatternFile();

        std::unordered_map<uintptr_t, VtableSlotInfo> computeVtableSlots(std::vector<bromascan::Class> const& classes);

    private:
        std::vector<uint8_t> m_binaryData;
        std::span<uint8_t const> m_targetSegment;
        std::vector<ClassBinding> m_classBindings;
        std::mutex m_mutex;
        intptr_t m_baseCorrection = 0;
        Platform m_platformType = Platform::WIN;

        std::shared_ptr<bromascan::FunctionList> m_functionList;
        std::shared_ptr<bromascan::VtableList> m_vtableList;
        uintptr_t m_imageBase = 0;
        std::unordered_map<uintptr_t, std::vector<uintptr_t>> m_callGraph;

        size_t m_totalMethods = 0;
        std::atomic<size_t> m_successfulMethods = 0;
        std::atomic<size_t> m_failedMethods = 0;

        std::string m_platform;
        std::string m_binaryFile;
        std::string m_inputFile;
        std::string m_outputFile;
        bool m_verbose;
    };
}
