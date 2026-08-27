#pragma once
#include <ast.hpp>
#include <filesystem>
#include <Geode/Result.hpp>

namespace broutil {
    struct UninlineTag {};
    struct MergeTag {};

    class BroUtil {
    public:
        BroUtil(
            std::filesystem::path inputBro,
            std::filesystem::path outputBro,
            bool format = false
        );

        BroUtil(
            std::filesystem::path inputBro,
            std::filesystem::path outputBro,
            UninlineTag
        );

        BroUtil(
            std::filesystem::path inputBro,
            std::filesystem::path scanResults,
            std::filesystem::path outputBro
        );

        BroUtil(
            std::filesystem::path originalBro,
            std::filesystem::path extraBro,
            std::filesystem::path outputBro,
            MergeTag
        );

        [[nodiscard]] geode::Result<> process();

    private:
        [[nodiscard]] geode::Result<> clearBindings(broma::Root root) const;
        [[nodiscard]] geode::Result<> mergeScanResults(broma::Root root) const;
        geode::Result<> mergeBromas(broma::Root root) const;

    private:
        std::filesystem::path m_inputBro;
        std::filesystem::path m_outputBro;
        std::filesystem::path m_scanResults;
        bool m_useScanResults = false;
        bool m_format = false;
        bool m_uninline = false;
        bool m_merge = false;
    };
}
