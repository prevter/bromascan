#include <chrono>
#include <cxxopts.hpp>
#include <fmt/format.h>

#include "broutil.hpp"

int main(int argc, char* argv[]) {
    cxxopts::Options options("broutil", "Broma file utility tool");
    options.add_options()
        ("h,help", "Print help")
        ("version", "Print version information")
        ("clear", "Clear all bindings from Broma file (excluding inline definitions)")
        ("append", "Append bindings from scan results file to Broma file")
        ("format", "Reformat the Broma file")
        ("uninline", "Remove all inline definitions from Broma file")
        ("merge", "Merge two Broma files together (input_bro extra_bro output_bro)");

    auto result = options.parse(argc, argv);
    if (result.count("help")) {
        fmt::print("{}", options.help());
        return 0;
    }

    if (result.count("version")) {
        fmt::print("broutil v" BROUTIL_VERSION "\n");
        return 0;
    }

    // clear mode
    if (result.count("clear")) {
        auto& inputPath = result.unmatched().at(0);
        auto& outputPath = result.unmatched().at(1);

        if (auto res = broutil::BroUtil(inputPath, outputPath).process(); !res) {
            fmt::print("Error: {}\n", res.unwrapErr());
            return 1;
        }

        fmt::print("Cleared bindings from Broma file: {}\n", outputPath);
        return 0;
    }

    // append mode
    if (result.count("append")) {
        auto& inputPath = result.unmatched().at(0);
        auto& scanResultsPath = result.unmatched().at(1);
        auto& outputPath = result.unmatched().at(2);

        if (auto res = broutil::BroUtil(inputPath, scanResultsPath, outputPath).process(); !res) {
            fmt::print("Error: {}\n", res.unwrapErr());
            return 1;
        }

        fmt::print("Appended bindings to Broma file: {}\n", outputPath);
        return 0;
    }

    // format mode
    if (result.count("format")) {
        auto& inputPath = result.unmatched().at(0);
        auto& outputPath = result.unmatched().at(1);

        if (auto res = broutil::BroUtil(inputPath, outputPath, true).process(); !res) {
            fmt::print("Error: {}\n", res.unwrapErr());
            return 1;
        }

        fmt::print("Reformatted Broma file: {}\n", outputPath);
        return 0;
    }

    // uninline mode
    if (result.count("uninline")) {
        auto& inputPath = result.unmatched().at(0);
        auto& outputPath = result.unmatched().at(1);
        if (auto res = broutil::BroUtil(inputPath, outputPath, broutil::UninlineTag{}).process(); !res) {
            fmt::print("Error: {}\n", res.unwrapErr());
            return 1;
        }
        fmt::print("Removed inline definitions from Broma file: {}\n", outputPath);
        return 0;
    }

    // merge mode
    if (result.count("merge")) {
        auto& originalBro = result.unmatched().at(0);
        auto& extraBro = result.unmatched().at(1);
        auto& outputBro = result.unmatched().at(2);
        if (auto res = broutil::BroUtil(originalBro, extraBro, outputBro, broutil::MergeTag{}).process(); !res) {
            fmt::print("Error: {}\n", res.unwrapErr());
            return 1;
        }
        fmt::print("Merged Broma files into: {}\n", outputBro);
        return 0;
    }

    fmt::print("Error: No valid operation specified. Use --help for usage information.\n");
    return 1;
}