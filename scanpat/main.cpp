#include <chrono>
#include <cstdint>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <cxxopts.hpp>
#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <binaries/Mach-O.hpp>
#include <binaries/PE.hpp>
#include <broma/FunctionList.hpp>

#include "scanpat.hpp"

static std::vector<uint8_t> readBinaryHead(std::string const& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return {};
    auto size = file.tellg();
    constexpr size_t kMaxHead = 1u << 20;
    size_t toRead = static_cast<size_t>(size);
    if (toRead > kMaxHead) toRead = kMaxHead;
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(toRead);
    if (!file.read(reinterpret_cast<char*>(buf.data()), toRead)) return {};
    return buf;
}

static uintptr_t parseAddrValue(std::string const& s) {
    try {
        if (s.starts_with("0x") || s.starts_with("0X")) {
            return std::stoull(s.substr(2), nullptr, 16);
        }
        return std::stoull(s, nullptr, 16);
    } catch (...) {
        return 0;
    }
}

static uintptr_t readAddr(nlohmann::json const& j) {
    if (j.is_number_unsigned() || j.is_number_integer()) {
        return static_cast<uintptr_t>(j.get<uint64_t>());
    }
    if (j.is_string()) return parseAddrValue(j.get<std::string>());
    return 0;
}

struct FnTable {
    bromascan::FunctionList functions;
    bromascan::VtableList vtables;
    std::unordered_map<uintptr_t, std::vector<uintptr_t>> callGraph;
};

static FnTable loadFnTable(std::string const& path, uintptr_t imageBase) {
    FnTable t;
    std::ifstream file(path);
    if (!file.is_open()) {
        fmt::print("Warning: could not open fn-table: {}\n", path);
        return t;
    }
    auto j = nlohmann::json::parse(file, nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
        fmt::print("Warning: fn-table is not valid JSON: {}\n", path);
        return t;
    }

    if (j.contains("functions") && j["functions"].is_array()) {
        for (auto const& el : j["functions"]) {
            bromascan::FunctionEntry e;
            for (auto const& key : {"address", "start", "start_ea"}) {
                if (el.contains(key)) { e.address = readAddr(el[key]); break; }
            }
            if (!e.address) continue;
            if (imageBase && e.address >= imageBase) e.address -= imageBase;
            if (el.contains("name") && el["name"].is_string()) e.name = el["name"].get<std::string>();
            if (el.contains("demangled") && el["demangled"].is_string()) e.demangled = el["demangled"].get<std::string>();
            if (el.contains("size") && el["size"].is_number()) e.size = el["size"].get<size_t>();
            t.functions.add(std::move(e));
        }
        t.functions.finalize();
    }

    if (j.contains("vtables") && j["vtables"].is_array()) {
        for (auto const& vt : j["vtables"]) {
            if (!vt.is_object()) continue;
            bromascan::VtableEntry e;
            for (auto const& key : {"address", "start", "start_ea"}) {
                if (vt.contains(key)) { e.address = readAddr(vt[key]); break; }
            }
            if (imageBase && e.address >= imageBase) e.address -= imageBase;
            if (vt.contains("class_name") && vt["class_name"].is_string()) e.className = vt["class_name"].get<std::string>();
            else if (vt.contains("demangled") && vt["demangled"].is_string()) {
                auto s = vt["demangled"].get<std::string>();
                auto pfx = std::string("vtable for ");
                if (s.starts_with(pfx)) s = s.substr(pfx.size());
                e.className = s;
            }
            if (vt.contains("members") && vt["members"].is_array()) {
                for (auto const& m : vt["members"]) {
                    uintptr_t addr = 0;
                    if (m.is_object()) {
                        for (auto const& key : {"address", "ptr", "function"}) {
                            if (m.contains(key)) { addr = readAddr(m[key]); break; }
                        }
                    } else if (m.is_number()) addr = m.get<uintptr_t>();
                    if (!addr) continue;
                    if (imageBase && addr >= imageBase) addr -= imageBase;
                    e.slots.push_back(addr);
                    e.slotNames.push_back(m.is_object() && m.contains("name") && m["name"].is_string()
                        ? m["name"].get<std::string>() : "");
                }
            }
            t.vtables.add(std::move(e));
        }
        t.vtables.finalize();
    }

    if (j.contains("call_graph") && j["call_graph"].is_array()) {
        for (auto const& node : j["call_graph"]) {
            uintptr_t caller = readAddr(node["address"]);
            if (imageBase && caller >= imageBase) caller -= imageBase;
            std::vector<uintptr_t> calls;
            if (node.contains("calls") && node["calls"].is_array()) {
                for (auto const& c : node["calls"]) {
                    uintptr_t callee = readAddr(c);
                    if (!callee) continue;
                    if (imageBase && callee >= imageBase) callee -= imageBase;
                    calls.push_back(callee);
                }
            }
            t.callGraph.emplace(caller, std::move(calls));
        }
    }

    return t;
}

int main(int argc, char* argv[]) {
    cxxopts::Options options("scanpat", "Mass-scan function addresses using patterns");
    options.add_options()
        ("v,verbose", "Enable verbose output")
        ("h,help", "Print help")
        ("version", "Print version information")
        ("t,fn-table", "IDA export JSON file containing function list, vtable list, and call graph.", cxxopts::value<std::string>())
        ("fuzzy", "Enable fuzzy matching (default: true)", cxxopts::value<bool>()->default_value("true"))
        ("binary", "Binary File", cxxopts::value<std::string>())
        ("patterns", "Input Patterns File", cxxopts::value<std::string>())
        ("output", "Output Scan Results File", cxxopts::value<std::string>());
    options.parse_positional({"binary", "patterns", "output"});
    auto result = options.parse(argc, argv);

    if (result.count("help")) {
        fmt::print("{}", options.help());
        return 0;
    }

    if (result.count("version")) {
        fmt::print("scanpat version" SCANPAT_VERSION "\n");
        return 0;
    }

    if (!result.count("binary") || !result.count("patterns") || !result.count("output")) {
        fmt::print("Error: Missing required arguments.\n");
        fmt::print("{}", options.help());
        return 1;
    }

    auto binaryFile = result["binary"].as<std::string>();
    auto patternsFile = result["patterns"].as<std::string>();
    auto outputFile = result["output"].as<std::string>();
    bool verbose = result.count("verbose") > 0;
    bool fuzzy = result["fuzzy"].as<bool>();

    if (verbose) {
        fmt::print("Binary File: {}\n", binaryFile);
        fmt::print("Patterns File: {}\n", patternsFile);
        fmt::print("Output File: {}\n", outputFile);
        fmt::print("Fuzzy matching: {}\n", fuzzy ? "enabled" : "disabled");
    }

    auto start = std::chrono::high_resolution_clock::now();
    scanpat::Scanner scanner(
        std::move(binaryFile),
        std::move(patternsFile),
        std::move(outputFile),
        verbose
    );

    auto prep = scanner.prepare();
    if (!prep) {
        fmt::print("Error: {}\n", prep.unwrapErr());
        return 1;
    }

    scanner.setFuzzyEnabled(fuzzy);

    if (result.count("t,fn-table")) {
        auto path = result["fn-table"].as<std::string>();
        auto t = loadFnTable(path, scanner.getImageBase());
        scanner.setFunctionList(std::move(t.functions));
        scanner.setVtableList(std::move(t.vtables));
        scanner.setCallGraph(std::move(t.callGraph));
        if (verbose) fmt::print("Loaded fn-table: {}\n", path);
    }

    if (auto res = scanner.scan(); !res) {
        fmt::print("Error: {}\n", res.unwrapErr());
        return 1;
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    fmt::print("Scan completed in {} ms\n", duration);

    return 0;
}
