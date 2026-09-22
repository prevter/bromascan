#pragma once
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <broma/Types.hpp>
#include <nlohmann/json.hpp>

enum class Platform {
    M1,
    IMAC,
    WIN,
    IOS
};

std::string_view format_as(Platform platform);

struct MethodBinding {
    bromascan::Function method;
    std::optional<std::string> pattern;
    std::optional<std::string> altPattern;
    std::optional<uintptr_t> altPatternOffset;
    std::optional<size_t> vtableSlot;
    std::optional<std::string> vtableName;
    std::optional<size_t> vtableSlotCount;
    std::vector<std::string> callTargets;
    std::optional<size_t> funcSize;
    std::optional<uintptr_t> offset;
};

struct ClassBinding {
    std::string name;
    std::vector<MethodBinding> methods;
};

void to_json(nlohmann::json& j, MethodBinding const& mb);
void from_json(nlohmann::json const& j, MethodBinding& mb);
void to_json(nlohmann::json& j, ClassBinding const& cb);
void from_json(nlohmann::json const& j, ClassBinding& cb);