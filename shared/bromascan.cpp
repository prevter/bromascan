#include "bromascan.hpp"

std::string_view format_as(Platform platform) {
    switch (platform) {
        case Platform::M1:
            return "M1";
        case Platform::IMAC:
            return "iMac";
        case Platform::WIN:
            return "Windows";
        case Platform::IOS:
            return "iOS";
        default:
            return "Unknown";
    }
}

void to_json(nlohmann::json& j, MethodBinding const& mb) {
    j["name"] = mb.method.name;
    j["return"] = mb.method.returnType;

    auto& args = j["args"];
    args = nlohmann::json::array();
    for (auto const& arg : mb.method.args) {
        auto& jsonArg = args.emplace_back();
        jsonArg["name"] = arg.name;
        jsonArg["type"] = arg.type;
    }

    if (mb.pattern.has_value()) {
        j["pattern"] = mb.pattern.value();
    }

    if (mb.altPattern.has_value()) {
        j["alt_pattern"] = mb.altPattern.value();
    }
    if (mb.altPatternOffset.has_value()) {
        j["alt_pattern_offset"] = mb.altPatternOffset.value();
    }
    if (mb.vtableSlot.has_value()) {
        j["vtable_slot"] = mb.vtableSlot.value();
    }
    if (mb.vtableName.has_value()) {
        j["vtable_name"] = mb.vtableName.value();
    }
    if (mb.vtableSlotCount.has_value()) {
        j["vtable_slot_count"] = mb.vtableSlotCount.value();
    }
    if (!mb.callTargets.empty()) {
        j["call_targets"] = mb.callTargets;
    }
    if (mb.funcSize.has_value()) {
        j["func_size"] = mb.funcSize.value();
    }

    if (mb.offset.has_value()) {
        j["offset"] = mb.offset.value();
    }
}

void from_json(nlohmann::json const& j, MethodBinding& mb) {
    mb.method.name = j["name"].get<std::string>();
    mb.method.returnType = j["return"].get<std::string>();

    auto& jsonArgs = j["args"];
    for (auto& jsonArg : jsonArgs) {
        auto& arg = mb.method.args.emplace_back();
        arg.name = jsonArg["name"].get<std::string>();
        arg.type = jsonArg["type"].get<std::string>();
    }

    if (j.contains("pattern") && !j["pattern"].is_null()) {
        mb.pattern = j["pattern"].get<std::string>();
    } else {
        mb.pattern = std::nullopt;
    }

    if (j.contains("alt_pattern") && !j["alt_pattern"].is_null()) {
        mb.altPattern = j["alt_pattern"].get<std::string>();
    } else {
        mb.altPattern = std::nullopt;
    }
    if (j.contains("alt_pattern_offset") && !j["alt_pattern_offset"].is_null()) {
        mb.altPatternOffset = j["alt_pattern_offset"].get<uintptr_t>();
    } else {
        mb.altPatternOffset = std::nullopt;
    }
    if (j.contains("vtable_slot") && !j["vtable_slot"].is_null()) {
        mb.vtableSlot = j["vtable_slot"].get<size_t>();
    } else {
        mb.vtableSlot = std::nullopt;
    }
    if (j.contains("vtable_name") && !j["vtable_name"].is_null()) {
        mb.vtableName = j["vtable_name"].get<std::string>();
    } else {
        mb.vtableName = std::nullopt;
    }
    if (j.contains("vtable_slot_count") && !j["vtable_slot_count"].is_null()) {
        mb.vtableSlotCount = j["vtable_slot_count"].get<size_t>();
    } else {
        mb.vtableSlotCount = std::nullopt;
    }
    if (j.contains("call_targets") && !j["call_targets"].is_null()) {
        mb.callTargets = j["call_targets"].get<std::vector<std::string>>();
    }
    if (j.contains("func_size") && !j["func_size"].is_null()) {
        mb.funcSize = j["func_size"].get<size_t>();
    } else {
        mb.funcSize = std::nullopt;
    }

    if (j.contains("offset") && !j["offset"].is_null()) {
        mb.offset = j["offset"].get<uintptr_t>();
    } else {
        mb.offset = std::nullopt;
    }
}

void to_json(nlohmann::json& j, ClassBinding const& cb) {
    j["name"] = cb.name;
    j["functions"] = nlohmann::json::array();
    for (auto const& method : cb.methods) {
        j["functions"].emplace_back(method);
    }
}

void from_json(nlohmann::json const& j, ClassBinding& cb) {
    cb.name = j["name"].get<std::string>();
    auto& jsonMethods = j["functions"];
    for (auto& jsonMethod : jsonMethods) {
        cb.methods.emplace_back(jsonMethod.get<MethodBinding>());
    }
}
