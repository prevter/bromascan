#pragma once
#include <climits>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include <sinaps.hpp>
#include <fmt/format.h>
#include <Geode/Result.hpp>
#include <broma/FunctionList.hpp>

#if defined(__x86_64__) || defined(__i386__)
#include <emmintrin.h>
#endif

namespace assembly {
    enum class GenerateError {
        None,
        NotFound,
        PatternTooLarge,
        InvalidInstruction,
    };

    inline std::string_view format_as(GenerateError error) {
        switch (error) {
            case GenerateError::None:
                return "None";
            case GenerateError::NotFound:
                return "NotFound";
            case GenerateError::PatternTooLarge:
                return "PatternTooLarge";
            case GenerateError::InvalidInstruction:
                return "InvalidInstruction";
            default:
                return "Unknown";
        }
    }

    namespace detail {
        inline std::vector<uintptr_t> findAllMatches(
            uint8_t const* data,
            size_t size,
            sinaps::token_t const* pattern,
            size_t pattern_size,
            size_t step_size
        ) {
            std::vector<uintptr_t> matches;
            if (size < pattern_size) return matches;
            matches.reserve(64);

            if (pattern_size == 4 && step_size == 4) {
                uint32_t patVal = 0, patMask = 0;
                for (int i = 0; i < 4; ++i) {
                    if (pattern[i].type != sinaps::token_t::type_t::wildcard) {
                        patVal |= static_cast<uint32_t>(pattern[i].byte) << (i * 8);
                        patMask |= static_cast<uint32_t>(pattern[i].mask) << (i * 8);
                    }
                }

                size_t limit = size - 4;
                size_t i = 0;

            #if defined(__x86_64__) || defined(__i386__)
                if (patMask != 0) {
                    __m128i maskV = _mm_set1_epi32(static_cast<int>(patMask));
                    __m128i patV = _mm_set1_epi32(static_cast<int>(patVal));
                    while (i + 16 <= limit + 1) {
                        __m128i v = _mm_loadu_si128(reinterpret_cast<__m128i const*>(data + i));
                        __m128i masked = _mm_and_si128(v, maskV);
                        __m128i cmp = _mm_cmpeq_epi32(masked, patV);
                        unsigned int mask = _mm_movemask_ps(_mm_castsi128_ps(cmp));
                        if (mask) {
                            if (mask & 1) matches.push_back(i);
                            if (mask & 2) matches.push_back(i + 4);
                            if (mask & 4) matches.push_back(i + 8);
                            if (mask & 8) matches.push_back(i + 12);
                        }
                        i += 16;
                    }
                }
            #endif

                while (i <= limit) {
                    uint32_t v;
                    std::memcpy(&v, data + i, 4);
                    if ((v & patMask) == patVal) {
                        matches.push_back(i);
                    }
                    i += 4;
                }
                return matches;
            }

            size_t limit = size - pattern_size;
            for (size_t i = 0; i <= limit; i += step_size) {
                bool found = true;
                for (size_t j = 0; j < pattern_size; ++j) {
                    switch (pattern[j].type) {
                        case sinaps::token_t::type_t::byte:
                            if (data[i + j] != pattern[j].byte) { found = false; }
                            break;
                        case sinaps::token_t::type_t::masked:
                            if ((data[i + j] & pattern[j].mask) != pattern[j].byte) { found = false; }
                            break;
                        default:
                            break;
                    }
                    if (!found) break;
                }

                if (found) {
                    matches.push_back(static_cast<uintptr_t>(i));
                }
            }

            return matches;
        }

        inline bool matchesRange(
            uint8_t const* data,
            size_t size,
            uintptr_t pos,
            sinaps::token_t const* tokens,
            size_t token_offset,
            size_t token_count
        ) {
            if (pos + token_offset + token_count > size) return false;
            auto* ptr = data + pos + token_offset;
            for (size_t j = 0; j < token_count; ++j) {
                switch (tokens[token_offset + j].type) {
                    case sinaps::token_t::type_t::byte:
                        if (ptr[j] != tokens[token_offset + j].byte) return false;
                        break;
                    case sinaps::token_t::type_t::masked:
                        if ((ptr[j] & tokens[token_offset + j].mask) != tokens[token_offset + j].byte) return false;
                        break;
                    default:
                        break;
                }
            }
            return true;
        }
    }

    inline std::optional<size_t> findFirstMatch(
        uint8_t const* data,
        size_t size,
        sinaps::token_t const* pattern,
        size_t pattern_size,
        size_t step_size
    ) {
        if (size < pattern_size) return std::nullopt;

        if (pattern_size == 4 && step_size == 4) {
            uint32_t patVal = 0, patMask = 0;
            for (int i = 0; i < 4; ++i) {
                if (pattern[i].type != sinaps::token_t::type_t::wildcard) {
                    patVal |= static_cast<uint32_t>(pattern[i].byte) << (i * 8);
                    patMask |= static_cast<uint32_t>(pattern[i].mask) << (i * 8);
                }
            }

            size_t limit = size - 4;
            size_t i = 0;

        #if defined(__x86_64__) || defined(__i386__)
            if (patMask != 0) {
                __m128i maskV = _mm_set1_epi32(static_cast<int>(patMask));
                __m128i patV = _mm_set1_epi32(static_cast<int>(patVal));
                while (i + 16 <= limit + 1) {
                    __m128i v = _mm_loadu_si128(reinterpret_cast<__m128i const*>(data + i));
                    __m128i masked = _mm_and_si128(v, maskV);
                    __m128i cmp = _mm_cmpeq_epi32(masked, patV);
                    unsigned int mask = _mm_movemask_ps(_mm_castsi128_ps(cmp));
                    if (mask) {
                        if (mask & 1) return i;
                        if (mask & 2) return i + 4;
                        if (mask & 4) return i + 8;
                        if (mask & 8) return i + 12;
                    }
                    i += 16;
                }
            }
        #endif

            while (i <= limit) {
                uint32_t v;
                std::memcpy(&v, data + i, 4);
                if ((v & patMask) == patVal) {
                    return i;
                }
                i += 4;
            }
            return std::nullopt;
        }

        size_t limit = size - pattern_size;
        for (size_t i = 0; i <= limit; i += step_size) {
            bool found = true;
            for (size_t j = 0; j < pattern_size; ++j) {
                switch (pattern[j].type) {
                    case sinaps::token_t::type_t::byte:
                        if (data[i + j] != pattern[j].byte) { found = false; }
                        break;
                    case sinaps::token_t::type_t::masked:
                        if ((data[i + j] & pattern[j].mask) != pattern[j].byte) { found = false; }
                        break;
                    default:
                        break;
                }
                if (!found) break;
            }
            if (found) {
                return i;
            }
        }
        return std::nullopt;
    }

    inline std::optional<size_t> fuzzyMatchAtFunctionStarts(
        uint8_t const* data,
        size_t size,
        sinaps::token_t const* pattern,
        size_t pattern_size,
        bromascan::FunctionList const* functionList,
        uintptr_t baseCorrection,
        size_t maxMismatches,
        size_t requiredMargin,
        size_t* bestMismatchesOut = nullptr
    ) {
        if (!functionList || functionList->empty() || pattern_size == 0) {
            return std::nullopt;
        }

        size_t bestMismatches = SIZE_MAX;
        size_t secondBest = SIZE_MAX;
        size_t bestOffset = SIZE_MAX;
        bool any = false;

        for (auto const& entry : functionList->entries()) {
            uintptr_t rva = entry.address;
            if (rva < baseCorrection) continue;
            size_t offset = static_cast<size_t>(rva - baseCorrection);
            if (offset + pattern_size > size) continue;

            size_t mismatches = 0;
            for (size_t j = 0; j < pattern_size; ++j) {
                switch (pattern[j].type) {
                    case sinaps::token_t::type_t::byte:
                        if (data[offset + j] != pattern[j].byte) ++mismatches;
                        break;
                    case sinaps::token_t::type_t::masked:
                        if ((data[offset + j] & pattern[j].mask) != pattern[j].byte) ++mismatches;
                        break;
                    default:
                        break;
                }
                if (mismatches > maxMismatches) break;
            }
            if (mismatches > maxMismatches) continue;

            any = true;
            if (mismatches < bestMismatches) {
                secondBest = bestMismatches;
                bestMismatches = mismatches;
                bestOffset = offset;
            } else if (mismatches < secondBest) {
                secondBest = mismatches;
            }
        }

        if (!any) return std::nullopt;
        if (bestMismatches > maxMismatches) return std::nullopt;
        if (secondBest != SIZE_MAX && (secondBest - bestMismatches) < requiredMargin) {
            return std::nullopt;
        }

        if (bestMismatchesOut) *bestMismatchesOut = bestMismatches;
        return bestOffset;
    }

    template <typename T>
    concept GeneratorConcept = requires(T t, std::span<uint8_t const> data) {
        { T(data) } -> std::same_as<T>;
        { t.readNextOpcode() } -> std::same_as<geode::Result<typename T::Opcode, GenerateError>>;
    };

    template <GeneratorConcept Generator>
    geode::Result<void, GenerateError> generatePattern(
        std::vector<sinaps::token_t>& outTokens,
        std::span<uint8_t const> data,
        uintptr_t offset,
        size_t maxSize = 256
    ) {
        outTokens.reserve(64);
        auto* dataPtr = data.data();
        auto dataSize = data.size();
        if (offset >= dataSize) {
            return geode::Err(GenerateError::NotFound);
        }

        Generator gen(std::span(dataPtr + offset, dataSize - offset));

        std::vector<uintptr_t> candidates;
        bool initialScanDone = false;
        size_t lastVerifiedTokenCount = 0;

        while (auto opc = gen.readNextOpcode()) {
            if (!opc.unwrap().appendTokens(outTokens)) {
                return geode::Err(GenerateError::InvalidInstruction);
            }

            if (outTokens.size() > maxSize) {
                return geode::Err(GenerateError::PatternTooLarge);
            }

            size_t currentTokenCount = outTokens.size();

            if (!initialScanDone) {
                candidates = detail::findAllMatches(
                    dataPtr,
                    dataSize,
                    outTokens.data(),
                    currentTokenCount,
                    Generator::IterSize
                );
                initialScanDone = true;
                lastVerifiedTokenCount = currentTokenCount;

                auto selfInCandidates = std::ranges::find(candidates, offset) != candidates.end();
                if (!selfInCandidates) {
                    return geode::Err(GenerateError::NotFound);
                }

                if (candidates.size() == 1) {
                    return geode::Ok();
                }
            } else {
                size_t newTokensStart = lastVerifiedTokenCount;
                size_t newTokensCount = currentTokenCount - lastVerifiedTokenCount;

                size_t writeIdx = 0;
                for (size_t readIdx = 0; readIdx < candidates.size(); ++readIdx) {
                    auto pos = candidates[readIdx];
                    if (detail::matchesRange(
                        dataPtr,
                        dataSize,
                        pos,
                        outTokens.data(),
                        newTokensStart,
                        newTokensCount
                    )) {
                        candidates[writeIdx++] = pos;
                    }
                }

                candidates.resize(writeIdx);
                lastVerifiedTokenCount = currentTokenCount;

                if (candidates.size() == 1 && candidates[0] == offset) {
                    return geode::Ok();
                }

                if (candidates.empty()) {
                    return geode::Err(GenerateError::NotFound);
                }
            }
        }

        return geode::Err(GenerateError::NotFound);
    }

    struct GenerateOptions {
        size_t maxSize = 256;
        bromascan::FunctionList const* functionList = nullptr;
        uintptr_t baseCorrection = 0;
    };

    template <GeneratorConcept Generator>
    geode::Result<void, GenerateError> generatePattern(
        std::vector<sinaps::token_t>& outTokens,
        std::span<uint8_t const> data,
        uintptr_t offset,
        GenerateOptions opts
    ) {
        return generatePattern<Generator>(outTokens, data, offset, opts.maxSize);
    }
}
