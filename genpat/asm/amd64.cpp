#include "amd64.hpp"

using namespace geode;

#include <fmt/format.h>
#include <Zydis/Zydis.h>

namespace assembly::amd64 {
    bool Generator::Opcode::appendTokens(std::vector<sinaps::token_t>& outTokens) const {
        auto copyBytes = [&](size_t start, size_t count, bool isWildcard = false) {
            for (size_t i = 0; i < count; ++i) {
                if (isWildcard) {
                    outTokens.emplace_back(sinaps::token_t::type_t::wildcard);
                } else {
                    outTokens.emplace_back(m_data[start + i]);
                }
            }
        };

        ZydisInstructionSegments segments;
        ZydisGetInstructionSegments(&m_instruction.info, &segments);

        for (size_t i = 0; i < segments.count; ++i) {
            auto const& [type, offset, size] = segments.segments[i];
            switch (type) {
                case ZYDIS_INSTR_SEGMENT_DISPLACEMENT:
                case ZYDIS_INSTR_SEGMENT_IMMEDIATE:
                    copyBytes(offset, size, true);
                    break;
                default:
                    copyBytes(offset, size, false);
                    break;
            }
        }

        return true;
    }

    Result<Generator::Opcode, GenerateError> Generator::readNextOpcode() {
        if (m_position >= m_data.size()) {
            return Err(GenerateError::NotFound);
        }

        auto ptr = m_data.data() + m_position;
        auto status = ZydisDisassembleIntel(
            ZYDIS_MACHINE_MODE_LONG_64,
            0, ptr,
            m_data.size() - m_position,
            &m_lastInstruction
        );

        if (ZYAN_FAILED(status)) {
            return Err(GenerateError::NotFound);
        }

        // if 0xCC (int3), return NotFound
        if (m_lastInstruction.info.opcode == 0xCC) {
            return Err(GenerateError::NotFound);
        }

        m_position += m_lastInstruction.info.length;
        return Ok(Opcode{m_lastInstruction, ptr});
    }
}
