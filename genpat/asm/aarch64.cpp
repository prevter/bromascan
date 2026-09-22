#include "aarch64.hpp"

#include <mutex>
#include <unordered_map>

#include <capstone/aarch64.h>
#include <capstone/capstone.h>

#include <fmt/format.h>

using namespace geode;

static std::unordered_map<std::string, size_t>& getUnkInstructionMap() {
    static auto* map = new std::unordered_map<std::string, size_t>();

    static std::once_flag flag;
    std::call_once(flag, [] {
        std::atexit([]() {
            if (map->empty()) return;
            std::vector<std::pair<std::string, size_t>> sorted(map->begin(), map->end());
            std::ranges::sort(sorted, [](auto const& a, auto const& b) {
                return b.second < a.second;
            });

            fmt::println("Unknown AArch64 instructions encountered:");
            for (auto const& [mnemonic, count] : sorted) {
                fmt::println("  {}: {}", mnemonic, count);
            }
        });
    });

    return *map;
}

namespace assembly::aarch64 {
    struct CapstoneHandle {
        csh handle = 0;
        cs_insn* ins = nullptr;

        CapstoneHandle() {
            if (cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
                fmt::println("Failed to initialize Capstone disassembler");
                std::terminate();
            }
            cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
            ins = cs_malloc(handle);
        }

        ~CapstoneHandle() {
            cs_free(ins, 1);
            cs_close(&handle);
        }

        CapstoneHandle(CapstoneHandle const&) = delete;
        CapstoneHandle& operator=(CapstoneHandle const&) = delete;
    };

    static CapstoneHandle& threadHandle() {
        thread_local CapstoneHandle h;
        return h;
    }

    bool Generator::Opcode::appendTokens(std::vector<sinaps::token_t>& outTokens) const {
        auto masked = this->getMasked();
        auto mask = this->m_mask;

        for (size_t i = 0; i < 4; ++i) {
            outTokens.emplace_back(masked & 0xff, mask & 0xff);
            masked >>= 8;
            mask >>= 8;
        }

        return true;
    }

    Result<Generator::Opcode, GenerateError> Generator::readNextOpcode() {
        auto& h = threadHandle();

        auto code = m_data.data() + m_position;
        size_t codeSize = m_data.size() - m_position;
        uint64_t address = m_position;

        if (!cs_disasm_iter(h.handle, &code, &codeSize, &address, h.ins)) {
            fmt::println("Failed to disassemble instruction: {}", cs_strerror(cs_errno(h.handle)));
            return Err(GenerateError::NotFound);
        }

        auto* ins = h.ins;
        uint32_t mask = 0;
        cs_aarch64& detail = ins->detail->aarch64;
        switch (ins->is_alias ? ins->alias_id : ins->id) {
            case AARCH64_INS_ALIAS_SUB: [[fallthrough]];
            case AARCH64_INS_SUB: {
                // sub sp, sp, #imm - prologue stack frame
                if (detail.operands[1].reg == AARCH64_REG_SP) {
                    mask = 0xffc003ff;
                }
                // immediate value
                else if (detail.operands[0].reg == detail.operands[1].reg) {
                    mask = 0b11111111'11000000'00000011'11111111;
                }
                // extended register
                else if (detail.operands[0].reg != detail.operands[1].reg &&
                         detail.operands[2].type == AARCH64_OP_REG) {
                    mask = 0b11111111'11111111'11100011'11111111;
                }
                // shifted register
                else if (detail.operands[2].type == AARCH64_OP_IMM) {
                    mask = 0b11111111'11111111'00000011'11111111;
                }
                break;
            }
            case AARCH64_INS_ALIAS_STP: [[fallthrough]];
            case AARCH64_INS_STP: {
                // stp xN, xN, [sp, #imm] - common prologue pattern
                if (detail.operands[2].mem.base == AARCH64_REG_SP) {
                    mask = 0xffff83e0;
                } else {
                    // generic stp instruction
                    mask = 0xffff8000;
                }
                break;
            }
            case AARCH64_INS_ALIAS_ADD: [[fallthrough]];
            case AARCH64_INS_ADD: {
                // add xN, sp, #imm - prologue stack frame
                if (detail.operands[1].reg == AARCH64_REG_SP) {
                    mask = 0xffc003ff;
                }
                // immediate value
                else if (detail.operands[0].reg == detail.operands[1].reg) {
                    mask = 0b11111111'11000000'00000011'11111111;
                }
                // extended register
                else if (detail.operands[0].reg != detail.operands[1].reg &&
                         detail.operands[2].type == AARCH64_OP_REG) {
                    mask = 0b11111111'11111111'11100011'11111111;
                }
                // shifted register
                else if (detail.operands[2].type == AARCH64_OP_IMM) {
                    mask = 0b11111111'11111111'00000011'11111111;
                }
                break;
            }
            case AARCH64_INS_ALIAS_MOV: [[fallthrough]];
            case AARCH64_INS_MOV: {
                // mov xN, xM - Keep full opcode (typically stable)
                if (detail.operands[0].type == AARCH64_OP_REG &&
                    detail.operands[1].type == AARCH64_OP_REG) {
                    mask = 0xffffffff;
                } else {
                    // generic mov instruction
                    mask = 0xffe0fc00;
                }
                break;
            }
            case AARCH64_INS_B: {
                // -- Branch instructions --
                // Keep only the opcode (branch target may change)
                // 0xfc = 11111100
                if (ins->detail->aarch64.cc == AArch64CC_Invalid) {
                    mask = 0xfc000000;
                } else {
                    // conditional branch
                    mask = 0xff000010;
                }
                break;
            }
            case AARCH64_INS_BL: {
                mask = 0xfc000000;
                break;
            }
            case AARCH64_INS_CBZ: [[fallthrough]];
            case AARCH64_INS_CBNZ: {
                // cbz xN, #imm - Keep only the opcode (branch target may change)
                mask = 0xff000000;
                break;
            }
            case AARCH64_INS_ALIAS_STR: [[fallthrough]];
            case AARCH64_INS_ALIAS_LDR: [[fallthrough]];
            case AARCH64_INS_STR: [[fallthrough]];
            case AARCH64_INS_LDR: {
                // str/ldr xN, [sp, #imm] - Keep full opcode (stack size usually stable)
                if (detail.operands[1].type == AARCH64_OP_MEM &&
                    detail.operands[1].mem.base == AARCH64_REG_SP) {
                    mask = 0xffffffe0;
                } else {
                    // store the opcode
                    mask = ins->id == AARCH64_INS_LDR ? 0xff000000 : 0xffc00000;
                }
                break;
            }
            case AARCH64_INS_STRB: {
                // store the opcode
                mask = 0xffe0fc00;
                break;
            }
            case AARCH64_INS_BRK: {
                mask = 0xffffffff;
                break;
            }
            case AARCH64_INS_ADRP: {
                // store the opcode
                mask = 0x9f000000;
                break;
            }
            case AARCH64_INS_FMOV: {
                // vector, immediate
                if (detail.operands[0].type == AARCH64_OP_REG &&
                    detail.operands[1].type == AARCH64_OP_REG) {
                    mask = 0xffffffff;
                }
                break;
            }
            case AARCH64_INS_ALIAS_RET: [[fallthrough]];
            case AARCH64_INS_RET: {
                mask = 0b11111111'11111111'11111100'00011111;
                break;
            }
            case AARCH64_INS_LDP: {
                if (detail.operands[2].type == AARCH64_OP_MEM && detail.operands[2].mem.base == AARCH64_REG_SP) {
                    mask = 0xffff83e0;
                } else {
                    mask = 0xffa08000;
                }
                break;
            }
            case AARCH64_INS_BLR: {
                mask = 0b11111111'11111111'11111100'00011111;
                break;
            }
            case AARCH64_INS_TBZ: [[fallthrough]];
            case AARCH64_INS_TBNZ: {
                mask = 0xff000000;
                break;
            }
            case AARCH64_INS_BR: {
                mask = 0b11111111'11111111'11111100'00011111;
                break;
            }
            case AARCH64_INS_STUR: [[fallthrough]];
            case AARCH64_INS_LDUR: {
                if (detail.operands[1].type == AARCH64_OP_MEM && detail.operands[1].mem.base == AARCH64_REG_SP) {
                    mask = 0xffffffe0;
                } else {
                    mask = 0xffe00c00;
                }
                break;
            }
            case AARCH64_INS_MOVK: [[fallthrough]];
            case AARCH64_INS_MOVZ: [[fallthrough]];
            case AARCH64_INS_MOVN: {
                mask = 0xff800000;
                break;
            }
            case AARCH64_INS_ALIAS_CMP: {
                if (detail.operands[1].type == AARCH64_OP_REG) {
                    mask = 0xffe0fc1f;
                } else {
                    mask = 0xffc0001f;
                }
                break;
            }
            case AARCH64_INS_ALIAS_CSET: [[fallthrough]];
            case AARCH64_INS_CSINC: {
                mask = 0xffe0fc00;
                break;
            }
            case AARCH64_INS_CSEL: {
                mask = 0xffe0fc00;
                break;
            }
            case AARCH64_INS_MSR: {
                mask = 0xffffffff;
                break;
            }
            case AARCH64_INS_MRS: {
                mask = 0xffdfffff;
                break;
            }
            case AARCH64_INS_UXTB: [[fallthrough]];
            case AARCH64_INS_UXTH: [[fallthrough]];
            case AARCH64_INS_SXTB: [[fallthrough]];
            case AARCH64_INS_SXTH: {
                mask = 0xffe0fc00;
                break;
            }
            case AARCH64_INS_LSL: [[fallthrough]];
            case AARCH64_INS_LSR: [[fallthrough]];
            case AARCH64_INS_ASR: [[fallthrough]];
            case AARCH64_INS_ROR: {
                mask = 0xff200c00;
                break;
            }
            case AARCH64_INS_AND: [[fallthrough]];
            case AARCH64_INS_ORR: [[fallthrough]];
            case AARCH64_INS_EOR: [[fallthrough]];
            case AARCH64_INS_BIC: {
                if (detail.operands[1].type == AARCH64_OP_REG &&
                    detail.operands[2].type == AARCH64_OP_IMM) {
                    mask = 0xff80001f;
                } else {
                    mask = 0xff200c00;
                }
                break;
            }
            case AARCH64_INS_ANDS: [[fallthrough]];
            case AARCH64_INS_EORS: {
                mask = 0xff200c00;
                break;
            }
            case AARCH64_INS_MADD: [[fallthrough]];
            case AARCH64_INS_MSUB: {
                mask = 0xff00fc00;
                break;
            }
            case AARCH64_INS_SDIV: [[fallthrough]];
            case AARCH64_INS_UDIV: {
                mask = 0xffe0fc1f;
                break;
            }
            case AARCH64_INS_CLZ: [[fallthrough]];
            case AARCH64_INS_RBIT: [[fallthrough]];
            case AARCH64_INS_REV: [[fallthrough]];
            case AARCH64_INS_REV16: [[fallthrough]];
            case AARCH64_INS_REV32: {
                mask = 0xfffffc00;
                break;
            }
            case AARCH64_INS_CCMN: [[fallthrough]];
            case AARCH64_INS_CCMP: {
                mask = 0xe0700000;
                break;
            }
            case AARCH64_INS_STRH: [[fallthrough]];
            case AARCH64_INS_LDRH: {
                if (detail.operands[1].type == AARCH64_OP_MEM &&
                    detail.operands[1].mem.base == AARCH64_REG_SP) {
                    mask = 0xFFFFFFE0;
                } else {
                    mask = 0xffc00000;
                }
                break;
            }
            case AARCH64_INS_STURB: [[fallthrough]];
            case AARCH64_INS_STURH: [[fallthrough]];
            case AARCH64_INS_LDURB: [[fallthrough]];
            case AARCH64_INS_LDURH: [[fallthrough]];
            case AARCH64_INS_LDURSW: [[fallthrough]];
            case AARCH64_INS_LDURSB: [[fallthrough]];
            case AARCH64_INS_LDURSH: {
                if (detail.operands[1].type == AARCH64_OP_MEM &&
                    detail.operands[1].mem.base == AARCH64_REG_SP) {
                    mask = 0xFFFFFFE0;
                } else {
                    mask = 0xffe00c00;
                }
                break;
            }
            case AARCH64_INS_ALIAS_NOP: {
                mask = 0xffffffff;
                break;
            }
            case AARCH64_INS_ALIAS_TST: {
                mask = 0xffe0fc1f;
                break;
            }
            case AARCH64_INS_ERET: {
                mask = 0xffffffff;
                break;
            }
            case AARCH64_INS_SVC: {
                mask = 0xffffffff;
                break;
            }
            case AARCH64_INS_HLT: {
                mask = 0xffffffff;
                break;
            }
            case AARCH64_INS_ADR: {
                mask = 0x9f000000;
                break;
            }
            default: {
                // auto mnem = std::string_view(ins->mnemonic);
                // if (mnem == "ldr") {
                //     fmt::println(
                //         "UNK [{} {}]: {:02x} {:02x} {:02x} {:02x} : {} {}",
                //         ins->is_alias ? "alias" : "normal",
                //         ins->is_alias ? ins->alias_id : ins->id,
                //         ins->bytes[0], ins->bytes[1], ins->bytes[2], ins->bytes[3],
                //         ins->mnemonic, ins->op_str
                //     );
                // }
                // fmt::println(
                //     "UNK [{} {}]: {:02x} {:02x} {:02x} {:02x} : {} {}",
                //     ins->is_alias ? "alias" : "normal",
                //     ins->is_alias ? ins->alias_id : ins->id,
                //     ins->bytes[0], ins->bytes[1], ins->bytes[2], ins->bytes[3],
                //     ins->mnemonic, ins->op_str
                // );
                // static std::mutex mutex;
                // std::scoped_lock lock(mutex);
                // getUnkInstructionMap()[ins->mnemonic]++;
                break;
            }
        }

        m_position += 4;

        return Ok(Opcode{
            {
                ins->bytes[0],
                ins->bytes[1],
                ins->bytes[2],
                ins->bytes[3]
            },
            mask
        });
    }
}
