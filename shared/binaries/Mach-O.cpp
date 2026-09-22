#include "Mach-O.hpp"

namespace bin::mach {
    geode::Result<std::span<uint8_t const>> getSegment(std::span<uint8_t const> binaryData, CPUType type) {
        auto magic = *reinterpret_cast<uint32_t const*>(binaryData.data());

        if (magic == MH_MAGIC_64) {
            auto header64 = reinterpret_cast<mach_header_64 const*>(binaryData.data());
            size_t offset = sizeof(mach_header_64) + header64->sizeofcmds;
            if (offset > binaryData.size()) {
                return geode::Err("Invalid Mach-O 64-bit header size");
            }
            return geode::Ok(binaryData.subspan(offset));
        }

        if (magic == FAT_MAGIC) {
            auto fatHeader = reinterpret_cast<fat_header const*>(binaryData.data());
            auto fatArches = reinterpret_cast<fat_arch const*>(binaryData.data() + sizeof(fat_header));
            for (uint32_t i = 0; i < fatHeader->get_nfat_arch(); ++i) {
                if (fatArches[i].get_cputype() == static_cast<cpu_type_t>(type)) {
                    size_t offset = fatArches[i].get_offset();
                    size_t size = fatArches[i].get_size();
                    if (offset + size > binaryData.size()) {
                        return geode::Err("Invalid fat binary architecture size");
                    }
                    return geode::Ok(binaryData.subspan(offset, size));
                }
            }
            return geode::Err("Specified CPU type not found in fat binary");
        }

        return geode::Err("Unsupported Mach-O format");
    }

    bool isFatBinary(std::span<uint8_t const> binaryData) {
        if (binaryData.size() < sizeof(fat_header)) {
            return false;
        }

        auto magic = *reinterpret_cast<uint32_t const*>(binaryData.data());
        return magic == FAT_MAGIC;
    }

    bool isMachO64(std::span<uint8_t const> binaryData) {
        if (binaryData.size() < sizeof(mach_header_64)) {
            return false;
        }

        auto magic = *reinterpret_cast<uint32_t const*>(binaryData.data());
        return magic == MH_MAGIC_64;
    }

    uintptr_t getImageBase(std::span<uint8_t const> binaryData) {
        auto magic = *reinterpret_cast<uint32_t const*>(binaryData.data());
        std::span<uint8_t const> slice = binaryData;

        if (magic == FAT_MAGIC) {
            auto fatHeader = reinterpret_cast<fat_header const*>(binaryData.data());
            auto fatArches = reinterpret_cast<fat_arch const*>(binaryData.data() + sizeof(fat_header));
            for (uint32_t i = 0; i < fatHeader->get_nfat_arch(); ++i) {
                size_t offset = fatArches[i].get_offset();
                size_t size = fatArches[i].get_size();
                if (offset + size <= binaryData.size()) {
                    slice = binaryData.subspan(offset, size);
                    break;
                }
            }
        }

        if (slice.size() < sizeof(mach_header_64)) return 0;
        auto header = reinterpret_cast<mach_header_64 const*>(slice.data());
        if (header->magic != MH_MAGIC_64) return 0;

        constexpr uint32_t LC_SEGMENT_64 = 0x19;
        struct segment_command_64 {
            uint32_t cmd; uint32_t cmdsize; char segname[16];
            uint64_t vmaddr, vmsize, fileoff, filesize;
            int32_t maxprot, initprot; uint32_t nsects, flags;
        };

        size_t offset = sizeof(mach_header_64);
        for (uint32_t i = 0; i < header->ncmds && offset + sizeof(segment_command_64) <= slice.size(); ++i) {
            auto* seg = reinterpret_cast<segment_command_64 const*>(slice.data() + offset);
            if (seg->cmd == LC_SEGMENT_64) {
                if (std::string_view(seg->segname, 16).starts_with("__TEXT")) {
                    return seg->vmaddr;
                }
            }
            if (seg->cmdsize == 0) break;
            offset += seg->cmdsize;
        }

        return 0;
    }

    std::vector<uintptr_t> getFunctionStarts(std::span<uint8_t const> binaryData, CPUType type) {
        std::vector<uintptr_t> result;
        auto magic = *reinterpret_cast<uint32_t const*>(binaryData.data());
        std::span<uint8_t const> slice = binaryData;

        if (magic == FAT_MAGIC) {
            auto fatHeader = reinterpret_cast<fat_header const*>(binaryData.data());
            auto fatArches = reinterpret_cast<fat_arch const*>(binaryData.data() + sizeof(fat_header));
            for (uint32_t i = 0; i < fatHeader->get_nfat_arch(); ++i) {
                if (fatArches[i].get_cputype() == static_cast<cpu_type_t>(type)) {
                    size_t offset = fatArches[i].get_offset();
                    size_t size = fatArches[i].get_size();
                    if (offset + size <= binaryData.size()) {
                        slice = binaryData.subspan(offset, size);
                        break;
                    }
                }
            }
        }

        if (slice.size() < sizeof(mach_header_64)) return result;
        auto header = reinterpret_cast<mach_header_64 const*>(slice.data());
        if (header->magic != MH_MAGIC_64) return result;

        constexpr uint32_t LC_SEGMENT_64 = 0x19;
        constexpr uint32_t LC_FUNCTION_STARTS = 0x26;
        struct segment_command_64 {
            uint32_t cmd; uint32_t cmdsize; char segname[16];
            uint64_t vmaddr, vmsize, fileoff, filesize;
            int32_t maxprot, initprot; uint32_t nsects, flags;
        };
        struct linkedit_data_command {
            uint32_t cmd; uint32_t cmdsize;
            uint32_t dataoff; uint32_t datasize;
        };

        uintptr_t textVmAddr = 0;
        uint32_t funcDataOff = 0, funcDataSize = 0;

        size_t offset = sizeof(mach_header_64);
        for (uint32_t i = 0; i < header->ncmds && offset + 8 <= slice.size(); ++i) {
            auto* cmd = reinterpret_cast<uint32_t const*>(slice.data() + offset);
            if (*cmd == LC_SEGMENT_64 && offset + sizeof(segment_command_64) <= slice.size()) {
                auto* seg = reinterpret_cast<segment_command_64 const*>(slice.data() + offset);
                if (std::string_view(seg->segname, 16).starts_with("__TEXT")) {
                    textVmAddr = static_cast<uintptr_t>(seg->vmaddr);
                }
            } else if (*cmd == LC_FUNCTION_STARTS && offset + sizeof(linkedit_data_command) <= slice.size()) {
                auto* ldc = reinterpret_cast<linkedit_data_command const*>(slice.data() + offset);
                funcDataOff = ldc->dataoff;
                funcDataSize = ldc->datasize;
            }
            uint32_t cmdsize = *(reinterpret_cast<uint32_t const*>(slice.data() + offset + 4));
            if (cmdsize == 0) break;
            offset += cmdsize;
        }

        if (funcDataOff == 0 || funcDataSize == 0) return result;
        if (funcDataOff + funcDataSize > slice.size()) return result;

        auto* data = slice.data() + funcDataOff;
        size_t pos = 0;
        uintptr_t prevAddr = textVmAddr;

        while (pos < funcDataSize) {
            uintptr_t delta = 0;
            int shift = 0;
            while (pos < funcDataSize) {
                uint8_t byte = data[pos++];
                delta |= static_cast<uintptr_t>(byte & 0x7f) << shift;
                shift += 7;
                if (!(byte & 0x80)) break;
            }
            if (delta == 0) continue;
            prevAddr += delta;
            result.push_back(prevAddr);
        }

        return result;
    }
}
