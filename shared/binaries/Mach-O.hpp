#pragma once

#include <bit>
#include <cstdint>
#include <span>
#include <Geode/Result.hpp>

namespace bin::mach {
    using cpu_type_t = uint32_t;
    using cpu_subtype_t = uint32_t;

    constexpr bool is_big_endian = std::endian::native == std::endian::big;
    constexpr uint32_t MH_MAGIC = is_big_endian ? 0xCEFAEDFE : 0xFEEDFACE;
    constexpr uint32_t MH_MAGIC_64 = is_big_endian ? 0xCFFAEDFE : 0xFEEDFACF;
    constexpr uint32_t FAT_MAGIC = is_big_endian ? 0xCAFEBABE : 0xBEBAFECA;

    // Mach-O structures use big endian smh...
    #define GEN_GETTER(type, name) \
        [[nodiscard]] type get_##name() const { \
            return is_big_endian ? name : std::byteswap(name); \
        }

    struct mach_header {
        uint32_t magic; // MH_MAGIC
        cpu_type_t cputype;
        cpu_subtype_t cpusubtype;
        uint32_t filetype;
        uint32_t ncmds;
        uint32_t sizeofcmds;
        uint32_t flags;

        GEN_GETTER(uint32_t, magic)
        GEN_GETTER(cpu_type_t, cputype)
        GEN_GETTER(cpu_subtype_t, cpusubtype)
        GEN_GETTER(uint32_t, filetype)
        GEN_GETTER(uint32_t, ncmds)
        GEN_GETTER(uint32_t, sizeofcmds)
        GEN_GETTER(uint32_t, flags)
    };

    struct mach_header_64 {
        uint32_t magic; // MH_MAGIC_64
        cpu_type_t cputype;
        cpu_subtype_t cpusubtype;
        uint32_t filetype;
        uint32_t ncmds;
        uint32_t sizeofcmds;
        uint32_t flags;
        uint32_t reserved;

        GEN_GETTER(uint32_t, magic)
        GEN_GETTER(cpu_type_t, cputype)
        GEN_GETTER(cpu_subtype_t, cpusubtype)
        GEN_GETTER(uint32_t, filetype)
        GEN_GETTER(uint32_t, ncmds)
        GEN_GETTER(uint32_t, sizeofcmds)
        GEN_GETTER(uint32_t, flags)
        GEN_GETTER(uint32_t, reserved)
    };

    struct fat_header {
        uint32_t magic; // FAT_MAGIC
        uint32_t nfat_arch;

        GEN_GETTER(uint32_t, magic)
        GEN_GETTER(uint32_t, nfat_arch)
    };

    struct fat_arch {
        cpu_type_t cputype;
        cpu_subtype_t cpusubtype;
        uint32_t offset;
        uint32_t size;
        uint32_t align;

        GEN_GETTER(cpu_type_t, cputype)
        GEN_GETTER(cpu_subtype_t, cpusubtype)
        GEN_GETTER(uint32_t, offset)
        GEN_GETTER(uint32_t, size)
        GEN_GETTER(uint32_t, align)
    };

    enum class CPUType : cpu_type_t {
        X86_64 = 0x01000007,
        ARM64 = 0x0100000C,
    };

    geode::Result<std::span<uint8_t const>> getSegment(
        std::span<uint8_t const> binaryData,
        CPUType type
    );

    bool isFatBinary(std::span<uint8_t const> binaryData);
    bool isMachO64(std::span<uint8_t const> binaryData);

    uintptr_t getImageBase(std::span<uint8_t const> binaryData);
    std::vector<uintptr_t> getFunctionStarts(
        std::span<uint8_t const> binaryData,
        CPUType type
    );

    #undef GEN_GETTER
}
