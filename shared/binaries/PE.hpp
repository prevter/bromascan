#pragma once

#include <cstdint>
#include <span>
#include <Geode/Result.hpp>

namespace bin::pe {
    constexpr uint16_t MZ_MAGIC = 0x5A4D; // "MZ"
    constexpr uint32_t PE_MAGIC = 0x00004550; // "PE\0\0"

    struct DOSHeader {
        uint16_t e_magic;      // "MZ"
        uint16_t e_cblp;
        uint16_t e_cp;
        uint16_t e_crlc;
        uint16_t e_cparhdr;
        uint16_t e_minalloc;
        uint16_t e_maxalloc;
        uint16_t e_ss;
        uint16_t e_sp;
        uint16_t e_csum;
        uint16_t e_ip;
        uint16_t e_cs;
        uint16_t e_lfarlc;
        uint16_t e_ovno;
        uint16_t e_res[4];
        uint16_t e_oemid;
        uint16_t e_oeminfo;
        uint16_t e_res2[10];
        uint32_t e_lfanew;     // file offset to PE header
    };

    struct FileHeader {
        uint16_t machine;
        uint16_t numberOfSections;
        uint32_t timeDateStamp;
        uint32_t pointerToSymbolTable;
        uint32_t numberOfSymbols;
        uint16_t sizeOfOptionalHeader;
        uint16_t characteristics;
    };

    struct SectionHeader {
        char name[8];
        uint32_t virtualSize;
        uint32_t virtualAddress;
        uint32_t sizeOfRawData;
        uint32_t pointerToRawData;
        uint32_t pointerToRelocations;
        uint32_t pointerToLinenumbers;
        uint16_t numberOfRelocations;
        uint16_t numberOfLinenumbers;
        uint32_t characteristics;
    };

    struct VirtualSection {
        uintptr_t virtualAddress;
        std::span<uint8_t const> data;
    };

    geode::Result<VirtualSection> getSection(std::span<uint8_t const> binaryData);
    bool isPE64(std::span<uint8_t const> binaryData);

    uintptr_t getImageBase(std::span<uint8_t const> binaryData);
}
