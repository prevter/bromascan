#include "PE.hpp"
#include <fmt/format.h>

namespace bin::pe {
    geode::Result<VirtualSection> getSection(std::span<uint8_t const> binaryData) {
        // test: print all section names
        if (binaryData.size() < sizeof(DOSHeader)) {
            return geode::Err("Invalid PE file: too small for DOS header");
        }

        auto* dosHeader = reinterpret_cast<DOSHeader const*>(binaryData.data());
        if (dosHeader->e_magic != MZ_MAGIC) {
            return geode::Err("Invalid PE file: missing MZ magic");
        }

        if (dosHeader->e_lfanew + sizeof(uint32_t) + sizeof(FileHeader) > binaryData.size()) {
            return geode::Err("Invalid PE file: too small for PE header");
        }

        uint32_t peSig = *reinterpret_cast<uint32_t const*>(binaryData.data() + dosHeader->e_lfanew);
        if (peSig != PE_MAGIC) {
            return geode::Err("Invalid PE file: missing PE signature");
        }

        auto* fileHeader = reinterpret_cast<FileHeader const*>(binaryData.data() + dosHeader->e_lfanew + sizeof(uint32_t));
        size_t sectionHeadersOffset = dosHeader->e_lfanew + sizeof(uint32_t) + sizeof(FileHeader) + fileHeader->sizeOfOptionalHeader;
        size_t sectionHeadersSize = fileHeader->numberOfSections * sizeof(SectionHeader);
        if (sectionHeadersOffset + sectionHeadersSize > binaryData.size()) {
            return geode::Err("Invalid PE file: too small for section headers");
        }

        // return the .text section
        auto* sectionHeaders = reinterpret_cast<SectionHeader const*>(binaryData.data() + sectionHeadersOffset);
        for (uint16_t i = 0; i < fileHeader->numberOfSections; ++i) {
            if (std::string_view(sectionHeaders[i].name, 8).starts_with(".text")) {
                size_t offset = sectionHeaders[i].pointerToRawData;
                size_t size = sectionHeaders[i].sizeOfRawData;
                if (offset + size > binaryData.size()) {
                    return geode::Err("Invalid PE file: .text section out of bounds");
                }
                return geode::Ok(VirtualSection{
                    sectionHeaders[i].virtualAddress,
                    binaryData.subspan(offset, size)
                });
            }
        }

        return geode::Err("PE file has no .text section");
    }

    bool isPE64(std::span<uint8_t const> binaryData) {
        if (binaryData.size() < sizeof(DOSHeader)) {
            return false;
        }

        auto* dosHeader = reinterpret_cast<DOSHeader const*>(binaryData.data());
        if (dosHeader->e_magic != MZ_MAGIC) {
            return false;
        }

        if (dosHeader->e_lfanew + sizeof(uint32_t) > binaryData.size()) {
            return false;
        }

        uint32_t peSig = *reinterpret_cast<uint32_t const*>(binaryData.data() + dosHeader->e_lfanew);
        return peSig == PE_MAGIC;
    }

    uintptr_t getImageBase(std::span<uint8_t const> binaryData) {
        if (binaryData.size() < sizeof(DOSHeader)) return 0;
        auto* dosHeader = reinterpret_cast<DOSHeader const*>(binaryData.data());
        if (dosHeader->e_magic != MZ_MAGIC) return 0;

        size_t peOffset = dosHeader->e_lfanew;
        if (peOffset + sizeof(uint32_t) + sizeof(FileHeader) > binaryData.size()) return 0;

        uint32_t peSig = *reinterpret_cast<uint32_t const*>(binaryData.data() + peOffset);
        if (peSig != PE_MAGIC) return 0;

        size_t optHeaderOffset = peOffset + sizeof(uint32_t) + sizeof(FileHeader);
        if (optHeaderOffset + 24 + sizeof(uint64_t) > binaryData.size()) return 0;

        uint16_t optMagic = *reinterpret_cast<uint16_t const*>(binaryData.data() + optHeaderOffset);
        if (optMagic == 0x20B) { // PE32+
            return *reinterpret_cast<uint64_t const*>(binaryData.data() + optHeaderOffset + 24);
        }
        if (optMagic == 0x10B) { // PE32
            return *reinterpret_cast<uint32_t const*>(binaryData.data() + optHeaderOffset + 28);
        }
        return 0;
    }
}
