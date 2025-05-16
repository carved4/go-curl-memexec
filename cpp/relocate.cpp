#include <windows.h>
#include <winnt.h>
#include <stdio.h>
#include <stdint.h>

// Logging macro for error reporting
#define LOG_ERROR(fmt, ...) fprintf(stderr, "[!] " fmt "\n", ##__VA_ARGS__)

// Page size for Windows (4KB)
#define PAGE_SIZE 4096
    
// Get the PE data directory
static IMAGE_DATA_DIRECTORY* getPeDir(void* modulePtr, DWORD directoryEntry) {
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)modulePtr;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)modulePtr + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

    if (directoryEntry >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;
    return &ntHeaders->OptionalHeader.DataDirectory[directoryEntry];
}

// process relocations for a single page
static bool processRelocEntry(
    BYTE* modulePtr,
    SIZE_T moduleSize,
    DWORD page,
    WORD type,
    WORD offset,
    uint64_t oldBase,
    uint64_t newBase
) {
    SIZE_T relocRva = page + offset;
    SIZE_T relocSize = (type == IMAGE_REL_BASED_DIR64) ? sizeof(uint64_t) : sizeof(DWORD);

    // Validate bounds
    if (relocRva + relocSize > moduleSize) {
        LOG_ERROR("Relocation out of bounds at RVA 0x%zx", relocRva);
        return false;
    }

    BYTE* relocAddr = modulePtr + relocRva;

    bool success = true;
    switch (type) {
        case IMAGE_REL_BASED_HIGHLOW:
            // 32-bit relocation
            if (oldBase > UINT32_MAX || newBase > UINT32_MAX) {
                LOG_ERROR("Base address too large for 32-bit relocation at RVA 0x%zx", relocRva);
                success = false;
            } else {
                DWORD* addr = (DWORD*)relocAddr;
                *addr = (*addr - (DWORD)oldBase + (DWORD)newBase);
            }
            break;
        case IMAGE_REL_BASED_DIR64:
            // 64-bit relocation
            {
                uint64_t* addr = (uint64_t*)relocAddr;
                *addr = (*addr - oldBase + newBase);
            }
            break;
        default:
            LOG_ERROR("Unsupported relocation type %d at RVA 0x%zx", type, relocRva);
            success = false;
            break;
    }

    return success;
}

// Apply base relocations to a PE module
bool applyReloc(uint64_t newBase, uint64_t oldBase, void* modulePtr, SIZE_T moduleSize) {
    // validate inputs
    if (!modulePtr || moduleSize < sizeof(IMAGE_DOS_HEADER)) {
        LOG_ERROR("Invalid module pointer or size");
        return false;
    }
    if (newBase & 0xFFF || oldBase & 0xFFF) {
        LOG_ERROR("Base addresses must be page-aligned");
        return false;
    }

    // validate pe headers
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)modulePtr;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        LOG_ERROR("Invalid DOS signature");
        return false;
    }

    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)modulePtr + dosHeader->e_lfanew);
    if ((BYTE*)ntHeaders + sizeof(IMAGE_NT_HEADERS) > (BYTE*)modulePtr + moduleSize ||
        ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        LOG_ERROR("Invalid PE signature or NT headers out of bounds");
        return false;
    }

    // get relocation directory
    IMAGE_DATA_DIRECTORY* relocDir = getPeDir(modulePtr, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (!relocDir || relocDir->VirtualAddress == 0 || relocDir->Size == 0) {
        LOG_ERROR("No relocation directory found");
        return true; // No relocations to apply, not an error
    }

    // Validate relocation directory bounds
    if (relocDir->VirtualAddress + relocDir->Size > moduleSize) {
        LOG_ERROR("Relocation directory out of module bounds");
        return false;
    }

    BYTE* relocBase = (BYTE*)modulePtr + relocDir->VirtualAddress;
    SIZE_T parsedSize = 0;
    SIZE_T maxSize = relocDir->Size;

    // process relocation blocks
    while (parsedSize < maxSize) {
        IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)(relocBase + parsedSize);
        if (reloc->SizeOfBlock == 0) break;

        // validate block size
        if (parsedSize + reloc->SizeOfBlock > maxSize) {
            LOG_ERROR("Invalid relocation block size at offset 0x%zx", parsedSize);
            return false;
        }

        DWORD page = reloc->VirtualAddress;
        int entries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entry = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));

        // calculate page boundaries for this block
        SIZE_T pageStartRva = page & ~(PAGE_SIZE - 1); // align to page start
        SIZE_T maxOffset = 0;
        for (int i = 0; i < entries; i++) {
            WORD offset = entry[i] & 0x0FFF;
            if (offset > maxOffset) maxOffset = offset;
        }
        SIZE_T pageEndRva = page + maxOffset + sizeof(uint64_t); // Conservatively include max relocation size
        SIZE_T protectSize = ((pageEndRva + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)) - pageStartRva;
        BYTE* pageStartAddr = (BYTE*)modulePtr + pageStartRva;

        // skip empty blocks
        if (entries == 0) {
            parsedSize += reloc->SizeOfBlock;
            continue;
        }

        // protect the entire page range for this block
        DWORD oldProtect;
        if (!VirtualProtect(pageStartAddr, protectSize, PAGE_READWRITE, &oldProtect)) {
            LOG_ERROR("Failed to change memory protection for page at RVA 0x%zx", pageStartRva);
            return false;
        }

        // process relocation entries
        for (int i = 0; i < entries; i++) {
            WORD typeOffset = entry[i];
            WORD type = typeOffset >> 12;
            WORD offset = typeOffset & 0x0FFF;

            // skip absolute relocations early
            if (type == IMAGE_REL_BASED_ABSOLUTE) continue;

            if (!processRelocEntry(static_cast<BYTE*>(modulePtr), moduleSize, page, type, offset, oldBase, newBase)) {
                VirtualProtect(pageStartAddr, protectSize, oldProtect, &oldProtect);
                return false;
            }
        }

        // restore original protection
        VirtualProtect(pageStartAddr, protectSize, oldProtect, &oldProtect);

        parsedSize += reloc->SizeOfBlock;
    }

    return true;
}