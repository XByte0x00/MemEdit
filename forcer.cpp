#include <windows.h>
#include <cstdint>
#include <cstring>
#include <winternl.h>

#ifdef _WIN32
    #define EXPORT extern "C" __declspec(dllexport)
#else
    #define EXPORT extern "C"
#endif

// NT API function pointers
typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

typedef NTSTATUS (NTAPI *pNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

// Global function pointers
static pNtWriteVirtualMemory g_NtWriteVirtualMemory = nullptr;
static pNtMapViewOfSection g_NtMapViewOfSection = nullptr;
static pNtCreateSection g_NtCreateSection = nullptr;
static pNtUnmapViewOfSection g_NtUnmapViewOfSection = nullptr;

// Shared memory structure for communication
struct ValueChangeRequest {
    uintptr_t address;
    double value;
    int value_type;  // 0=float32, 1=float64, 2=int8, etc.
    int completed;
};

// Global shared memory
static ValueChangeRequest* g_sharedMemory = nullptr;
static HANDLE g_mappingHandle = nullptr;
static HMODULE g_ntdll = nullptr;

// Auto-unload thread state
static HMODULE g_hModule = nullptr;
static volatile bool g_autoUnloadStarted = false;
static volatile bool g_requestsReceived = false;

// Forward declarations
static void StartAutoUnloadIfNeeded();

EXPORT void InitializeForcer() {
    // Load NT API functions
    g_ntdll = GetModuleHandleA("ntdll.dll");
    if (g_ntdll) {
        g_NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(g_ntdll, "NtWriteVirtualMemory");
        g_NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(g_ntdll, "NtMapViewOfSection");
        g_NtCreateSection = (pNtCreateSection)GetProcAddress(g_ntdll, "NtCreateSection");
        g_NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(g_ntdll, "NtUnmapViewOfSection");
    }
    
    // Create or open shared memory
    g_mappingHandle = CreateFileMappingA(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,
        sizeof(ValueChangeRequest) * 1000,  // Support up to 1000 changes at once
        "Global\\MemoryForcerShared"
    );
    
    if (g_mappingHandle) {
        g_sharedMemory = (ValueChangeRequest*)MapViewOfFile(
            g_mappingHandle,
            FILE_MAP_ALL_ACCESS,
            0,
            0,
            sizeof(ValueChangeRequest) * 1000
        );
    }
}

EXPORT void CleanupForcer() {
    if (g_sharedMemory) {
        UnmapViewOfFile(g_sharedMemory);
        g_sharedMemory = nullptr;
    }
    if (g_mappingHandle) {
        CloseHandle(g_mappingHandle);
        g_mappingHandle = nullptr;
    }
}

// Write method 1: Standard WriteProcessMemory
static bool TryWriteProcessMemory(uintptr_t address, void* data, size_t size) {
    try {
        HANDLE hProcess = GetCurrentProcess();
        SIZE_T written = 0;
        
        DWORD oldProtect;
        if (!VirtualProtect((LPVOID)address, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return false;
        }
        
        bool success = WriteProcessMemory(hProcess, (LPVOID)address, data, size, &written);
        VirtualProtect((LPVOID)address, size, oldProtect, &oldProtect);
        
        return success && written == size;
    } catch (...) {
        return false;
    }
}

// Write method 2: NtWriteVirtualMemory (NT API)
static bool TryNtWriteVirtualMemory(uintptr_t address, void* data, size_t size) {
    if (!g_NtWriteVirtualMemory) return false;
    
    try {
        HANDLE hProcess = GetCurrentProcess();
        SIZE_T written = 0;
        
        DWORD oldProtect;
        if (!VirtualProtect((LPVOID)address, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return false;
        }
        
        NTSTATUS status = g_NtWriteVirtualMemory(hProcess, (PVOID)address, data, size, &written);
        VirtualProtect((LPVOID)address, size, oldProtect, &oldProtect);
        
        return NT_SUCCESS(status) && written == size;
    } catch (...) {
        return false;
    }
}

// Write method 3: NtMapViewOfSection (most powerful)
static bool TryMapViewWrite(uintptr_t address, void* data, size_t size) {
    if (!g_NtCreateSection || !g_NtMapViewOfSection || !g_NtUnmapViewOfSection) {
        return false;
    }
    
    try {
        // Get system page size
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        SIZE_T pageSize = sysInfo.dwPageSize;  // Usually 4096
        
        // Round up to page size
        SIZE_T alignedSize = ((size + pageSize - 1) / pageSize) * pageSize;
        
        HANDLE hSection = NULL;
        LARGE_INTEGER sectionSize;
        sectionSize.QuadPart = alignedSize;
        
        // Create a section with page-aligned size
        NTSTATUS status = g_NtCreateSection(
            &hSection,
            SECTION_ALL_ACCESS,
            NULL,
            &sectionSize,
            PAGE_EXECUTE_READWRITE,
            SEC_COMMIT,
            NULL
        );
        
        if (!NT_SUCCESS(status)) return false;
        
        // Map into our process
        PVOID localView = NULL;
        SIZE_T viewSize = 0;  // Let system decide
        status = g_NtMapViewOfSection(
            hSection,
            GetCurrentProcess(),
            &localView,
            0,
            0,
            NULL,
            &viewSize,
            1, // ViewUnmap
            0,
            PAGE_EXECUTE_READWRITE
        );
        
        if (!NT_SUCCESS(status)) {
            CloseHandle(hSection);
            return false;
        }
        
        // Write our data to local view
        memcpy(localView, data, size);
        
        // Calculate page-aligned target address and proper protection size
        uintptr_t pageAlignedAddr = (address / pageSize) * pageSize;
        size_t offsetInPage = address - pageAlignedAddr;
        
        // Calculate aligned size that covers the entire write (including offset and cross-page)
        SIZE_T protectSize = ((offsetInPage + size + pageSize - 1) / pageSize) * pageSize;
        
        // Change protection of target memory (covering all pages needed)
        DWORD oldProtect;
        if (VirtualProtect((LPVOID)pageAlignedAddr, protectSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            // Direct memcpy since we can't reliably remap to arbitrary address
            memcpy((void*)address, data, size);
            VirtualProtect((LPVOID)pageAlignedAddr, protectSize, oldProtect, &oldProtect);
            
            g_NtUnmapViewOfSection(GetCurrentProcess(), localView);
            CloseHandle(hSection);
            return true;
        }
        
        g_NtUnmapViewOfSection(GetCurrentProcess(), localView);
        CloseHandle(hSection);
        
        return false;
    } catch (...) {
        return false;
    }
}

EXPORT int ForceChangeValue(uintptr_t address, double value, int value_type) {
    if (!address) return 0;
    
    try {
        // Determine size based on value type
        size_t size = 0;
        
        switch (value_type) {
            case 0: size = 4; break;  // float32
            case 1: size = 8; break;  // float64
            case 2:
            case 3: size = 1; break;  // int8, uint8
            case 4:
            case 5: size = 2; break;  // int16, uint16
            case 6:
            case 7: size = 4; break;  // int32, uint32
            case 8:
            case 9: size = 8; break;  // int64, uint64
            default: return 0;
        }
        
        // Prepare the data to write
        unsigned char data[8];
        
        switch (value_type) {
            case 0: {  // float32
                float val = (float)value;
                memcpy(data, &val, sizeof(float));
                break;
            }
            case 1: {  // float64
                memcpy(data, &value, sizeof(double));
                break;
            }
            case 2: {  // int8
                int8_t val = (int8_t)value;
                memcpy(data, &val, sizeof(int8_t));
                break;
            }
            case 3: {  // uint8
                uint8_t val = (uint8_t)value;
                memcpy(data, &val, sizeof(uint8_t));
                break;
            }
            case 4: {  // int16
                int16_t val = (int16_t)value;
                memcpy(data, &val, sizeof(int16_t));
                break;
            }
            case 5: {  // uint16
                uint16_t val = (uint16_t)value;
                memcpy(data, &val, sizeof(uint16_t));
                break;
            }
            case 6: {  // int32
                int32_t val = (int32_t)value;
                memcpy(data, &val, sizeof(int32_t));
                break;
            }
            case 7: {  // uint32
                uint32_t val = (uint32_t)value;
                memcpy(data, &val, sizeof(uint32_t));
                break;
            }
            case 8: {  // int64
                int64_t val = (int64_t)value;
                memcpy(data, &val, sizeof(int64_t));
                break;
            }
            case 9: {  // uint64
                uint64_t val = (uint64_t)value;
                memcpy(data, &val, sizeof(uint64_t));
                break;
            }
        }
        
        // Try multiple write methods in order
        // Method 1: Standard WriteProcessMemory
        if (TryWriteProcessMemory(address, data, size)) {
            return 1;
        }
        
        // Method 2: NtWriteVirtualMemory (NT API)
        if (TryNtWriteVirtualMemory(address, data, size)) {
            return 1;
        }
        
        // Method 3: NtMapViewOfSection (last resort)
        if (TryMapViewWrite(address, data, size)) {
            return 1;
        }
        
        // All methods failed
        return 0;
    }
    catch (...) {
        return 0;  // Failed
    }
}

EXPORT int ProcessChangeRequests() {
    if (!g_sharedMemory) return 0;
    
    int processed = 0;
    for (int i = 0; i < 1000; i++) {
        if (g_sharedMemory[i].address != 0 && g_sharedMemory[i].completed == 0) {
            g_requestsReceived = true;  // Mark that we've seen requests
            int result = ForceChangeValue(
                g_sharedMemory[i].address,
                g_sharedMemory[i].value,
                g_sharedMemory[i].value_type
            );
            g_sharedMemory[i].completed = result ? 1 : -1;
            processed++;
        }
    }
    
    // Start auto-unload monitoring after processing requests
    if (processed > 0) {
        StartAutoUnloadIfNeeded();
    }
    
    return processed;
}

// Check if all requests are completed
static bool AllRequestsCompleted() {
    if (!g_sharedMemory) return true;
    
    for (int i = 0; i < 1000; i++) {
        if (g_sharedMemory[i].address != 0 && g_sharedMemory[i].completed == 0) {
            return false;
        }
    }
    return true;
}

// Auto-unload thread
DWORD WINAPI AutoUnloadThread(LPVOID lpParam) {
    // Wait for all requests to be processed
    for (int attempts = 0; attempts < 100; attempts++) {
        Sleep(100);  // Check every 100ms
        
        if (AllRequestsCompleted()) {
            // All requests completed, cleanup and unload
            Sleep(500);  // Give a bit more time for any final operations
            CleanupForcer();
            
            // Unload the DLL
            if (g_hModule) {
                FreeLibraryAndExitThread(g_hModule, 0);
            }
            return 0;
        }
    }
    
    // Timeout after 10 seconds, unload anyway
    CleanupForcer();
    if (g_hModule) {
        FreeLibraryAndExitThread(g_hModule, 0);
    }
    return 0;
}

// Start the auto-unload monitoring (called from ProcessChangeRequests)
static void StartAutoUnloadIfNeeded() {
    if (!g_autoUnloadStarted && g_requestsReceived && g_hModule) {
        g_autoUnloadStarted = true;
        HANDLE hThread = CreateThread(NULL, 0, AutoUnloadThread, NULL, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);  // Don't need to keep the handle
        }
    }
}

// DLL Entry Point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            g_hModule = (HMODULE)hinstDLL;
            DisableThreadLibraryCalls(hinstDLL);  // Optimization
            InitializeForcer();
            // Auto-unload will start automatically after first ProcessChangeRequests call
            break;
        case DLL_PROCESS_DETACH:
            CleanupForcer();
            break;
    }
    return TRUE;
}
