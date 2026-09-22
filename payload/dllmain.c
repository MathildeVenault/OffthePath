#include <Windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        MessageBoxW(NULL,
                   L"KBGD hijack successful!\n\nGetSystemDirectory() was redirected.",
                   L"OffthePath",
                   MB_OK | MB_ICONINFORMATION);
    }
    return TRUE;
}
