#pragma once
#ifndef KBGD_H
#define KBGD_H

#include <Windows.h>

// KBGD system directory pointer is at offset +32 in the structure
#define KBGD_SYSTEM_DIRECTORY_OFFSET 32

// Function pointer type for KernelBaseGetGlobalData export
typedef PVOID(__fastcall* LPFN_KernelBaseGetGlobalData)(VOID);

// Returns address of KernelBaseGlobalData structure
// This address is valid across all processes in the session (shared section)
PVOID ResolveKBGD(void);

// Performs the KBGD hijacking attack
// Returns TRUE on success, FALSE on failure
BOOL PatchKBGD(DWORD targetPid, const WCHAR* fakePath);

#endif // KBGD_H
