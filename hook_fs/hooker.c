#include <Windows.h>
#include <stdio.h>

#include "detours.h"
#include "hooker.h"
#include "hook_types.h"

_CreateFileW  fCreateFileW;
_NtCreateFile fNtCreateFile;

INTERNAL_FILE g_files[MAX_FILES];
HANDLE        g_cur_unique_handle = HANDLE_START;

DLLEXPORT void HookerInit(void)
{
    fCreateFileW = GetProcAddress(GetModuleHandleW(L"Kernel32.dll"), "CreateFileW");
    fNtCreateFile = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile");

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach(&(PVOID&)fCreateFileW, HookedCreateFileW);
    DetourAttach(&(PVOID&)fNtCreateFile, HookedNtCreateFile);

    DetourTransactionCommit();
    return;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    return TRUE;
}