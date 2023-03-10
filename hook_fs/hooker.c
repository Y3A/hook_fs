#include <Windows.h>
#include <stdio.h>

#include "detours.h"
#include "hooker.h"
#include "hook_types.h"

_CreateFileW  fCreateFileW;
_NtCreateFile fNtCreateFile;

INTERNAL_FILE g_files[MAX_FILES];
HANDLE        g_cur_unique_handle = HANDLE_START;
DWORD         g_cur_index;

DLLEXPORT void HookerInit(void)
{
    // Load desired functions
    fCreateFileW = GetProcAddress(GetModuleHandleW(L"Kernel32.dll"), "CreateFileW");
    fNtCreateFile = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile");

    // Use detours to hook em
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach(&(PVOID&)fCreateFileW, HookedCreateFileW);
    DetourAttach(&(PVOID&)fNtCreateFile, HookedNtCreateFile);

    DetourTransactionCommit();
    return;
}

DLLEXPORT BOOL HookerHookFile(LPCWSTR lpFileName, PVOID lpBuffer, SIZE_T cbBuffer)
{
    HANDLE          assignable_handle = g_cur_unique_handle;
    DWORD           free_slot = g_cur_index;
    PINTERNAL_FILE  file = &g_files[free_slot];

    // Validate globals
    if (free_slot >= MAX_FILES)
        return FALSE;

    // Set relavent fields of our own file structure and manage globals
    InterlockedIncrement(&g_cur_unique_handle);
    InterlockedIncrement(&g_cur_index);

    wcscpy_s(file->name, MAX_PATH, lpFileName);
    file->handle = assignable_handle;
    file->data = lpBuffer;
    file->data_len = cbBuffer;

    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    return TRUE;
}