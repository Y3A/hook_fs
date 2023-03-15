#include <Windows.h>
#include <stdio.h>

#include "detours.h"
#include "hooker.h"
#include "hook_types.h"

_CreateFileW             fCreateFileW;
_NtCreateFile            fNtCreateFile;
_ReadFile                fReadFile;
_NtReadFile              fNtReadFile;
_GetFileSize             fGetFileSize;
_GetFileSizeEx           fGetFileSizeEx;
_CloseHandle             fCloseHandle;
_SetFilePointer          fSetFilePointer;
_SetFilePointerEx        fSetFilePointerEx;
_GetFileAttributesW      fGetFileAttributesW;
_GetFileAttributesExW    fGetFileAttributesExW;
_GetOverlappedResult     fGetOverlappedResult;
_GetOverlappedResultEx   fGetOverlappedResultEx;

INTERNAL_FILE g_files[MAX_FILES];
HANDLE        g_cur_unique_handle = HANDLE_START;
DWORD         g_cur_index;

DLLEXPORT void HookerInit(void)
{
    // Load desired functions
    fCreateFileW = GetProcAddress(GetModuleHandleW(L"KernelBase.dll"), "CreateFileW");
    fNtCreateFile = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile");
    fReadFile = GetProcAddress(GetModuleHandleW(L"KernelBase.dll"), "ReadFile");
    fNtReadFile = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtReadFile");
    fGetFileSize = GetProcAddress(GetModuleHandleW(L"KernelBase.dll"), "GetFileSize");
    fGetFileSizeEx = GetProcAddress(GetModuleHandleW(L"KernelBase.dll"), "GetFileSizeEx");
    fCloseHandle = GetProcAddress(GetModuleHandleW(L"KernelBase.dll"), "CloseHandle");
    fSetFilePointer = GetProcAddress(GetModuleHandleW(L"KernelBase.dll"), "SetFilePointer");
    fSetFilePointerEx = GetProcAddress(GetModuleHandleW(L"KernelBase.dll"), "SetFilePointerEx");
    fGetFileAttributesW = GetProcAddress(GetModuleHandleW(L"KernelBase.dll"), "GetFileAttributesW");
    fGetFileAttributesExW = GetProcAddress(GetModuleHandleW(L"KernelBase.dll"), "GetFileAttributesExW");
    fGetOverlappedResult = GetProcAddress(GetModuleHandleW(L"KernelBase.dll"), "GetOverlappedResult");
    fGetOverlappedResultEx = GetProcAddress(GetModuleHandleW(L"KernelBase.dll"), "GetOverlappedResultEx");

    // Use detours to hook em
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach((PVOID)&fCreateFileW, HookedCreateFileW);
    DetourAttach((PVOID)&fNtCreateFile, HookedNtCreateFile);
    DetourAttach((PVOID)&fReadFile, HookedReadFile);
    DetourAttach((PVOID)&fNtReadFile, HookedNtReadFile);
    DetourAttach((PVOID)&fGetFileSize, HookedGetFileSize);
    DetourAttach((PVOID)&fGetFileSizeEx, HookedGetFileSizeEx);
    DetourAttach((PVOID)&fCloseHandle, HookedCloseHandle);
    DetourAttach((PVOID)&fSetFilePointer, HookedSetFilePointer);
    DetourAttach((PVOID)&fSetFilePointerEx, HookedSetFilePointerEx);
    DetourAttach((PVOID)&fGetFileAttributesW, HookedGetFileAttributesW);
    DetourAttach((PVOID)&fGetFileAttributesExW, HookedGetFileAttributesExW);
    DetourAttach((PVOID)&fGetOverlappedResult, HookedGetOverlappedResult);
    DetourAttach((PVOID)&fGetOverlappedResultEx, HookedGetOverlappedResultEx);

    DetourTransactionCommit();
    return;
}

DLLEXPORT BOOL HookerHookFile(LPCWSTR lpFileName, PVOID lpBuffer, SIZE_T cbBuffer, DWORD dwAttributes)
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
    file->attributes = dwAttributes;

    return TRUE;
}

DLLEXPORT BOOL HookerUpdateBufLen(HANDLE hFile, SIZE_T cbBuffer)
{
    DWORD cur_max = g_cur_index;

    for (int i = 0; i < cur_max; i++) {
        if (hFile != g_files[i].handle)
            continue;

        // Update buffer length(harness does this for fuzzer)
        g_files[i].data_len = cbBuffer;
        return TRUE;
    }

    return FALSE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    return TRUE;
}