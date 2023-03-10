#include <Windows.h>
#include <ntstatus.h>
#include <stdio.h>

#include "hooker.h"
#include "hook_types.h"

HANDLE HookedCreateFileW(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
)
{
    for (int i = 0; i < MAX_FILES; i++) {
        if (wcscmp(g_files[i].name, lpFileName) != 0)
            continue;

        // Is a file we want to hook
        return g_files[i].handle;
    }

    // Can't touch disk!
    SetLastError(ERROR_FILE_NOT_FOUND);
    return INVALID_HANDLE_VALUE;
}

NTSTATUS HookedNtCreateFile(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength
)
{
    return STATUS_SUCCESS;
}