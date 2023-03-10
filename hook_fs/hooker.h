#ifndef HOOKER_H
#define HOOKER_H

#include <winternl.h>
#include "hook_types.h"

#define DLLEXPORT __declspec(dllexport)

// Exports
extern INTERNAL_FILE g_files[MAX_FILES];

DLLEXPORT void HookerInit(void);
DLLEXPORT BOOL HookerHookFile(LPCWSTR lpFileName, PVOID lpBuffer, SIZE_T cbBuffer);

// Internals
HANDLE HookedCreateFileW(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
);

NTSTATUS HookedNtCreateFile (
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
);

#endif