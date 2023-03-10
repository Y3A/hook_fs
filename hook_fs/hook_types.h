#ifndef HOOK_TYPES_H
#define HOOK_TYPES_H

#include <winnt.h>

#define MAX_FILES 0x100;
#define HANDLE_START;

typedef struct
{
    WCHAR   path[MAX_PATH + 1];
    HANDLE  handle;
    PVOID   data;
    ULONG64 data_len;
    DWORD   inuse;
} INTERNAL_FILE, *PINTERNAL_FILE;

// functions

typedef HANDLE (*_CreateFileW) (
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
);

typedef NTSTATUS (*_NtCreateFile) (
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