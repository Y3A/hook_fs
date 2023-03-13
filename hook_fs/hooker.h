#ifndef HOOKER_H
#define HOOKER_H

#include <winternl.h>
#include "hook_types.h"

#define DLLEXPORT __declspec(dllexport)

// Exports
extern INTERNAL_FILE g_files[MAX_FILES];
extern DWORD         g_cur_index;

DLLEXPORT void HookerInit(void);
DLLEXPORT BOOL HookerHookFile(LPCWSTR lpFileName, PVOID lpBuffer, SIZE_T cbBuffer);
DLLEXPORT BOOL HookerUpdateBufLen(HANDLE hFile, SIZE_T cbBuffer);

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

BOOL HookedReadFile (
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
);

NTSTATUS HookedNtReadFile(
    HANDLE           FileHandle,
    HANDLE           Event,
    PIO_APC_ROUTINE  ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            Buffer,
    ULONG            Length,
    PLARGE_INTEGER   ByteOffset,
    PULONG           Key
);

DWORD HookedGetFileSize (
    HANDLE  hFile,
    LPDWORD lpFileSizeHigh
);

BOOL HookedGetFileSizeEx (
    HANDLE         hFile,
    PLARGE_INTEGER lpFileSize
);

#endif