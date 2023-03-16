#ifndef HOOK_TYPES_H
#define HOOK_TYPES_H

#include <winnt.h>

#define MAX_FILES 0x100
#define HANDLE_START 0x82

#define FILE_USE_FILE_POINTER_POSITION 0xfffffffe

typedef struct
{
    WCHAR   name[MAX_PATH + 1];
    HANDLE  handle;
    PVOID   data;
    SIZE_T  data_len;
    DWORD   attributes;
    union {
        DWORD   flag_attributes; // CreateFileW
        DWORD   create_options;  // NtCreateFile
    };
    DWORD   pos;
    DWORD   ref_count;
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

typedef BOOL (*_ReadFile) (
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
);

typedef NTSTATUS (*_NtReadFile) (
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

typedef DWORD (*_GetFileSize) (
    HANDLE  hFile,
    LPDWORD lpFileSizeHigh
);

typedef BOOL (*_GetFileSizeEx) (
    HANDLE         hFile,
    PLARGE_INTEGER lpFileSize
);

typedef BOOL (*_CloseHandle) (
    HANDLE hObject
);

typedef DWORD (*_SetFilePointer) (
    HANDLE hFile,
    LONG   lDistanceToMove,
    PLONG  lpDistanceToMoveHigh,
    DWORD  dwMoveMethod
);

typedef BOOL (*_SetFilePointerEx) (
    HANDLE         hFile,
    LARGE_INTEGER  liDistanceToMove,
    PLARGE_INTEGER lpNewFilePointer,
    DWORD          dwMoveMethod
);

typedef DWORD (*_GetFileAttributesW) (
    LPCWSTR lpFileName
);

typedef BOOL (*_GetFileAttributesExW) (
    LPCWSTR                lpFileName,
    GET_FILEEX_INFO_LEVELS fInfoLevelId,
    LPVOID                 lpFileInformation
);

typedef BOOL (*_GetOverlappedResult) (
    HANDLE       hFile,
    LPOVERLAPPED lpOverlapped,
    LPDWORD      lpNumberOfBytesTransferred,
    BOOL         bWait
);

typedef BOOL (*_GetOverlappedResultEx) (
    HANDLE       hFile,
    LPOVERLAPPED lpOverlapped,
    LPDWORD      lpNumberOfBytesTransferred,
    DWORD        dwMilliseconds,
    BOOL         bAlertable
);

#endif