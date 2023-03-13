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
    DWORD cur_max = g_cur_index;

    if (dwFlagsAndAttributes & FILE_FLAG_OVERLAPPED) {
        // Don't support async IO as of now
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    for (int i = 0; i < cur_max; i++) {
        if (wcscmp(g_files[i].name, lpFileName) != 0)
            continue;

        // Is a file we want to hook
        // Currently don't support opening the same file twice without closing
        if (g_files[i].ref_count >= 1) {
            SetLastError(ERROR_SHARING_VIOLATION);
            return INVALID_HANDLE_VALUE;
        }

        SetLastError(NO_ERROR);
        g_files[i].attributes = dwFlagsAndAttributes;
        InterlockedIncrement(&g_files[i].ref_count);

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
    if (ObjectAttributes->RootDirectory) {
        // ObjectName is relative, just call our fake createfile
        return HookedCreateFileW(
            ObjectAttributes->ObjectName->Buffer, 0, 0, NULL, 0, 0, NULL
        ) ? STATUS_SUCCESS : STATUS_OBJECT_NAME_INVALID;
    }
    else {
        // ObjectName is absolute, assume \\?\ for global root directory
        return HookedCreateFileW(
            ObjectAttributes->ObjectName->Buffer + strlen("\\\\?\\") * 2, 0, 0, NULL, 0, 0, NULL
        ) ? STATUS_SUCCESS : STATUS_OBJECT_NAME_INVALID;
    }
}

BOOL HookedReadFile(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
)
{
    DWORD          cur_max = g_cur_index;
    DWORD          to_read = 0;
    PINTERNAL_FILE file;
    ULONG64        offset = 0;

    if (!lpNumberOfBytesRead && !lpOverlapped) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    // Conform to MSDN
    if (lpNumberOfBytesRead)
        *lpNumberOfBytesRead = 0;

    for (int i = 0; i < cur_max; i++) {
        if (hFile != g_files[i].handle)
            continue;

        // Hooked file, return from buffer
        file = &g_files[i];
        to_read = nNumberOfBytesToRead > file->data_len ? file->data_len : nNumberOfBytesToRead;
        
        if (!lpOverlapped) {
            // No offsets and stuff, direct read
            RtlMoveMemory(lpBuffer, file->data, to_read);
            *lpNumberOfBytesRead = to_read;
            SetLastError(NO_ERROR);
            return TRUE;
        }

        // Read from offset
        lpOverlapped->Internal = STATUS_PENDING;
        
        if (lpOverlapped->hEvent)
            // Set event to non-signalled
            if (!ResetEvent(lpOverlapped->hEvent)) {
                SetLastError(ERROR_INVALID_PARAMETER);
                lpOverlapped->Internal = STATUS_INVALID_PARAMETER;
                lpOverlapped->InternalHigh = 0;
                return FALSE;
            }

        // Begin IO
        offset = lpOverlapped->OffsetHigh;
        offset = offset << 32 | lpOverlapped->Offset;

        if (offset > (ULONG64)file->data_len) {
            SetLastError(ERROR_HANDLE_EOF);
            lpOverlapped->Internal = STATUS_END_OF_FILE;
            lpOverlapped->InternalHigh = 0;
            return FALSE;
        }

        // Won't overflow here since offset can't reach > 32bits
        to_read = to_read > (file->data_len - (DWORD)offset) ? (file->data_len - (DWORD)offset) : to_read;
        RtlMoveMemory(lpBuffer, (PBYTE)((ULONG64)file->data + (ULONG64)offset), to_read);

        // Return success
        if (lpNumberOfBytesRead)
            *lpNumberOfBytesRead = to_read;

        lpOverlapped->Internal = STATUS_SUCCESS;
        lpOverlapped->InternalHigh = to_read;
     
        if (lpOverlapped->hEvent)
            SetEvent(lpOverlapped->hEvent);

        SetLastError(NO_ERROR);
        return TRUE;
    }

    SetLastError(ERROR_FILE_NOT_FOUND);
    return FALSE;
}

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
)
{
    DWORD             cur_max = g_cur_index;
    DWORD             to_read;
    PINTERNAL_FILE    file;
    ULONG64           offset = 0;
    DWORD             pos;

    for (int i = 0; i < cur_max; i++) {
        if (FileHandle != g_files[i].handle)
            continue;

        // Found hooked handle
        file = &g_files[i];
        to_read = Length > file->data_len ? file->data_len : Length;
        pos = file->pos;

        // Begin IO
        IoStatusBlock->Status = STATUS_PENDING;
        IoStatusBlock->Information = 0;
        
        if (ByteOffset) {
            if (ByteOffset->HighPart == -1 && ByteOffset->LowPart == FILE_USE_FILE_POINTER_POSITION \
                && (file->attributes & FILE_SYNCHRONOUS_IO_ALERT || file->attributes & FILE_SYNCHRONOUS_IO_NONALERT)) {
                // Special case, read from current pos
                offset = pos;
            }
            else if ((ULONG64)ByteOffset->QuadPart > (ULONG64)file->data_len) {
                // Surely off limits
                IoStatusBlock->Status = STATUS_END_OF_FILE;
                if (Event)
                    SetEvent(Event);
                return STATUS_END_OF_FILE;
            }
            else {
                // Else set offset
                offset = (ULONG64)ByteOffset->QuadPart;
                // Also set pos
                file->pos = offset;
            }
        }
        else
            if (file->attributes & FILE_SYNCHRONOUS_IO_ALERT || file->attributes & FILE_SYNCHRONOUS_IO_NONALERT)
                // Special case again, continue position
                offset = pos;

        // Read with buffer
        // Won't overflow here since offset can't reach > 32bits
        to_read = to_read > (file->data_len - (DWORD)offset) ? (file->data_len - (DWORD)offset) : to_read;
        RtlMoveMemory(Buffer, (PBYTE)((ULONG64)file->data + (ULONG64)offset), to_read);

        // Return success and update pos
        IoStatusBlock->Status = STATUS_SUCCESS;
        IoStatusBlock->Information = to_read;
        // Still double-fetchable but it's fine...
        InterlockedAdd(&(file->pos), to_read);
        if (Event)
            SetEvent(Event);
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

DWORD HookedGetFileSize(
    HANDLE  hFile,
    LPDWORD lpFileSizeHigh
)
{
    DWORD cur_max = g_cur_index;

    // Not gonna deal with large files
    if (lpFileSizeHigh)
        *lpFileSizeHigh = 0;

    for (int i = 0; i < cur_max; i++) {
        if (hFile != g_files[i].handle)
            continue;

        // Return file size
        SetLastError(NO_ERROR);
        return g_files[i].data_len;
    }

    // Not found
    SetLastError(ERROR_FILE_NOT_FOUND);
    return INVALID_FILE_SIZE;
}

BOOL HookedGetFileSizeEx(
    HANDLE         hFile,
    PLARGE_INTEGER lpFileSize
)
{
    DWORD cur_max = g_cur_index;

    if (!lpFileSize) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    for (int i = 0; i < cur_max; i++) {
        if (hFile != g_files[i].handle)
            continue;

        // Set largeint to 64bit file size
        SetLastError(NO_ERROR);
        lpFileSize->QuadPart = (ULONG64)g_files[i].data_len;

        return TRUE;
    }

    // Not found
    SetLastError(ERROR_FILE_NOT_FOUND);
    return FALSE;
}