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
        g_files[i].flag_attributes = dwFlagsAndAttributes;
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
    HANDLE   res;
    NTSTATUS status = STATUS_SUCCESS;

    if (!FileHandle)
        return ERROR_INVALID_PARAMETER;

    if (ObjectAttributes->RootDirectory)
        // ObjectName is relative, just call our fake createfile
        res = HookedCreateFileW(ObjectAttributes->ObjectName->Buffer, \
            0, 0, NULL, 0, 0, NULL);

    else
        // ObjectName is absolute, assume \\?\ for global root directory
        res = HookedCreateFileW(ObjectAttributes->ObjectName->Buffer + strlen("\\\\?\\") * 2, \
            0, 0, NULL, 0, 0, NULL);

    *FileHandle = res;

    if (res == INVALID_HANDLE_VALUE) {
        switch (GetLastError())
        {
            case ERROR_INVALID_PARAMETER:
                status = STATUS_INVALID_PARAMETER;
                break;

            case ERROR_SHARING_VIOLATION:
                status = STATUS_SHARING_VIOLATION;
                break;

            default:
                status = STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }

    return status;

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
    DWORD          to_read = nNumberOfBytesToRead;
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
        offset = file->pos;

        // lpOverlapped can't be null if file is opened as overlapped
        if (file->flag_attributes & FILE_FLAG_OVERLAPPED && !lpOverlapped) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }

        // Error handling for ridiculous offsets by SetFilePointer and friends
        if (offset >= file->data_len)
            if (!lpOverlapped) {
                *lpNumberOfBytesRead = 0;
                SetLastError(NO_ERROR);
                return TRUE;
            }

        if (!lpOverlapped) {
            // Won't overflow here since offset can't reach > 32bits
            to_read = nNumberOfBytesToRead > file->data_len ? file->data_len : nNumberOfBytesToRead;
            to_read = to_read > (file->data_len - (DWORD)offset) ? (file->data_len - (DWORD)offset) : to_read;
            // No offsets and stuff, direct read
            RtlMoveMemory(lpBuffer, (PBYTE)((ULONG64)file->data + (ULONG64)offset), to_read);
            InterlockedAdd(&file->pos, to_read);
            *lpNumberOfBytesRead = to_read;
            SetLastError(NO_ERROR);
            return TRUE;
        }

        // lpOverlapped is set, do offset read
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
        SetLastError(ERROR_IO_PENDING);
        offset = lpOverlapped->OffsetHigh;
        offset = offset << 32 | lpOverlapped->Offset;

        // Out of bounds
        if (offset >= (ULONG64)file->data_len) {
            lpOverlapped->Internal = STATUS_END_OF_FILE;
            lpOverlapped->InternalHigh = 0;
            if (lpOverlapped->hEvent)
                SetEvent(lpOverlapped->hEvent);
            return FALSE;
        }

        // Handle EOF
        if ((ULONG64)offset + (ULONG64)to_read > (ULONG64)file->data_len)
            lpOverlapped->Internal = STATUS_END_OF_FILE;
        else
            lpOverlapped->Internal = STATUS_SUCCESS;

        to_read = nNumberOfBytesToRead > file->data_len ? file->data_len : nNumberOfBytesToRead;
        to_read = to_read > (file->data_len - (DWORD)offset) ? (file->data_len - (DWORD)offset) : to_read;
        RtlMoveMemory(lpBuffer, (PBYTE)((ULONG64)file->data + (ULONG64)offset), to_read);

        // Return success
        InterlockedAdd(&file->pos, to_read);

        if (lpNumberOfBytesRead)
            *lpNumberOfBytesRead = to_read;

        lpOverlapped->InternalHigh = to_read;
     
        if (lpOverlapped->hEvent)
            SetEvent(lpOverlapped->hEvent);

        // Return pending to emulate async
        return FALSE;
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
                && (file->flag_attributes & FILE_SYNCHRONOUS_IO_ALERT || file->flag_attributes & FILE_SYNCHRONOUS_IO_NONALERT)) {
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
            if (file->flag_attributes & FILE_SYNCHRONOUS_IO_ALERT || file->flag_attributes & FILE_SYNCHRONOUS_IO_NONALERT)
                // Special case again, continue position
                offset = pos;

        // Check if offset is end
        if (offset >= file->data_len) {
            IoStatusBlock->Status = STATUS_END_OF_FILE;
            if (Event)
                SetEvent(Event);
            return STATUS_END_OF_FILE;
        }

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

BOOL HookedCloseHandle(
    HANDLE hObject
)
{
    DWORD cur_max = g_cur_index;
    
    for (int i = 0; i < cur_max; i++) {
        if (hObject != g_files[i].handle)
            continue;

        // Found hooked file
        if (g_files[i].ref_count) {
            InterlockedDecrement(&g_files[i].ref_count);
            SetLastError(NO_ERROR);
            return TRUE;
        }

        // Attempting to close a handle without references
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    // Not a hooked file, forward to real API to close like mutexes and stuff
    // And CloseHandle probably don't touch disk anyways
    return fCloseHandle(hObject);
}

DWORD HookedSetFilePointer(
    HANDLE hFile,
    LONG   lDistanceToMove,
    PLONG  lpDistanceToMoveHigh,
    DWORD  dwMoveMethod
)
{
    DWORD           cur_max = g_cur_index;
    PINTERNAL_FILE  file;
    DWORD           pos;

    for (int i = 0; i < cur_max; i++) {
        if (hFile != g_files[i].handle)
            continue;

        // Found hooked file
        file = &g_files[i];
        pos = file->pos;

        if (lpDistanceToMoveHigh && *lpDistanceToMoveHigh != 0) {
            // Don't support 64 bit offsets
            SetLastError(ERROR_INVALID_PARAMETER);
            return INVALID_SET_FILE_POINTER;
        }

        // Now we can ignore high bytes
        switch (dwMoveMethod)
        {
            case FILE_BEGIN:
                pos = 0;
                break;

            case FILE_CURRENT:
                break;

            case FILE_END:
                pos = file->data_len;
                break;

            default:
                // Error
                SetLastError(ERROR_INVALID_PARAMETER);
                return INVALID_SET_FILE_POINTER;
        }

        pos = pos + lDistanceToMove;
        if (pos < 0) {
            // Negative seek
            SetLastError(ERROR_NEGATIVE_SEEK);
            return INVALID_SET_FILE_POINTER;
        }

        // Success
        file->pos = pos;
        SetLastError(NO_ERROR);
        return pos;
    }

    // Not a hooked file
    SetLastError(ERROR_FILE_NOT_FOUND);
    return INVALID_SET_FILE_POINTER;
}

BOOL HookedSetFilePointerEx(
    HANDLE         hFile,
    LARGE_INTEGER  liDistanceToMove,
    PLARGE_INTEGER lpNewFilePointer,
    DWORD          dwMoveMethod
)
{
    DWORD res;

    if (liDistanceToMove.HighPart) {
        // Again, don't support 64bit
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    res = HookedSetFilePointer(hFile, liDistanceToMove.LowPart, NULL, dwMoveMethod);
    if (res == INVALID_SET_FILE_POINTER) {
        // Error would have been set by the other function
        return FALSE;
    }

    // File pointer is also set, we just have to set output(or not)
    if (lpNewFilePointer)
        lpNewFilePointer->QuadPart = (ULONG64)res;

    return TRUE;
}

DWORD HookedGetFileAttributesW(
    LPCWSTR lpFileName
)
{
    DWORD cur_max = g_cur_index;

    for (int i = 0; i < cur_max; i++) {
        if (wcscmp(lpFileName, g_files[i].name) != 0)
            continue;

        // Found hooked file
        SetLastError(NO_ERROR);
        return g_files[i].attributes;
    }

    SetLastError(ERROR_FILE_NOT_FOUND);
    return INVALID_FILE_ATTRIBUTES;
}

BOOL HookedGetFileAttributesExW(
    LPCWSTR                lpFileName,
    GET_FILEEX_INFO_LEVELS fInfoLevelId,
    LPVOID                 lpFileInformation
)
{
    DWORD           cur_max = g_cur_index;
    PINTERNAL_FILE  file;

    if (!lpFileInformation) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    for (int i = 0; i < cur_max; i++) {
        if (wcscmp(lpFileName, g_files[i].name) != 0)
            continue;

        // Found hooked file
        file = &g_files[i];

        // Set a generic error(none) first, override later
        SetLastError(NO_ERROR);

        // Assemble output buffer
        switch (fInfoLevelId)
        {
            case GetFileExInfoStandard:
                ((LPWIN32_FILE_ATTRIBUTE_DATA)lpFileInformation)->dwFileAttributes = file->attributes;
                ((LPWIN32_FILE_ATTRIBUTE_DATA)lpFileInformation)->nFileSizeLow = file->data_len;
                // Other info like creation time shall be null
                break;

            default:
                // Invalid info level
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
        }

        return TRUE;
    }

    SetLastError(ERROR_FILE_NOT_FOUND);
    return FALSE;
}

BOOL HookedGetOverlappedResult(
    HANDLE       hFile,
    LPOVERLAPPED lpOverlapped,
    LPDWORD      lpNumberOfBytesTransferred,
    BOOL         bWait
)
{
    // Since we emulate everything as synchronous, this is easy
    DWORD cur_max = g_cur_index;

    if (!lpNumberOfBytesTransferred || !lpOverlapped) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    for (int i = 0; i < cur_max; i++) {
        if (hFile != g_files[i].handle)
            continue;

        // Found hooked, return prev stored value
        SetLastError(NO_ERROR);
        *lpNumberOfBytesTransferred = lpOverlapped->InternalHigh;

        if (lpOverlapped->Internal == STATUS_END_OF_FILE)
            SetLastError(ERROR_HANDLE_EOF);

        return TRUE;
    }

    // Not found
    SetLastError(ERROR_FILE_NOT_FOUND);
    return FALSE;
}

BOOL HookedGetOverlappedResultEx(
    HANDLE       hFile,
    LPOVERLAPPED lpOverlapped,
    LPDWORD      lpNumberOfBytesTransferred,
    DWORD        dwMilliseconds,
    BOOL         bAlertable
)
{
    // Ignore these extra args :) the program has to wait!
    return HookedGetOverlappedResult(hFile, lpOverlapped, lpNumberOfBytesTransferred, TRUE);
}