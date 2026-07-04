/*
 * tmb_clean.c - Remove all TrustMeBro persistence artifacts
 *
 * Args: short scope_flags (bit0=sip, bit1=finalpolicy, bit2=all),
 *       char* custom_provider_guid (optional)
 */

#include "tmb_bof.h"

void go(char *args, int alen) {
    if (!tmb_init()) { TMB_ERR("Failed to resolve NT API."); return; }

    datap parser;
    BeaconDataParse(&parser, args, alen);
    short flags = BeaconDataShort(&parser);
    int guid_len = 0;
    char *custom_guid = BeaconDataExtract(&parser, &guid_len);

    BOOL do_sip = (flags & 1) || (flags & 4);
    BOOL do_fp  = (flags & 2) || (flags & 4);
    BOOL has_custom = (custom_guid && *custom_guid);

    if (!do_sip && !do_fp && !has_custom) {
        TMB_ERR("No scope specified. Use: --sip, --finalpolicy, --custom-provider {GUID}, or --all");
        return;
    }

    if (do_sip) {
        STR_WINTRUST(dll);
        STR_CRYPTSIPVERIFY(func);
        int count = 0;
        for (int i = 0; GUID_ALIASES[i].alias; i++) {
            wchar_t path64[256], path32[256];
            tmb_build_sip_path(FALSE, GUID_ALIASES[i].guid_str, path64);
            tmb_build_sip_path(TRUE, GUID_ALIASES[i].guid_str, path32);
            if (tmb_reg_write_sip(path64, dll, func)) count++;
            if (tmb_reg_write_sip(path32, dll, func)) count++;
        }
        TMB_OK("SIP keys restored (%d entries).", count);
    }

    if (do_fp) {
        WSTR_INIT(guid, L'{',L'0',L'0',L'A',L'A',L'C',L'5',L'6',L'B',L'-',L'C',L'D',L'4',L'4',L'-',L'1',L'1',L'd',L'0',L'-',L'8',L'C',L'C',L'2',L'-',L'0',L'0',L'C',L'0',L'4',L'F',L'C',L'2',L'9',L'5',L'E',L'E',L'}');
        wchar_t path[256];
        tmb_build_finalpolicy_path(guid, path);
        STR_WINTRUST(dll);
        STR_SOFTPUBAUTHENTICODE(func);
        if (tmb_reg_write_sip(path, dll, func)) {
            TMB_OK("FinalPolicy restored to SoftpubAuthenticode.");
        } else {
            TMB_ERR("FinalPolicy restore failed.");
        }
    }

    if (has_custom) {
        wchar_t wguid[64];
        int i = 0;
        while (custom_guid[i] && i < 63) { wguid[i] = (wchar_t)custom_guid[i]; i++; }
        wguid[i] = 0;
        wchar_t path[256];
        tmb_build_finalpolicy_path(wguid, path);
        HANDLE hk = tmb_reg_open(path, FALSE);
        if (hk) {
            NTSTATUS s = tmb_reg_delete(hk);
            g_nt.pNtClose(hk);
            if (s == 0) TMB_OK("Custom provider removed: %S", wguid);
            else TMB_NTERR("NtDeleteKey", s);
        } else {
            TMB_ERR("Custom provider key not found.");
        }
    }

    TMB_WARN("Log out and log back in for changes to take effect.");
}
