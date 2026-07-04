/*
 * tmb_probe.c - Query local Code Integrity enforcement state
 *
 * No writes. No admin required. Pure recon.
 * Reports: CI enabled, test-signing, UMCI, debug mode, HVCI, SAC.
 *
 * Build: x86_64-w64-mingw32-gcc -o bofs/bin/tmb_probe.o -c bofs/src/tmb_probe.c -I bofs/include -Wall
 */

#include "tmb_bof.h"

#define SystemCodeIntegrityInformation 0x67

typedef struct {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} CI_INFO;

void go(char *args, int alen) {
    if (!tmb_init()) {
        TMB_ERR("Failed to resolve NT API.");
        return;
    }

    CI_INFO ci;
    ci.Length = sizeof(ci);
    ci.CodeIntegrityOptions = 0;

    NTSTATUS status = g_nt.pNtQuerySystemInformation(
        SystemCodeIntegrityInformation, &ci, sizeof(ci), NULL);

    if (status != 0) {
        TMB_NTERR("NtQuerySystemInformation", status);
        return;
    }

    ULONG f = ci.CodeIntegrityOptions;

    TMB_INFO("Code Integrity Flags: 0x%08lX", f);
    TMB_INFO("  CI Enabled:              %s", (f & 0x01) ? "YES" : "no");
    TMB_INFO("  Test-Signing:            %s", (f & 0x02) ? "YES (test certs accepted)" : "no");
    TMB_INFO("  UMCI (User-Mode CI):     %s", (f & 0x04) ? "YES" : "no");
    TMB_INFO("  Debug Mode:              %s", (f & 0x08) ? "YES" : "no");
    TMB_INFO("  Flight Signing:          %s", (f & 0x20) ? "YES" : "no");
    TMB_INFO("  HVCI (Memory Integrity): %s", (f & 0x100) ? "YES" : "no");
    TMB_INFO("  HVCI Strict:             %s", (f & 0x200) ? "YES" : "no");
    TMB_INFO("  Smart App Control:       %s", (f & 0x2000) ? "YES" : "no");
    TMB_INFO("  Audit Mode:              %s", (f & 0x800) ? "YES" : "no");
}
