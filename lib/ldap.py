import ldap3
import ssl
import os
import datetime
from binascii import unhexlify


def get_dn(domain):
    """Convert domain FQDN to LDAP distinguished name format"""
    components = domain.split('.')
    base = ''
    for comp in components:
        base += f',DC={comp}'
    return base[1:]


def ldap3_kerberos_login(connection, target, user, password, domain='', lmhash='', nthash='', aesKey='', kdcHost=None, TGT=None, TGS=None, useCache=True, ccache_file=None):
    """
    Login to LDAP using Kerberos authentication. Supports ccache files via KRB5CCNAME environment variable or ccache_file parameter.
    Based on impacket's ldap3_kerberos_login implementation.
    
    :param connection: ldap3 Connection object (must be opened but not bound)
    :param target: Target server (DC hostname/FQDN)
    :param user: Username
    :param password: Password (used if no ccache/TGT available)
    :param domain: Domain name
    :param lmhash: LM hash (for pass-the-hash)
    :param nthash: NT hash (for pass-the-hash)
    :param aesKey: AES key for Kerberos (pass-the-key)
    :param kdcHost: KDC hostname/IP
    :param TGT: Pre-obtained TGT structure
    :param TGS: Pre-obtained TGS structure
    :param useCache: Whether to use ccache from KRB5CCNAME environment variable or ccache_file
    :param ccache_file: Path to ccache file (alternative to KRB5CCNAME environment variable)
    :return: True on success, raises Exception on error
    """
    from pyasn1.codec.ber import encoder, decoder
    from pyasn1.type.univ import noValue
    
    if lmhash != '' or nthash != '':
        if len(lmhash) % 2:
            lmhash = '0' + lmhash
        if len(nthash) % 2:
            nthash = '0' + nthash
        try:
            lmhash = unhexlify(lmhash)
            nthash = unhexlify(nthash)
        except TypeError:
            pass
    
    # Import impacket kerberos modules
    from impacket.krb5.ccache import CCache
    from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
    
    if TGT is not None or TGS is not None:
        useCache = False
    
    # Try to load ccache from ccache_file parameter or KRB5CCNAME environment variable
    if useCache:
        try:
            # Check ccache_file parameter first, then KRB5CCNAME environment variable
            ccache_file_path = None
            if ccache_file:
                ccache_file_path = ccache_file
            elif os.getenv('KRB5CCNAME'):
                ccache_file_path = os.getenv('KRB5CCNAME')
            
            if ccache_file_path:
                ccache = CCache.loadFile(ccache_file_path)
                if ccache is not None:
                    # Retrieve domain information from CCache if needed
                    if domain == '':
                        domain = ccache.principal.realm['data'].decode('utf-8')
                    
                    # Try to get TGS for ldap/target@domain
                    principal = 'ldap/%s@%s' % (target.upper(), domain.upper())
                    creds = ccache.getCredential(principal)
                    
                    if creds is None:
                        # Try to get TGT and request TGS
                        principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
                        creds = ccache.getCredential(principal)
                        if creds is not None:
                            TGT = creds.toTGT()
                    else:
                        TGS = creds.toTGS(principal)
                    
                    # Retrieve user information from CCache if needed (after getting creds)
                    if (user == '' or user is None) and creds is not None:
                        try:
                            user = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
                        except:
                            pass
                    
                    if (user == '' or user is None) and len(ccache.principal.components) > 0:
                        user = ccache.principal.components[0]['data'].decode('utf-8')
        except Exception:
            # No cache present or error loading, continue with normal auth
            pass
    
    # Ensure user is set and is a string
    if not user or user == '':
        raise Exception("Username is required for Kerberos authentication. Provide it via command line or ensure ccache file contains user information.")
    
    # Get TGT if not already available
    # Use int() to ensure we're passing an integer, not an enum
    userName = Principal(str(user), type=int(constants.PrincipalNameType.NT_PRINCIPAL.value))
    if TGT is None:
        if TGS is None:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash, aesKey, kdcHost)
    else:
        tgt = TGT['KDC_REP']
        cipher = TGT['cipher']
        sessionKey = TGT['sessionKey']
    
    # Get TGS for ldap/target if not already available
    if TGS is None:
        # Use int() to ensure we're passing an integer, not an enum
        serverName = Principal('ldap/%s' % target, type=int(constants.PrincipalNameType.NT_SRV_INST.value))
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey)
    else:
        tgs = TGS['KDC_REP']
        cipher = TGS['cipher']
        sessionKey = TGS['sessionKey']
    
    # Build SPNEGO NegTokenInit with Kerberos AP-REQ
    blob = SPNEGO_NegTokenInit()
    blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]
    
    # Extract ticket from TGS
    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs['ticket'])
    
    # Build AP-REQ
    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    
    opts = []
    apReq['ap-options'] = constants.encodeFlags(opts)
    seq_set(apReq, 'ticket', ticket.to_asn1)
    
    # Build authenticator
    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = domain
    seq_set(authenticator, 'cname', userName.components_to_asn1)
    now = datetime.datetime.utcnow()
    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)
    
    encodedAuthenticator = encoder.encode(authenticator)
    
    # Key Usage 11: AP-REQ Authenticator encrypted with session key
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)
    
    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator
    
    blob['MechToken'] = encoder.encode(apReq)
    
    # Perform SASL bind
    request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO', blob.getData())
    
    if connection.closed:
        connection.open(read_server_info=False)
    
    connection.sasl_in_progress = True
    response = connection.post_send_single_response(connection.send('bindRequest', request, None))
    connection.sasl_in_progress = False
    
    if response[0]['result'] != 0:
        raise Exception(f"Kerberos authentication failed: {response}")
    
    connection.bound = True
    return True


def init_ldap_connection(target, tls_version, domain, username, password, nt_hash=None, use_channel_binding=False, kerberos=False, lmhash=None, nthash=None, aesKey=None, kdcHost=None, ccache_file=None):
    """Initialize LDAP connection with NTLM or Kerberos authentication"""
    
    if tls_version is not None:
        use_ssl = True
        port = 636
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=tls_version)
    else:
        use_ssl = False
        port = 389
        tls = None
    
    ldap_server = ldap3.Server(target, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls)
    
    # Set up channel binding if requested (required for LDAPS when server has channel binding: Always)
    channel_binding = dict()
    if use_channel_binding:
        if not hasattr(ldap3, 'TLS_CHANNEL_BINDING'):
            raise Exception(
                "Channel binding is required but not available in your ldap3 library.\n"
                "Install the supported version: pip install git+https://github.com/ly4k/ldap3.git"
            )
        channel_binding = dict(channel_binding=ldap3.TLS_CHANNEL_BINDING)
        
        # Note: Kerberos + channel binding may not be fully supported yet
        if kerberos:
            raise Exception(
                "Kerberos authentication with channel binding is not fully supported yet.\n"
                "Try using regular LDAP (without --ldaps) with Kerberos, or use NTLM with LDAPS."
            )
    
    # Handle Kerberos authentication
    if kerberos:
        ldap_session = ldap3.Connection(ldap_server)
        ldap_session.bind()  # Open connection without authentication
        
        # Set KRB5CCNAME if ccache_file provided
        if ccache_file and not os.getenv('KRB5CCNAME'):
            os.environ['KRB5CCNAME'] = os.path.abspath(ccache_file)
        
        # Authenticate using Kerberos
        ldap3_kerberos_login(
            ldap_session, target, username, password, domain,
            lmhash or '', nthash or '', aesKey or '', kdcHost,
            ccache_file=ccache_file
        )
        
        return ldap_server, ldap_session
    
    # NTLM authentication (existing code)
    user = f'{domain}\\{username}' if username else None
    
    if username and password:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=password, 
                                        authentication=ldap3.NTLM, auto_bind=True, **channel_binding)
    elif username and nt_hash:
        # Use NT hash for authentication (format: lmhash:nthash)
        lmhash_empty = "aad3b435b51404eeaad3b435b51404ee"  # Empty LM hash
        ldap_session = ldap3.Connection(ldap_server, user=user, password=f"{lmhash_empty}:{nt_hash}", 
                                        authentication=ldap3.NTLM, auto_bind=True, **channel_binding)
    else:
        # Anonymous bind
        from ldap3 import ANONYMOUS
        ldap_session = ldap3.Connection(ldap_server, authentication=ANONYMOUS, auto_bind=True, **channel_binding)
    
    return ldap_server, ldap_session


def init_ldap_session(domain, username, password, dc_ip, ldaps, nt_hash=None, kerberos=False, lmhash=None, nthash=None, aesKey=None, ccache_file=None):
    """
    Initialize LDAP session with domain controller.
    
    Supports:
    - NTLM authentication (password or NT hash)
    - Kerberos authentication (via ccache file, password, hashes, or AES key)
    
    :param domain: Domain name
    :param username: Username
    :param password: Password
    :param dc_ip: DC IP or hostname
    :param ldaps: Use LDAPS (port 636)
    :param nt_hash: NT hash for NTLM pass-the-hash
    :param kerberos: Use Kerberos authentication
    :param lmhash: LM hash (for Kerberos pass-the-hash)
    :param nthash: NT hash (for Kerberos pass-the-hash)
    :param aesKey: AES key (for Kerberos pass-the-key)
    :param ccache_file: Path to ccache file (alternative to KRB5CCNAME env var)
    :return: (ldap_server, ldap_session) tuple
    """
    # For Kerberos, try to get target hostname if dc_ip is not provided
    if kerberos:
        if dc_ip:
            target = dc_ip
        else:
            target = domain
    else:
        if dc_ip:
            target = dc_ip
        else:
            target = domain
    
    if ldaps:
        # For LDAPS, automatically enable channel binding (required for servers with channel binding: Always like DC1)
        # Channel binding is backward compatible, so it works with both DC1 (Always) and DC2 (Never)
        try:
            # Try with channel binding enabled (works with both DC1 and DC2)
            return init_ldap_connection(
                target, ssl.PROTOCOL_TLSv1_2, domain, username, password, nt_hash,
                use_channel_binding=True, kerberos=kerberos, lmhash=lmhash, nthash=nthash,
                aesKey=aesKey, kdcHost=dc_ip, ccache_file=ccache_file
            )
        except Exception as e:
            error_msg = str(e)
            # If channel binding library not available, provide clear error
            if 'TLS_CHANNEL_BINDING' in error_msg or 'Channel binding' in error_msg or not hasattr(ldap3, 'TLS_CHANNEL_BINDING'):
                raise Exception(
                    f"LDAPS requires channel binding but it's not available in your ldap3 library.\n"
                    f"  Install the supported version: pip install git+https://github.com/ly4k/ldap3.git\n"
                    f"  Or use regular LDAP: remove --ldaps flag"
                )
            # If TLSv1_2 fails, try TLSv1
            try:
                return init_ldap_connection(
                    target, ssl.PROTOCOL_TLSv1, domain, username, password, nt_hash,
                    use_channel_binding=True, kerberos=kerberos, lmhash=lmhash, nthash=nthash,
                    aesKey=aesKey, kdcHost=dc_ip, ccache_file=ccache_file
                )
            except Exception as e2:
                error_msg2 = str(e2)
                error_type = type(e2).__name__
                
                if isinstance(e2, ldap3.core.exceptions.LDAPSocketOpenError) or 'SocketOpenError' in error_type:
                    raise ldap3.core.exceptions.LDAPSocketOpenError(
                        f"Failed to connect to LDAPS (port 636) on {target}.\n"
                        f"  Error: {error_msg2}\n"
                        f"  Possible causes:\n"
                        f"    - LDAPS may not be enabled/configured on this DC\n"
                        f"    - Port 636 may be blocked by firewall\n"
                        f"  Solution: Remove --ldaps flag to use regular LDAP on port 389"
                    )
                elif isinstance(e2, ldap3.core.exceptions.LDAPBindError) or 'BindError' in error_type:
                    raise
                else:
                    raise Exception(f"LDAPS connection failed: {error_msg2}") from e2
    else:
        return init_ldap_connection(
            target, None, domain, username, password, nt_hash, use_channel_binding=False,
            kerberos=kerberos, lmhash=lmhash, nthash=nthash, aesKey=aesKey,
            kdcHost=dc_ip, ccache_file=ccache_file
        )

