"""
trustkit.core.kerberos
~~~~~~~~~~~~~~~~~~~~~~
Kerberos AS-REQ / TGS-REQ wire protocol using pyasn1.

Implements just enough to:
  - Request a TGT (AS-REQ)
  - Request a TGS (TGS-REQ)
  - Decode AS-REP / TGS-REP
  - Decode EncTicketPart

No impacket dependency.
"""

import os
import socket
import struct
import datetime
from binascii import unhexlify

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ, namedtype, tag, constraint, useful
from pyasn1.type.univ import noValue

from .crypto import get_cipher, RC4HMAC, AES256SHA196

# ---------------------------------------------------------------------------
# ASN.1 Kerberos types (RFC 4120)
# ---------------------------------------------------------------------------

# Application tags
APP = lambda n: tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, n)
CTX = lambda n: tag.Tag(tag.tagClassContext, tag.tagFormatSimple, n)
CTX_C = lambda n: tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, n)


class KerberosString(univ.OctetString):
    pass


class Realm(KerberosString):
    pass


class PrincipalName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('name-type',   univ.Integer().subtype(implicitTag=CTX(0))),
        namedtype.NamedType('name-string', univ.SequenceOf(componentType=KerberosString()).subtype(implicitTag=CTX_C(1))),
    )


class KerberosTime(useful.GeneralizedTime):
    pass


class HostAddress(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('addr-type', univ.Integer().subtype(implicitTag=CTX(0))),
        namedtype.NamedType('address',   univ.OctetString().subtype(implicitTag=CTX(1))),
    )


class EncryptedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('etype',  univ.Integer().subtype(implicitTag=CTX(0))),
        namedtype.OptionalNamedType('kvno', univ.Integer().subtype(implicitTag=CTX(1))),
        namedtype.NamedType('cipher', univ.OctetString().subtype(implicitTag=CTX(2))),
    )


class Ticket(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(APP(1))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tkt-vno',  univ.Integer().subtype(implicitTag=CTX(0))),
        namedtype.NamedType('realm',    Realm().subtype(implicitTag=CTX(1))),
        namedtype.NamedType('sname',    PrincipalName().subtype(implicitTag=CTX_C(2))),
        namedtype.NamedType('enc-part', EncryptedData().subtype(implicitTag=CTX_C(3))),
    )


class AuthorizationDataEntry(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('ad-type', univ.Integer().subtype(implicitTag=CTX(0))),
        namedtype.NamedType('ad-data', univ.OctetString().subtype(implicitTag=CTX(1))),
    )


class AuthorizationData(univ.SequenceOf):
    componentType = AuthorizationDataEntry()


class ADIfRelevant(AuthorizationData):
    pass


class EncTicketPart(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(APP(3))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('flags',              univ.BitString().subtype(implicitTag=CTX(0))),
        namedtype.NamedType('key',                EncryptedData().subtype(implicitTag=CTX_C(1))),
        namedtype.NamedType('crealm',             Realm().subtype(implicitTag=CTX(2))),
        namedtype.NamedType('cname',              PrincipalName().subtype(implicitTag=CTX_C(3))),
        namedtype.NamedType('transited',          univ.Sequence().subtype(implicitTag=CTX_C(4))),
        namedtype.NamedType('authtime',           KerberosTime().subtype(implicitTag=CTX(5))),
        namedtype.OptionalNamedType('starttime',  KerberosTime().subtype(implicitTag=CTX(6))),
        namedtype.NamedType('endtime',            KerberosTime().subtype(implicitTag=CTX(7))),
        namedtype.OptionalNamedType('renew-till', KerberosTime().subtype(implicitTag=CTX(8))),
        namedtype.OptionalNamedType('caddr',      univ.SequenceOf(componentType=HostAddress()).subtype(implicitTag=CTX_C(9))),
        namedtype.OptionalNamedType('authorization-data', AuthorizationData().subtype(implicitTag=CTX_C(10))),
    )


class PADATA(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('padata-type',  univ.Integer().subtype(implicitTag=CTX(1))),
        namedtype.NamedType('padata-value', univ.OctetString().subtype(implicitTag=CTX(2))),
    )


class PADATASequence(univ.SequenceOf):
    componentType = PADATA()


class KDCReqBody(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('kdc-options',   univ.BitString().subtype(implicitTag=CTX(0))),
        namedtype.OptionalNamedType('cname', PrincipalName().subtype(implicitTag=CTX_C(1))),
        namedtype.NamedType('realm',         Realm().subtype(implicitTag=CTX(2))),
        namedtype.OptionalNamedType('sname', PrincipalName().subtype(implicitTag=CTX_C(3))),
        namedtype.OptionalNamedType('from',  KerberosTime().subtype(implicitTag=CTX(4))),
        namedtype.NamedType('till',          KerberosTime().subtype(implicitTag=CTX(5))),
        namedtype.OptionalNamedType('rtime', KerberosTime().subtype(implicitTag=CTX(6))),
        namedtype.NamedType('nonce',         univ.Integer().subtype(implicitTag=CTX(7))),
        namedtype.NamedType('etype',         univ.SequenceOf(componentType=univ.Integer()).subtype(implicitTag=CTX_C(8))),
        namedtype.OptionalNamedType('addresses', univ.SequenceOf(componentType=HostAddress()).subtype(implicitTag=CTX_C(9))),
        namedtype.OptionalNamedType('enc-authorization-data', EncryptedData().subtype(implicitTag=CTX_C(10))),
        namedtype.OptionalNamedType('additional-tickets', univ.SequenceOf(componentType=Ticket()).subtype(implicitTag=CTX_C(11))),
    )


class ASReq(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(APP(10))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('pvno',    univ.Integer().subtype(implicitTag=CTX(1))),
        namedtype.NamedType('msg-type', univ.Integer().subtype(implicitTag=CTX(2))),
        namedtype.OptionalNamedType('padata', PADATASequence().subtype(implicitTag=CTX_C(3))),
        namedtype.NamedType('req-body', KDCReqBody().subtype(implicitTag=CTX_C(4))),
    )


class TGSReq(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(APP(12))
    componentType = ASReq.componentType


class KDCRep(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('pvno',      univ.Integer().subtype(implicitTag=CTX(0))),
        namedtype.NamedType('msg-type',  univ.Integer().subtype(implicitTag=CTX(1))),
        namedtype.OptionalNamedType('padata', PADATASequence().subtype(implicitTag=CTX_C(2))),
        namedtype.NamedType('crealm',    Realm().subtype(implicitTag=CTX(3))),
        namedtype.NamedType('cname',     PrincipalName().subtype(implicitTag=CTX_C(4))),
        namedtype.NamedType('ticket',    Ticket().subtype(implicitTag=CTX_C(5))),
        namedtype.NamedType('enc-part',  EncryptedData().subtype(implicitTag=CTX_C(6))),
    )


class ASRep(KDCRep):
    tagSet = KDCRep.tagSet.tagImplicitly(APP(11))


class TGSRep(KDCRep):
    tagSet = KDCRep.tagSet.tagImplicitly(APP(13))


class KRBError(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(APP(30))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('pvno',       univ.Integer().subtype(implicitTag=CTX(0))),
        namedtype.NamedType('msg-type',   univ.Integer().subtype(implicitTag=CTX(1))),
        namedtype.OptionalNamedType('ctime',  KerberosTime().subtype(implicitTag=CTX(2))),
        namedtype.OptionalNamedType('cusec',  univ.Integer().subtype(implicitTag=CTX(3))),
        namedtype.NamedType('stime',      KerberosTime().subtype(implicitTag=CTX(4))),
        namedtype.NamedType('susec',      univ.Integer().subtype(implicitTag=CTX(5))),
        namedtype.NamedType('error-code', univ.Integer().subtype(implicitTag=CTX(6))),
        namedtype.OptionalNamedType('crealm',  Realm().subtype(implicitTag=CTX(7))),
        namedtype.OptionalNamedType('cname',   PrincipalName().subtype(implicitTag=CTX_C(8))),
        namedtype.NamedType('realm',      Realm().subtype(implicitTag=CTX(9))),
        namedtype.NamedType('sname',      PrincipalName().subtype(implicitTag=CTX_C(10))),
        namedtype.OptionalNamedType('e-text',  univ.OctetString().subtype(implicitTag=CTX(11))),
        namedtype.OptionalNamedType('e-data',  univ.OctetString().subtype(implicitTag=CTX(12))),
    )


# ---------------------------------------------------------------------------
# Kerberos error codes
# ---------------------------------------------------------------------------
KDC_ERR_NONE              = 0
KDC_ERR_PREAUTH_FAILED    = 24
KDC_ERR_ETYPE_NOSUPP      = 14
KDC_ERR_TGT_REVOKED       = 20
KDC_ERR_WRONG_REALM       = 68
KRB_AP_ERR_BAD_INTEGRITY  = 31


class KerberosError(Exception):
    def __init__(self, code, msg=''):
        self.code = code
        super().__init__('KerberosError 0x%x: %s' % (code, msg or _error_name(code)))

    def get_error_code(self):
        return self.code


def _error_name(code):
    names = {
        KDC_ERR_PREAUTH_FAILED:   'KDC_ERR_PREAUTH_FAILED',
        KDC_ERR_ETYPE_NOSUPP:     'KDC_ERR_ETYPE_NOSUPP',
        KDC_ERR_TGT_REVOKED:      'KDC_ERR_TGT_REVOKED',
        KDC_ERR_WRONG_REALM:      'KDC_ERR_WRONG_REALM',
        KRB_AP_ERR_BAD_INTEGRITY: 'KRB_AP_ERR_BAD_INTEGRITY',
    }
    return names.get(code, 'UNKNOWN')


# ---------------------------------------------------------------------------
# Wire helpers
# ---------------------------------------------------------------------------

def _krb_time(dt=None):
    """Format datetime as Kerberos GeneralizedTime string."""
    if dt is None:
        dt = datetime.datetime.utcnow()
    return dt.strftime('%Y%m%d%H%M%SZ').encode()


def _make_principal(name: str, name_type: int = 1):
    """Build a PrincipalName ASN.1 object."""
    parts = name.split('/')
    pn = PrincipalName()
    pn['name-type'] = name_type
    ns = univ.SequenceOf(componentType=KerberosString())
    for i, p in enumerate(parts):
        ns[i] = p.encode()
    pn['name-string'] = ns
    return pn


def _send_recv(host: str, port: int, data: bytes) -> bytes:
    """Send a Kerberos message over TCP (4-byte length prefix)."""
    msg = struct.pack('>I', len(data)) + data
    with socket.create_connection((host, port), timeout=10) as s:
        s.sendall(msg)
        # Read 4-byte length
        raw_len = b''
        while len(raw_len) < 4:
            chunk = s.recv(4 - len(raw_len))
            if not chunk:
                raise ConnectionError('KDC closed connection')
            raw_len += chunk
        length = struct.unpack('>I', raw_len)[0]
        resp = b''
        while len(resp) < length:
            chunk = s.recv(length - len(resp))
            if not chunk:
                raise ConnectionError('KDC closed connection')
            resp += chunk
    return resp


def _check_error(resp: bytes):
    """Raise KerberosError if response is a KRB-ERROR."""
    try:
        err, _ = decoder.decode(resp, asn1Spec=KRBError())
        code = int(err['error-code'])
        raise KerberosError(code)
    except KerberosError:
        raise
    except Exception:
        pass  # not an error message


# ---------------------------------------------------------------------------
# Pre-authentication
# ---------------------------------------------------------------------------

def _build_pa_enc_timestamp(key: bytes, etype: int) -> bytes:
    """Build PA-ENC-TIMESTAMP pre-auth data."""
    from pyasn1.type import useful
    now = datetime.datetime.utcnow()
    # PA-ENC-TS-ENC ::= SEQUENCE { patimestamp, pausec }
    ts = univ.Sequence()
    ts['patimestamp'] = KerberosTime(_krb_time(now))  # type: ignore
    ts['pausec'] = now.microsecond
    plaintext = encoder.encode(ts)
    cipher = get_cipher(etype)
    encrypted = cipher.encrypt(key, 1, plaintext)  # key usage 1 = AS-REQ pa-enc-ts
    enc_data = EncryptedData()
    enc_data['etype'] = etype
    enc_data['cipher'] = encrypted
    return encoder.encode(enc_data)


# ---------------------------------------------------------------------------
# AS-REQ (TGT request)
# ---------------------------------------------------------------------------

def get_tgt(username: str, domain: str, dc: str,
            nthash: str = None, aes_key: str = None,
            port: int = 88) -> tuple:
    """
    Request a TGT from the KDC.

    Returns (tgt_bytes, etype, session_key_bytes, old_session_key_bytes)
    where tgt_bytes is the raw DER-encoded AS-REP.

    Tries AES256 first if aes_key provided, falls back to RC4.
    """
    attempts = []
    if aes_key:
        attempts.append((18, unhexlify(aes_key)))
    if nthash:
        attempts.append((23, unhexlify(nthash)))
    if not attempts:
        raise ValueError('Provide nthash or aes_key')

    for etype, key in attempts:
        try:
            tgt, session_key = _do_as_req(username, domain, dc, port, etype, key)
            return tgt, etype, session_key, key
        except KerberosError as e:
            if e.code in (KDC_ERR_ETYPE_NOSUPP, KDC_ERR_PREAUTH_FAILED):
                continue
            raise

    raise KerberosError(KDC_ERR_PREAUTH_FAILED, 'All credential types failed')


def _do_as_req(username, domain, dc, port, etype, key):
    """Build and send AS-REQ, return (raw_as_rep, session_key_bytes)."""
    nonce = struct.unpack('>I', os.urandom(4))[0]

    req = ASReq()
    req['pvno'] = 5
    req['msg-type'] = 10  # AS-REQ

    # Pre-auth
    pa_ts = _build_pa_enc_timestamp(key, etype)
    pa = PADATA()
    pa['padata-type'] = 2  # PA-ENC-TIMESTAMP
    pa['padata-value'] = pa_ts
    pas = PADATASequence()
    pas[0] = pa
    req['padata'] = pas

    # Request body
    body = KDCReqBody()
    body['kdc-options'] = univ.BitString(hexValue='50800000')  # forwardable, renewable
    body['cname'] = _make_principal(username, 1)
    body['realm'] = domain.upper().encode()
    body['sname'] = _make_principal('krbtgt/%s' % domain.upper(), 2)
    body['till'] = KerberosTime(_krb_time(
        datetime.datetime.utcnow() + datetime.timedelta(hours=10)
    ))
    body['nonce'] = nonce
    etypes = univ.SequenceOf(componentType=univ.Integer())
    etypes[0] = etype
    body['etype'] = etypes
    req['req-body'] = body

    raw = encoder.encode(req)
    resp = _send_recv(dc, port, raw)
    _check_error(resp)

    as_rep, _ = decoder.decode(resp, asn1Spec=ASRep())
    # Decrypt enc-part to get session key
    enc_part_cipher = bytes(as_rep['enc-part']['cipher'])
    cipher = get_cipher(etype)
    # Key usage 3 = AS-REP enc-part encrypted with client key
    plaintext = cipher.decrypt(key, 3, enc_part_cipher)
    # The session key is in EncASRepPart — parse it
    # EncASRepPart is APP(25), just decode as Sequence to get key
    enc_as_rep_part, _ = decoder.decode(plaintext)
    session_key_etype = int(enc_as_rep_part[0][0])
    session_key_bytes = bytes(enc_as_rep_part[0][1])

    return resp, session_key_bytes


# ---------------------------------------------------------------------------
# TGS-REQ (service ticket request)
# ---------------------------------------------------------------------------

def get_tgs(spn: str, domain: str, dc: str,
            tgt_bytes: bytes, tgt_etype: int, session_key: bytes,
            port: int = 88) -> tuple:
    """
    Request a TGS using an existing TGT.
    Returns (tgs_bytes, etype, service_session_key).
    """
    as_rep, _ = decoder.decode(tgt_bytes, asn1Spec=ASRep())
    ticket = as_rep['ticket']

    nonce = struct.unpack('>I', os.urandom(4))[0]

    # Build authenticator
    auth = _build_authenticator(domain, session_key, tgt_etype)

    # Encrypt authenticator with session key
    cipher = get_cipher(tgt_etype)
    enc_auth = cipher.encrypt(session_key, 7, auth)  # key usage 7 = TGS-REQ authenticator

    enc_auth_data = EncryptedData()
    enc_auth_data['etype'] = tgt_etype
    enc_auth_data['cipher'] = enc_auth

    # AP-REQ
    ap_req = _build_ap_req(ticket, enc_auth_data)

    # TGS-REQ
    req = TGSReq()
    req['pvno'] = 5
    req['msg-type'] = 12

    pa = PADATA()
    pa['padata-type'] = 1  # PA-TGS-REQ
    pa['padata-value'] = ap_req
    pas = PADATASequence()
    pas[0] = pa
    req['padata'] = pas

    body = KDCReqBody()
    body['kdc-options'] = univ.BitString(hexValue='50800000')
    body['realm'] = domain.upper().encode()
    body['sname'] = _make_principal(spn, 2)
    body['till'] = KerberosTime(_krb_time(
        datetime.datetime.utcnow() + datetime.timedelta(hours=10)
    ))
    body['nonce'] = nonce
    etypes = univ.SequenceOf(componentType=univ.Integer())
    etypes[0] = tgt_etype
    body['etype'] = etypes
    req['req-body'] = body

    raw = encoder.encode(req)
    resp = _send_recv(dc, port, raw)
    _check_error(resp)

    tgs_rep, _ = decoder.decode(resp, asn1Spec=TGSRep())
    enc_part_cipher = bytes(tgs_rep['enc-part']['cipher'])
    plaintext = cipher.decrypt(session_key, 8, enc_part_cipher)  # key usage 8 = TGS-REP enc-part
    enc_tgs_rep_part, _ = decoder.decode(plaintext)
    svc_session_key = bytes(enc_tgs_rep_part[0][1])

    return resp, tgt_etype, svc_session_key


def _build_authenticator(realm: str, session_key: bytes, etype: int) -> bytes:
    """Build a minimal Kerberos Authenticator for TGS-REQ."""
    now = datetime.datetime.utcnow()
    auth = univ.Sequence()
    # authenticator-vno=5, crealm, cname, cusec, ctime
    # Simplified — just enough for TGS-REQ
    auth_seq = univ.Sequence()
    auth_seq[0] = univ.Integer(5)
    auth_seq[1] = univ.OctetString(realm.upper().encode())
    auth_seq[2] = univ.Integer(now.microsecond)
    auth_seq[3] = KerberosTime(_krb_time(now))
    return encoder.encode(auth_seq)


def _build_ap_req(ticket, enc_auth_data) -> bytes:
    """Build AP-REQ containing the TGT and encrypted authenticator."""
    ap_req = univ.Sequence()
    ap_req[0] = univ.Integer(5)   # pvno
    ap_req[1] = univ.Integer(14)  # msg-type AP-REQ
    ap_req[2] = univ.BitString(hexValue='00000000')  # ap-options
    ap_req[3] = ticket
    ap_req[4] = enc_auth_data
    return encoder.encode(ap_req)


# ---------------------------------------------------------------------------
# Ticket decryption
# ---------------------------------------------------------------------------

def decrypt_ticket(as_rep_bytes: bytes, krbtgt_key: bytes, etype: int) -> tuple:
    """
    Decrypt the ticket inside an AS-REP using the krbtgt key.
    Returns (enc_ticket_part_asn1, raw_plaintext).
    """
    as_rep, _ = decoder.decode(as_rep_bytes, asn1Spec=ASRep())
    cipher_text = bytes(as_rep['ticket']['enc-part']['cipher'])
    ticket_etype = int(as_rep['ticket']['enc-part']['etype'])
    cipher = get_cipher(ticket_etype)
    plaintext = cipher.decrypt(krbtgt_key, 2, cipher_text)  # key usage 2
    enc_ticket, _ = decoder.decode(plaintext, asn1Spec=EncTicketPart())
    return enc_ticket, plaintext, as_rep


def reencrypt_ticket(as_rep, enc_ticket_part, krbtgt_key: bytes, etype: int) -> bytes:
    """Re-encrypt a modified EncTicketPart and return updated AS-REP bytes."""
    cipher = get_cipher(etype)
    new_cipher_text = cipher.encrypt(krbtgt_key, 2, encoder.encode(enc_ticket_part))
    as_rep['ticket']['enc-part']['cipher'] = new_cipher_text
    return encoder.encode(as_rep)
