"""
trustkit.core.ccache
~~~~~~~~~~~~~~~~~~~~
Minimal MIT ccache file writer (no impacket dependency).

Format reference: https://web.mit.edu/kerberos/krb5-devel/doc/formats/ccache_file_format.html

Writes a ccache containing a single ticket so it can be used with:
  export KRB5CCNAME=/tmp/ticket.ccache
  impacket-secretsdump -k -no-pass ...
"""

import struct
import datetime


def _pack_principal(realm: str, name: str) -> bytes:
    """Pack a principal (realm + name components) into ccache binary format."""
    parts = name.split('/')
    # name_type(4) + num_components(4) + realm_len(4) + realm + components
    data = struct.pack('>II', 1, len(parts))  # name_type=1 (NT_PRINCIPAL), count
    realm_b = realm.encode()
    data += struct.pack('>I', len(realm_b)) + realm_b
    for p in parts:
        p_b = p.encode()
        data += struct.pack('>I', len(p_b)) + p_b
    return data


def _pack_keyblock(etype: int, key: bytes) -> bytes:
    """Pack a keyblock: etype(2) + etype(2) + key_len(2) + key."""
    return struct.pack('>HHH', etype, etype, len(key)) + key


def _pack_times(auth: int, start: int, end: int, renew: int) -> bytes:
    return struct.pack('>IIII', auth, start, end, renew)


def _pack_ticket(ticket_bytes: bytes) -> bytes:
    return struct.pack('>I', len(ticket_bytes)) + ticket_bytes


def write_ccache(path: str, tgs_rep_bytes: bytes, session_key: bytes,
                 etype: int, client: str, realm: str, spn: str):
    """
    Write a ccache file containing a single service ticket.

    Args:
        path:          Output file path
        tgs_rep_bytes: Raw DER-encoded TGS-REP (or AS-REP for TGT)
        session_key:   Session key bytes
        etype:         Encryption type integer
        client:        Client principal name (e.g. 'administrator')
        realm:         Realm (e.g. 'DEMACIA.DOJO')
        spn:           Service principal name (e.g. 'cifs/DC1.demacia.dojo')
    """
    # Extract the raw ticket from the TGS-REP
    from pyasn1.codec.der import decoder
    from trustkit.core.kerberos import TGSRep, ASRep

    try:
        rep, _ = decoder.decode(tgs_rep_bytes, asn1Spec=TGSRep())
    except Exception:
        rep, _ = decoder.decode(tgs_rep_bytes, asn1Spec=ASRep())

    ticket_bytes = bytes(decoder.decode(bytes(rep['ticket']))[0] if False else
                         _encode_ticket(rep))

    now = int(datetime.datetime.utcnow().timestamp())
    end = now + 36000  # 10 hours

    # ccache file format v4
    # Header: file_format_version(2) + header_len(2) + header_tags
    header_tag = struct.pack('>HHI', 1, 4, 0)  # tag=1 (DeltaTime), len=4, offset=0
    header = struct.pack('>HH', 0x0504, len(header_tag)) + header_tag

    # Default principal
    default_principal = _pack_principal(realm.upper(), client)

    # Credential entry
    client_principal = _pack_principal(realm.upper(), client)
    server_principal = _pack_principal(realm.upper(), spn)
    keyblock = _pack_keyblock(etype, session_key)
    times = _pack_times(now, now, end, end)
    is_skey = struct.pack('>B', 0)
    ticket_flags = struct.pack('>I', 0x40e00000)  # forwardable, renewable, initial, pre-authent
    addresses = struct.pack('>I', 0)   # no addresses
    authdata  = struct.pack('>I', 0)   # no authdata
    raw_ticket = _pack_ticket(ticket_bytes)
    second_ticket = struct.pack('>I', 0)

    credential = (client_principal + server_principal + keyblock + times +
                  is_skey + ticket_flags + addresses + authdata +
                  raw_ticket + second_ticket)

    with open(path, 'wb') as f:
        f.write(header)
        f.write(default_principal)
        f.write(credential)


def _encode_ticket(rep) -> bytes:
    """Re-encode the ticket from a KDC-REP."""
    from pyasn1.codec.der import encoder
    return encoder.encode(rep['ticket'])
