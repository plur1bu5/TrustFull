"""
trustkit.attacks.enumerate
~~~~~~~~~~~~~~~~~~~~~~~~~~
Comprehensive AD trust enumeration module.

For each trust discovered, enumerates:
  - Direction, type, transitivity
  - SID filtering (quarantine) status
  - Selective authentication
  - TGT delegation (CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION)
  - TREAT_AS_EXTERNAL (relaxed SID filtering for cross-forest)
  - RC4 vs AES encryption support
  - Trust account name (via trustedDomain flatName)
  - Target DC resolution
  - Foreign security principals (cross-forest group members)
  - Applicable attack techniques

Usage:
  trustfull enumerate domain.local/user -hashes :NTHASH -dc-ip 10.0.0.1
  trustfull enumerate domain.local/user -p 'Password' -dc-ip 10.0.0.1
  trustfull enumerate domain.local/user -k -no-pass -dc-ip 10.0.0.1
"""

import sys
import logging
import argparse
import socket
import struct
import datetime

# trustAttributes bit flags (MS-ADTS 2.2.16)
TRUST_ATTR = {
    0x00000001: ('NON_TRANSITIVE',                  'Non-transitive'),
    0x00000002: ('UPLEVEL_ONLY',                    'Uplevel-only (Windows 2000+)'),
    0x00000004: ('QUARANTINED_DOMAIN',              'SID filtering enabled (quarantine)'),
    0x00000008: ('FOREST_TRANSITIVE',               'Forest-transitive'),
    0x00000010: ('CROSS_ORGANIZATION',              'Cross-organization (selective auth)'),
    0x00000020: ('WITHIN_FOREST',                   'Within forest (parent-child or shortcut)'),
    0x00000040: ('TREAT_AS_EXTERNAL',               'Treat as external (relaxed SID filtering)'),
    0x00000080: ('USES_RC4_ENCRYPTION',             'Uses RC4 encryption'),
    0x00000200: ('CROSS_ORG_NO_TGT_DELEGATION',     'TGT delegation DISABLED across trust'),
    0x00000400: ('PIM_TRUST',                       'PAM/PIM trust'),
    0x00000800: ('CROSS_ORG_ENABLE_TGT_DELEGATION', 'TGT delegation ENABLED across trust'),
}

# userAccountControl flags relevant to delegation
UAC_TRUSTED_FOR_DELEGATION         = 0x00080000  # unconstrained
UAC_NOT_DELEGATED                  = 0x00100000
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x01000000  # constrained with protocol transition

TRUST_DIRECTION = {0: 'Disabled', 1: 'Inbound', 2: 'Outbound', 3: 'Bidirectional'}
TRUST_TYPE      = {1: 'Downlevel (NT)', 2: 'Uplevel (AD)', 3: 'MIT Kerberos', 4: 'Unknown'}


def _parse_forest_trust_info(data):
    """
    Parse msDS-TrustForestTrustInfo binary blob (MS-ADTS 6.1.6.7.1).
    Returns list of dicts with domain name and SID for each record.
    Record types: 0=TopLevelName, 1=TopLevelNameEx, 2=DomainInfo
    """
    results = []
    try:
        if len(data) < 8:
            return results
        # version (4 bytes) + record count (4 bytes)
        version, count = struct.unpack_from('<II', data, 0)
        offset = 8
        for _ in range(count):
            if offset + 12 > len(data):
                break
            rec_len, flags, timestamp_lo, timestamp_hi, rec_type = struct.unpack_from('<IIIII', data, offset)
            # rec_type is actually at offset+16 in some versions — handle both
            # Standard layout: RecordLen(4) + Flags(4) + Timestamp(8) + Type(4) + Data
            rec_type = struct.unpack_from('<I', data, offset + 16)[0]
            rec_data_offset = offset + 20
            rec_end = offset + rec_len

            if rec_type == 2:  # LSA_FOREST_TRUST_DOMAIN_INFO
                try:
                    # SID length (4) + SID bytes + DnsName length (4) + DnsName + NetbiosName length (4) + NetbiosName
                    sid_len = struct.unpack_from('<I', data, rec_data_offset)[0]
                    sid_bytes = data[rec_data_offset+4 : rec_data_offset+4+sid_len]
                    sid_str = _format_sid(sid_bytes)
                    dns_offset = rec_data_offset + 4 + sid_len
                    dns_len = struct.unpack_from('<I', data, dns_offset)[0]
                    dns_name = data[dns_offset+4 : dns_offset+4+dns_len].decode('utf-16-le', errors='replace')
                    results.append({'type': 'domain', 'sid': sid_str, 'name': dns_name})
                except Exception:
                    pass
            elif rec_type == 0:  # LSA_FOREST_TRUST_TOP_LEVEL_NAME
                try:
                    name_len = struct.unpack_from('<I', data, rec_data_offset)[0]
                    name = data[rec_data_offset+4 : rec_data_offset+4+name_len].decode('utf-16-le', errors='replace')
                    results.append({'type': 'tln', 'name': name})
                except Exception:
                    pass

            offset = rec_end if rec_len > 0 else offset + 20
    except Exception:
        pass
    return results


def _format_sid(sid_bytes):
    """Convert raw SID bytes to S-1-X-Y-Z string."""
    try:
        if len(sid_bytes) < 8:
            return sid_bytes.hex()
        revision = sid_bytes[0]
        sub_count = sid_bytes[1]
        authority = int.from_bytes(sid_bytes[2:8], 'big')
        subs = [struct.unpack_from('<I', sid_bytes, 8 + i*4)[0] for i in range(sub_count)]
        return 'S-%d-%d-%s' % (revision, authority, '-'.join(str(s) for s in subs))
    except Exception:
        return sid_bytes.hex()

BANNER = r"""
  ___ _ __  _   _ _ __ ___   ___ _ __ __ _| |_ ___
 / _ \ '_ \| | | | '_ ` _ \ / _ \ '__/ _` | __/ _ \
|  __/ | | | |_| | | | | | |  __/ | | (_| | ||  __/
 \___|_| |_|\__,_|_| |_| |_|\___|_|  \__,_|\__\___|

 Trust Enumeration -- trustfull by plur1bu5
"""


def build_parser():
    p = argparse.ArgumentParser(
        prog='trustfull enumerate',
        description='Enumerate all AD trust relationships with attack surface analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  trustfull enumerate domain.local/user -p 'Password' -dc-ip 10.0.0.1
  trustfull enumerate domain.local/user -hashes :NTHASH -dc-ip 10.0.0.1
  trustfull enumerate domain.local/user -k -no-pass -dc-ip 10.0.0.1
  trustfull enumerate domain.local/user -hashes :NTHASH -dc-ip 10.0.0.1 --recurse
"""
    )
    p.add_argument('target', help='domain/username')
    p.add_argument('-p', '-password', metavar='PASSWORD', dest='password', default='')
    p.add_argument('-hashes', metavar='LMHASH:NTHASH')
    p.add_argument('-aesKey', metavar='HEX')
    p.add_argument('-k', action='store_true', help='Use Kerberos (KRB5CCNAME)')
    p.add_argument('-no-pass', action='store_true')
    p.add_argument('-dc-ip', metavar='IP', required=True)
    p.add_argument('--recurse', action='store_true',
                   help='Recursively enumerate trusts in discovered domains (if creds work)')
    p.add_argument('--foreign-principals', action='store_true',
                   help='Enumerate foreign security principals, group members, ACLs, SID history, shadow principals, gMSA, unconstrained delegation')
    p.add_argument('--cross-trust', action='store_true',
                   help='Actively enumerate Kerberoastable/ASREPRoastable accounts in discovered trusted domains')
    p.add_argument('-debug', action='store_true')
    return p


def main():
    print(BANNER)
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format='%(message)s')

    domain, username = args.target.split('/', 1)
    password = args.password or ''
    lmhash = nthash = ''
    if args.hashes:
        lm, nt = args.hashes.split(':', 1)
        lmhash, nthash = lm, nt

    enumerator = TrustEnumerator(
        domain=domain, username=username, password=password,
        lmhash=lmhash, nthash=nthash, aes_key=args.aesKey or '',
        use_kerberos=args.k, dc_ip=args.dc_ip, debug=args.debug,
    )

    try:
        trusts = enumerator.enumerate()
        enumerator.print_trusts(trusts)

        if args.foreign_principals:
            # Foreign security principals (cross-forest group memberships)
            fps = enumerator.enumerate_foreign_principals()
            enumerator.print_foreign_principals(fps)

            # Foreign group members (users from other domains in local groups)
            fgm = enumerator.enumerate_foreign_group_members()
            if fgm:
                print('\n[*] Foreign Group Members in %s (users from other domains in local groups)' % domain)
                for item in fgm:
                    print('  Group: %s' % item['group'])
                    for m in item['foreign_members']:
                        print('    --> %s' % m)

            # Foreign ACL principals
            facls = enumerator.enumerate_foreign_acls()
            if facls:
                print('\n[*] Foreign ACL Principals in %s  <-- cross-domain privilege escalation paths' % domain)
                for item in facls:
                    # Try to resolve SID to name
                    trustee_display = item['trustee_sid']
                    try:
                        # Check if SID is from a trusted domain
                        sid_domain_part = '-'.join(item['trustee_sid'].split('-')[:-1])
                        for t in trusts:
                            if t.get('sid') == sid_domain_part:
                                # Found the domain, try to resolve
                                resolved = enumerator._resolve_sid_in_domain(item['trustee_sid'], t['name'], t.get('dc_ip'))
                                if resolved:
                                    trustee_display = f"{resolved} ({item['trustee_sid']})"
                                break
                    except:
                        pass
                    print('  \033[93m[!]\033[0m %s has \033[91m%s\033[0m on %s' % (
                        trustee_display, item['right'], item['object']))
            else:
                print('\n[*] Foreign ACL Principals: none found (or nTSecurityDescriptor not readable)')

            # SID history
            sid_hist = enumerator.enumerate_sid_history()
            if sid_hist:
                print('\n[*] Accounts with SID History in %s  <-- potential privilege escalation' % domain)
                for item in sid_hist:
                    print('  \033[93m[!]\033[0m %s  sIDHistory: %s' % (item['name'], ', '.join(item['sid_history'])))

            # Shadow principals (PAM trust)
            shadows = enumerator.enumerate_shadow_principals()
            if shadows:
                print('\n[*] Shadow Principals (PAM Trust) in %s  <-- bastion forest admin access' % domain)
                for s in shadows:
                    print('  \033[91m[!!]\033[0m %s  mapped SID: %s' % (s['name'], s['mapped_sid']))
                    for m in s.get('members', []):
                        print('       member: %s' % m)

            # Unconstrained delegation
            hosts = enumerator.enumerate_unconstrained_delegation()
            if hosts:
                print('\n[*] Unconstrained Delegation Hosts in %s' % domain)
                for h in hosts:
                    dc_marker = ' (DC)' if h['is_dc'] else '  <-- non-DC, prime TGT capture target'
                    print('  %-30s  %s%s' % (h['name'], h['dns'] or '', dc_marker))

            # Constrained delegation
            constrained = enumerator.enumerate_constrained_delegation()
            if constrained:
                print('\n[*] Constrained Delegation Accounts in %s' % domain)
                for c in constrained:
                    pt = ' (protocol transition)' if c['protocol_transition'] else ''
                    print('  %-30s%s' % (c['name'], pt))
                    for spn in c['spns']:
                        print('    -> %s' % spn)

            # RBCD
            rbcd = enumerator.enumerate_rbcd()
            if rbcd:
                print('\n[*] Resource-Based Constrained Delegation in %s' % domain)
                for r in rbcd:
                    print('  %-30s' % r['name'])
                    for sid in r['allowed_sids']:
                        print('    <- %s' % sid)

            # gMSA accounts
            gmsas = enumerator.enumerate_gmsa()
            if gmsas:
                print('\n[*] gMSA Accounts in %s  (GoldenGMSA target if child domain SYSTEM)' % domain)
                for g in gmsas:
                    print('  %-30s  rotation: %s days' % (g['name'], g['interval'] or 'N/A'))

        if getattr(args, 'cross_trust', False) and trusts:
            print('\n[*] Cross-trust active enumeration...')
            for t in trusts:
                if t['direction'] not in (2, 3):  # only outbound/bidirectional
                    continue
                td = t['name']
                td_ip = t.get('dc_ip')
                if not td_ip:
                    print('  [-] %s -- no DC resolved, skipping' % td)
                    continue
                print('  [*] Attempting Kerberoasting in %s...' % td)
                kerb = enumerator.enumerate_kerberoastable_across_trust(td, td_ip)
                if kerb:
                    print('\n  [*] Kerberoastable accounts in %s:' % td)
                    for u in kerb:
                        print('    \033[93m[!]\033[0m %-25s  SPNs: %s' % (u['name'], ', '.join(u['spns'])))
                    print('  --> impacket-GetUserSPNs -target-domain %s %s/%s' % (td, domain, enumerator.username))
                else:
                    print('  [-] No Kerberoastable accounts found (or auth failed)')
                print('  [*] Attempting ASREPRoasting in %s...' % td)
                asrep = enumerator.enumerate_asreproastable_across_trust(td, td_ip)
                if asrep:
                    print('\n  [*] ASREPRoastable accounts in %s:' % td)
                    for u in asrep:
                        print('    \033[93m[!]\033[0m %s' % u)
                    print('  --> impacket-GetNPUsers -target-domain %s %s/%s' % (td, domain, enumerator.username))
                else:
                    print('  [-] No ASREPRoastable accounts found (or auth failed)')
                
                # Enumerate unconstrained delegation across trust
                print('  [*] Enumerating unconstrained delegation in %s...' % td)
                unc_hosts = enumerator.enumerate_unconstrained_delegation_across_trust(td, td_ip)
                if unc_hosts:
                    print('\n  [*] Unconstrained Delegation Hosts in %s:' % td)
                    for h in unc_hosts:
                        dc_marker = ' (DC)' if h['is_dc'] else '  <-- non-DC, prime TGT capture target'
                        print('    \033[93m[!]\033[0m %-25s  %s%s' % (h['name'], h['dns'] or '', dc_marker))
                else:
                    print('  [-] No unconstrained delegation hosts found (or auth failed)')
                
                # Enumerate constrained delegation
                print('  [*] Enumerating constrained delegation in %s...' % td)
                constrained = enumerator.enumerate_constrained_delegation_across_trust(td, td_ip)
                if constrained:
                    print('\n  [*] Constrained Delegation in %s:' % td)
                    for c in constrained:
                        pt = ' (protocol transition)' if c['protocol_transition'] else ''
                        print('    \033[93m[!]\033[0m %-25s%s' % (c['name'], pt))
                        for spn in c['spns']:
                            print('      -> %s' % spn)
                else:
                    print('  [-] No constrained delegation found (or auth failed)')
                
                # Enumerate RBCD
                print('  [*] Enumerating RBCD in %s...' % td)
                rbcd = enumerator.enumerate_rbcd_across_trust(td, td_ip)
                if rbcd:
                    print('\n  [*] Resource-Based Constrained Delegation in %s:' % td)
                    for r in rbcd:
                        print('    \033[93m[!]\033[0m %-25s' % r['name'])
                        for sid in r['allowed_sids']:
                            print('      <- %s' % sid)
                else:
                    print('  [-] No RBCD found (or auth failed)')
                
                # Enumerate foreign ACLs in trusted domain (check if current domain users have ACLs there)
                print('  [*] Checking for foreign ACLs in %s...' % td)
                foreign_acls = enumerator.enumerate_foreign_acls_across_trust(td, td_ip)
                if foreign_acls:
                    print('\n  [*] Foreign ACLs in %s (current domain users with permissions):' % td)
                    for item in foreign_acls:
                        trustee_display = item['trustee_sid']
                        try:
                            resolved = enumerator._resolve_sid(item['trustee_sid'])
                            if resolved:
                                trustee_display = f"{resolved} ({item['trustee_sid']})"
                        except:
                            pass
                        print('    \033[93m[!]\033[0m %s has \033[91m%s\033[0m on %s' % (
                            trustee_display, item['right'], item['object']))
                else:
                    print('  [-] No foreign ACLs found (or auth failed)')
                if asrep:
                    print('\n  [*] ASREPRoastable accounts in %s:' % td)
                    for u in asrep:
                        print('    \033[93m[!]\033[0m %s' % u)
                    print('  --> impacket-GetNPUsers -target-domain %s %s/%s' % (td, domain, enumerator.username))
                else:
                    print('  [-] No ASREPRoastable accounts found (or auth failed)')

        if args.recurse and trusts:
            print('\n[*] Recursing into discovered domains...')
            seen = {domain.lower()}
            for t in trusts:
                target_domain = t['name']
                if target_domain.lower() in seen:
                    continue
                seen.add(target_domain.lower())
                dc_ip = t.get('dc_ip')
                if not dc_ip:
                    print('[-] Cannot recurse into %s -- no DC resolved' % target_domain)
                    continue
                print('\n[*] Enumerating trusts in %s (%s)' % (target_domain, dc_ip))
                sub = TrustEnumerator(
                    domain=target_domain, username=username, password=password,
                    lmhash=lmhash, nthash=nthash, aes_key=args.aesKey or '',
                    use_kerberos=args.k, dc_ip=dc_ip, debug=args.debug,
                )
                try:
                    sub_trusts = sub.enumerate()
                    sub.print_trusts(sub_trusts)
                except Exception as e:
                    print('[-] Could not enumerate %s: %s' % (target_domain, e))

    except Exception as e:
        print('\n\033[91m[-] Error:\033[0m %s' % e)
        if args.debug:
            import traceback; traceback.print_exc()
        sys.exit(1)


class TrustEnumerator:
    def __init__(self, domain, username, password, lmhash, nthash,
                 aes_key, use_kerberos, dc_ip, debug=False):
        self.domain       = domain
        self.username     = username
        self.password     = password
        self.lmhash       = lmhash
        self.nthash       = nthash
        self.aes_key      = aes_key
        self.use_kerberos = use_kerberos
        self.dc_ip        = dc_ip
        self.debug        = debug
        self._ldap        = None

    def _connect(self):
        from impacket.ldap import ldap as impacket_ldap

        conn = impacket_ldap.LDAPConnection('ldap://%s' % self.dc_ip, self.domain, self.dc_ip)
        if self.use_kerberos:
            conn.kerberosLogin(
                self.username, self.password, self.domain,
                self.lmhash, self.nthash, self.aes_key,
                kdcHost=self.dc_ip
            )
        else:
            conn.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
        self._ldap = conn
        return conn

    def _base_dn(self):
        return ','.join('DC=%s' % p for p in self.domain.split('.'))

    def enumerate(self):
        conn = self._connect()
        base = self._base_dn()

        resp = conn.search(
            searchBase='CN=System,%s' % base,
            searchFilter='(objectClass=trustedDomain)',
            attributes=[
                'name', 'flatName', 'trustDirection', 'trustType',
                'trustAttributes', 'securityIdentifier',
                'msDS-TrustForestTrustInfo',
                'whenCreated', 'whenChanged', 'objectGUID',
                'trustPosixOffset',
            ],
            sizeLimit=0,
        )

        trusts = []
        for entry in resp:
            if 'objectName' not in entry:
                continue
            t = self._parse_trust(entry)
            if t:
                trusts.append(t)
        return trusts

    def _parse_trust(self, entry):
        def _attr(name):
            try:
                for a in entry['attributes']:
                    if str(a['type']).lower() == name.lower():
                        v = a['vals'][0]
                        # impacket returns AttributeValue — extract raw bytes or string
                        raw = bytes(v)
                        # try decode as string first (for text fields)
                        try:
                            return raw.decode('utf-8')
                        except Exception:
                            return raw
            except Exception:
                pass
            return None

        name = _attr('name')
        if not name:
            return None

        flat_name  = _attr('flatName') or ''
        direction  = int(_attr('trustDirection') or 0)
        trust_type = int(_attr('trustType') or 0)
        attrs      = int(_attr('trustAttributes') or 0)

        # Timestamps
        when_created = _attr('whenCreated') or ''
        when_changed = _attr('whenChanged') or ''
        
        # Convert LDAP timestamps to readable format
        def _format_time(ldap_time):
            if not ldap_time or len(ldap_time) < 14:
                return ldap_time
            try:
                from datetime import datetime
                dt = datetime.strptime(ldap_time[:14], '%Y%m%d%H%M%S')
                return dt.strftime('%m/%d/%Y %I:%M:%S %p')
            except:
                return ldap_time
        
        when_created = _format_time(when_created)
        when_changed = _format_time(when_changed)

        # objectGUID — raw bytes → formatted UUID
        guid_raw = _attr('objectGUID')
        guid_str = ''
        if guid_raw:
            try:
                import uuid
                raw_bytes = guid_raw if isinstance(guid_raw, bytes) else guid_raw.encode('latin-1')
                if len(raw_bytes) == 16:
                    guid_str = str(uuid.UUID(bytes_le=raw_bytes))
            except Exception:
                pass

        # Target domain SID
        sid_str = ''
        sid_raw = _attr('securityIdentifier')
        if sid_raw:
            try:
                from impacket.ldap.ldaptypes import LDAP_SID
                raw_bytes = sid_raw if isinstance(sid_raw, bytes) else sid_raw.encode('latin-1')
                sid_str = LDAP_SID(raw_bytes).formatCanonical()
            except Exception:
                pass

        # msDS-TrustForestTrustInfo — parse SIDs of all domains in trusted forest
        forest_trust_info = []
        fti_raw = _attr('msDS-TrustForestTrustInfo')
        if fti_raw:
            raw_bytes = fti_raw if isinstance(fti_raw, bytes) else fti_raw.encode('latin-1')
            forest_trust_info = _parse_forest_trust_info(raw_bytes)

        dc_ip = self._resolve_dc(name)
        trust_class, is_transitive, sid_filtering = self._classify(attrs, trust_type)

        # Derive all boolean flags
        tgt_delegation    = bool(attrs & 0x00000800)
        tgt_no_delegation = bool(attrs & 0x00000200)
        treat_as_external = bool(attrs & 0x00000040)
        selective_auth    = bool(attrs & 0x00000010)
        within_forest     = bool(attrs & 0x00000020)
        forest_transitive = bool(attrs & 0x00000008)
        uses_rc4          = bool(attrs & 0x00000080)
        non_transitive    = bool(attrs & 0x00000001)
        uplevel_only      = bool(attrs & 0x00000002)
        pim_trust         = bool(attrs & 0x00000400)

        # SIDFilteringForestAware: forest trust without TREAT_AS_EXTERNAL
        # = standard forest SID filtering (blocks all extra SIDs from other forests)
        sid_filtering_forest_aware = forest_transitive and not treat_as_external
        # SIDFilteringQuarantined: QUARANTINED_DOMAIN flag
        sid_filtering_quarantined  = bool(attrs & 0x00000004)

        # UsesAESKeys: derived — if RC4 flag NOT set and trust type is Uplevel (AD)
        uses_aes_keys = (trust_type == 2) and not uses_rc4

        # IsTreeRoot / IsTreeParent — not directly in trustAttributes, derive from context
        # IntraForest = WITHIN_FOREST flag
        intra_forest = within_forest

        active_flags = [desc for bit, (_, desc) in TRUST_ATTR.items() if attrs & bit]
        attacks = self._recommend_attacks(
            direction, trust_class, sid_filtering, selective_auth,
            tgt_delegation, treat_as_external, within_forest, forest_transitive,
            forest_trust_info
        )

        return {
            'name': name, 'flat_name': flat_name,
            'direction': direction, 'direction_str': TRUST_DIRECTION.get(direction, 'Unknown'),
            'trust_type': trust_type, 'trust_type_str': TRUST_TYPE.get(trust_type, 'Unknown'),
            'attrs': attrs, 'trust_class': trust_class,
            'is_transitive': is_transitive, 'non_transitive': non_transitive,
            'intra_forest': intra_forest,
            'sid_filtering': sid_filtering,
            'sid_filtering_forest_aware': sid_filtering_forest_aware,
            'sid_filtering_quarantined': sid_filtering_quarantined,
            'selective_auth': selective_auth,
            'tgt_delegation': tgt_delegation, 'tgt_no_delegation': tgt_no_delegation,
            'treat_as_external': treat_as_external,
            'within_forest': within_forest, 'forest_transitive': forest_transitive,
            'uses_rc4': uses_rc4, 'uses_aes_keys': uses_aes_keys,
            'uplevel_only': uplevel_only, 'pim_trust': pim_trust,
            'sid': sid_str, 'dc_ip': dc_ip,
            'guid': guid_str,
            'when_created': when_created, 'when_changed': when_changed,
            'forest_trust_info': forest_trust_info,
            'active_flags': active_flags, 'attacks': attacks,
        }

    def _classify(self, attrs, trust_type):
        if attrs & 0x00000020:
            return 'ParentChild', True, bool(attrs & 0x00000004)
        elif attrs & 0x00000008:
            return 'Forest', True, not bool(attrs & 0x00000040)
        elif attrs & 0x00000040 or attrs & 0x00000010:
            return 'External', False, True
        elif trust_type == 3:
            return 'Realm (MIT Kerberos)', False, True
        else:
            return 'Unknown', not bool(attrs & 0x00000001), True

    def _recommend_attacks(self, direction, trust_class, sid_filtering,
                            selective_auth, tgt_delegation, treat_as_external,
                            within_forest, forest_transitive, forest_trust_info=None):
        attacks = []
        can_attack = direction in (2, 3)

        if within_forest and not sid_filtering:
            attacks.append({'name': 'badChild -- ExtraSids (trust key)', 'cmd': 'trustfull badChild --trust-key',
                'note': 'Child-to-parent escalation via inter-realm ticket + EA SID', 'severity': 'CRITICAL'})
            attacks.append({'name': 'badChild -- ExtraSids (golden ticket)', 'cmd': 'trustfull badChild --golden',
                'note': 'Forge golden ticket with Enterprise Admin SID injected', 'severity': 'CRITICAL'})

        if forest_transitive and not sid_filtering and can_attack:
            attacks.append({'name': 'Cross-Forest ExtraSids', 'cmd': 'trustfull badChild --trust-key',
                'note': 'Forest trust with SID filtering disabled -- ExtraSids works cross-forest', 'severity': 'CRITICAL'})

        if tgt_delegation and can_attack:
            attacks.append({'name': 'TGT Delegation Abuse',
                'cmd': 'Coerce DC -> unconstrained delegation host in trusted domain -> capture TGT',
                'note': 'CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION (0x800) -- TGTs forwarded across trust boundary',
                'severity': 'CRITICAL'})

        if treat_as_external and can_attack:
            attacks.append({'name': 'Diamond Ticket with extra SID (RID>=1000)',
                'cmd': 'impacket-ticketer -extra-sid <TRUSTED_SID>-<RID>=1000',
                'note': 'TREAT_AS_EXTERNAL relaxes SID filtering -- RID>=1000 extra SIDs pass the boundary',
                'severity': 'HIGH'})

        if forest_trust_info and can_attack:
            attacks.append({'name': 'Forest Trust SID injection (msDS-TrustForestTrustInfo)',
                'cmd': 'Modify msDS-TrustForestTrustInfo to inject arbitrary SID into trusted forest list',
                'note': 'With full control of this forest, add arbitrary SIDs trusted by partner forest (~24h propagation)',
                'severity': 'HIGH'})

        if can_attack and not selective_auth:
            attacks.append({'name': 'Kerberoasting across trust',
                'cmd': 'impacket-GetUserSPNs -target-domain TRUSTED_DOMAIN',
                'note': 'Enumerate and crack SPNs in trusted domain', 'severity': 'MEDIUM'})
            attacks.append({'name': 'ASREPRoasting across trust',
                'cmd': 'impacket-GetNPUsers -target-domain TRUSTED_DOMAIN',
                'note': 'Find accounts without Kerberos pre-auth in trusted domain', 'severity': 'MEDIUM'})
            attacks.append({'name': 'Foreign ACLs',
                'cmd': 'trustfull enumerate --foreign-principals',
                'note': 'Users from this domain may have dangerous ACLs (GenericAll, WriteDACL) on objects in trusted domain', 'severity': 'HIGH'})
            attacks.append({'name': 'Foreign principal group membership',
                'cmd': 'trustfull enumerate --foreign-principals',
                'note': 'Trust account may have privileged group membership in trusted domain', 'severity': 'MEDIUM'})
            attacks.append({'name': 'GoldenGMSA across trust',
                'cmd': 'GoldenGMSA tool -- requires SYSTEM on child DC to read KDS root key attributes',
                'note': 'If gMSA accounts exist in parent domain, compute password from child domain SYSTEM context',
                'severity': 'MEDIUM'})

        if sid_filtering and within_forest:
            attacks.append({'name': 'SID filtering ENABLED (quarantine)', 'cmd': None,
                'note': 'QUARANTINED_DOMAIN flag set -- ExtraSids stripped at trust boundary', 'severity': 'BLOCKED'})

        if selective_auth:
            attacks.append({'name': 'Selective authentication ENABLED', 'cmd': None,
                'note': 'Users need explicit "Allowed to authenticate" -- limits lateral movement', 'severity': 'BLOCKED'})

        if not attacks:
            attacks.append({'name': 'No direct attacks identified', 'cmd': None,
                'note': 'Enumerate further: unconstrained delegation hosts, foreign principals, gMSA accounts',
                'severity': 'INFO'})

        return attacks

    def enumerate_unconstrained_delegation(self):
        """Find computers with unconstrained delegation (prime TGT capture targets)."""
        conn = self._ldap or self._connect()
        base = self._base_dn()
        resp = conn.search(
            searchBase=base,
            searchFilter='(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))',
            attributes=['sAMAccountName', 'dNSHostName', 'userAccountControl', 'operatingSystem'],
            sizeLimit=0,
        )
        hosts = []
        for entry in resp:
            if 'objectName' not in entry:
                continue
            try:
                name = dns = os_ver = ''
                for a in entry['attributes']:
                    t = str(a['type']).lower()
                    if t == 'samaccountname': name = str(a['vals'][0])
                    elif t == 'dnshostname':  dns  = str(a['vals'][0])
                    elif t == 'operatingsystem': os_ver = str(a['vals'][0])
                is_dc = 'OU=Domain Controllers' in str(entry['objectName'])
                hosts.append({'name': name, 'dns': dns, 'os': os_ver, 'is_dc': is_dc})
            except Exception:
                pass
        return hosts

    def enumerate_constrained_delegation(self):
        """Find accounts with constrained delegation."""
        conn = self._ldap or self._connect()
        base = self._base_dn()
        resp = conn.search(
            searchBase=base,
            searchFilter='(msDS-AllowedToDelegateTo=*)',
            attributes=['sAMAccountName', 'msDS-AllowedToDelegateTo', 'userAccountControl'],
            sizeLimit=0,
        )
        accounts = []
        for entry in resp:
            if 'objectName' not in entry:
                continue
            try:
                name = spns = uac = ''
                for a in entry['attributes']:
                    t = str(a['type']).lower()
                    if t == 'samaccountname': name = str(a['vals'][0])
                    elif t == 'msds-allowedtodelegateto': spns = [str(v) for v in a['vals']]
                    elif t == 'useraccountcontrol': uac = int(a['vals'][0])
                protocol_transition = bool(uac & 0x01000000)
                accounts.append({'name': name, 'spns': spns, 'protocol_transition': protocol_transition})
            except Exception:
                pass
        return accounts

    def enumerate_rbcd(self):
        """Find accounts with resource-based constrained delegation."""
        conn = self._ldap or self._connect()
        base = self._base_dn()
        resp = conn.search(
            searchBase=base,
            searchFilter='(msDS-AllowedToActOnBehalfOfOtherIdentity=*)',
            attributes=['sAMAccountName', 'msDS-AllowedToActOnBehalfOfOtherIdentity'],
            sizeLimit=0,
        )
        accounts = []
        for entry in resp:
            if 'objectName' not in entry:
                continue
            try:
                name = sd_bytes = None
                for a in entry['attributes']:
                    t = str(a['type']).lower()
                    if t == 'samaccountname': name = str(a['vals'][0])
                    elif t == 'msds-allowedtoactonbehalfofotheridentity':
                        v = a['vals'][0]
                        sd_bytes = bytes(v) if hasattr(v, '__bytes__') else (v if isinstance(v, bytes) else v.encode('latin-1'))
                if name and sd_bytes:
                    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
                    sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)
                    sids = []
                    if sd['Dacl']:
                        for ace in sd['Dacl']['Data']:
                            sid = ace['Ace']['Sid'].formatCanonical()
                            sids.append(self._resolve_sid(sid))
                    if sids:
                        accounts.append({'name': name, 'allowed_sids': sids})
            except Exception:
                pass
        return accounts

    def enumerate_gmsa(self):
        """Find gMSA accounts -- attackable via GoldenGMSA across trust."""
        conn = self._ldap or self._connect()
        base = self._base_dn()
        resp = conn.search(
            searchBase=base,
            searchFilter='(objectClass=msDS-GroupManagedServiceAccount)',
            attributes=['sAMAccountName', 'msDS-ManagedPasswordInterval', 'distinguishedName'],
            sizeLimit=0,
        )
        accounts = []
        for entry in resp:
            if 'objectName' not in entry:
                continue
            try:
                name = interval = ''
                for a in entry['attributes']:
                    t = str(a['type']).lower()
                    if t == 'samaccountname': name = str(a['vals'][0])
                    elif t == 'msds-managedpasswordinterval': interval = str(a['vals'][0])
                accounts.append({'name': name, 'interval': interval, 'dn': str(entry['objectName'])})
            except Exception:
                pass
        return accounts

    def _resolve_dc(self, domain):
        try:
            import dns.resolver
            srv = dns.resolver.resolve('_ldap._tcp.dc._msdcs.%s' % domain, 'SRV')
            host = str(list(srv)[0].target).rstrip('.')
            return socket.gethostbyname(host)
        except Exception:
            pass
        try:
            return socket.gethostbyname(domain)
        except Exception:
            return None

    def _resolve_sid(self, sid):
        """Resolve SID to domain\\username by searching current domain."""
        try:
            conn = self._ldap or self._connect()
            resp = conn.search(
                searchBase=self._base_dn(),
                searchFilter=f'(objectSid={sid})',
                attributes=['sAMAccountName'],
                sizeLimit=1,
            )
            for entry in resp:
                if 'attributes' in entry:
                    for a in entry['attributes']:
                        if str(a['type']).lower() == 'samaccountname':
                            return f"{self.domain}\\{str(a['vals'][0])}"
        except:
            pass
        return None

    def _resolve_sid_in_domain(self, sid, target_domain, target_dc_ip):
        """Resolve SID by querying a specific domain."""
        try:
            sub = TrustEnumerator(
                domain=self.domain, username=self.username, password=self.password,
                lmhash=self.lmhash, nthash=self.nthash, aes_key=self.aes_key,
                use_kerberos=self.use_kerberos, dc_ip=target_dc_ip, debug=False,
            )
            conn = sub._connect()
            base = ','.join('DC=%s' % p for p in target_domain.split('.'))
            resp = conn.search(
                searchBase=base,
                searchFilter=f'(objectSid={sid})',
                attributes=['sAMAccountName'],
                sizeLimit=1,
            )
            for entry in resp:
                if 'attributes' in entry:
                    for a in entry['attributes']:
                        if str(a['type']).lower() == 'samaccountname':
                            return f"{target_domain}\\{str(a['vals'][0])}"
        except:
            pass
        return None

    def enumerate_foreign_principals(self):
        conn = self._ldap or self._connect()
        base = self._base_dn()
        resp = conn.search(
            searchBase='CN=ForeignSecurityPrincipals,%s' % base,
            searchFilter='(objectClass=foreignSecurityPrincipal)',
            attributes=['cn', 'memberOf'],
            sizeLimit=0,
        )
        fps = []
        for entry in resp:
            if 'objectName' not in entry:
                continue
            try:
                cn = member_of = None
                for a in entry['attributes']:
                    t = str(a['type']).lower()
                    if t == 'cn':
                        cn = str(a['vals'][0])
                    elif t == 'memberof':
                        member_of = [str(v) for v in a['vals']]
                if cn:
                    fps.append({'sid': cn, 'member_of': member_of or []})
            except Exception:
                pass
        return fps

    def print_trusts(self, trusts):
        SEV  = {'CRITICAL': '\033[91m', 'HIGH': '\033[93m', 'MEDIUM': '\033[94m', 'BLOCKED': '\033[90m', 'INFO': '\033[0m'}
        MARK = {'CRITICAL': '[!!]', 'HIGH': '[!]', 'MEDIUM': '[*]', 'BLOCKED': '[-]', 'INFO': '[i]'}
        R = '\033[0m'

        print('\n' + '=' * 70)
        print('[*] Domain: %s  |  DC: %s' % (self.domain, self.dc_ip))
        print('=' * 70)

        if not trusts:
            print('  No trusts found.\n')
            return

        print('  Found %d trust(s)\n' % len(trusts))

        for t in trusts:
            print('  +-- Trust: %s --> %s' % (self.domain, t['name']))
            print('  |   NetBIOS:              %s' % (t['flat_name'] or 'N/A'))
            print('  |   Type:                 %s' % t['trust_class'])
            print('  |   Direction:            %s' % t['direction_str'])
            print('  |   Transitive:           %s' % ('Yes' if t['is_transitive'] else 'No'))
            print('  |   IntraForest:          %s' % ('Yes' if t['intra_forest'] else 'No'))
            print('  |   LDAP trust type:      %s' % t['trust_type_str'])
            print('  |   Target SID:           %s' % (t['sid'] or 'N/A'))
            print('  |   Target DC IP:         %s' % (t['dc_ip'] or 'unresolved'))
            print('  |   Object GUID:          %s' % (t['guid'] or 'N/A'))
            print('  |   Created:              %s' % (t['when_created'] or 'N/A'))
            print('  |   Last changed:         %s' % (t['when_changed'] or 'N/A'))
            print('  |')
            print('  |   -- Security Properties --')
            print('  |   SID filtering:        %s' % (
                'Enabled' if t['sid_filtering']
                else '\033[91mDISABLED  <-- ExtraSids attacks possible\033[0m'
            ))
            print('  |   SIDFilteringForestAware: %s' % ('Yes' if t['sid_filtering_forest_aware'] else 'No'))
            print('  |   SIDFilteringQuarantined: %s' % ('Yes' if t['sid_filtering_quarantined'] else 'No'))
            print('  |   Selective auth:       %s' % ('Enabled' if t['selective_auth'] else 'Disabled'))
            print('  |   DisallowTransivity:   %s' % ('Yes' if t['non_transitive'] else 'No'))
            print('  |   TGT delegation:       %s' % (
                '\033[91mENABLED (0x800)  <-- TGTs forwarded across trust\033[0m' if t['tgt_delegation']
                else 'Explicitly disabled (0x200)' if t['tgt_no_delegation']
                else 'Default (not set)'
            ))
            print('  |   Treat-as-external:    %s' % (
                '\033[93mYes (0x40)  <-- RID>=1000 SIDs pass filter\033[0m'
                if t['treat_as_external'] else 'No'
            ))
            print('  |   UsesAESKeys:          %s' % ('Yes' if t['uses_aes_keys'] else 'No'))
            print('  |   UsesRC4Encryption:    %s' % ('Yes' if t['uses_rc4'] else 'No'))
            print('  |   UplevelOnly:          %s' % ('Yes' if t['uplevel_only'] else 'No'))
            if t['pim_trust']:
                print('  |   PAM/PIM trust:        Yes')
            print('  |')

            # msDS-TrustForestTrustInfo decoded
            if t['forest_trust_info']:
                print('  |   -- Forest Trust Info (msDS-TrustForestTrustInfo) --')
                for rec in t['forest_trust_info']:
                    if rec['type'] == 'domain':
                        print('  |     Domain: %-30s  SID: %s' % (rec.get('name', ''), rec.get('sid', '')))
                    elif rec['type'] == 'tln':
                        print('  |     TLN:    %s' % rec.get('name', ''))
                print('  |')

            print('  |   -- Raw Flags (trustAttributes=0x%08x) --' % t['attrs'])
            for f in t['active_flags']:
                print('  |     [+] %s' % f)
            print('  |')
            print('  |   -- Attack Surface --')
            for atk in t['attacks']:
                sev   = atk['severity']
                color = SEV.get(sev, '')
                mark  = MARK.get(sev, '[*]')
                print('  |   %s%s %s%s' % (color, mark, atk['name'], R))
                print('  |       %s' % atk['note'])
                if atk['cmd']:
                    print('  |       --> %s' % atk['cmd'])
            print('  +' + '-' * 60)
            print()

    def print_foreign_principals(self, fps):
        print('\n[*] Foreign Security Principals in %s' % self.domain)
        if not fps:
            print('  None found.\n')
            return
        for fp in fps:
            print('  SID: %s' % fp['sid'])
            for g in fp['member_of']:
                print('    --> Member of: %s' % g)
        print()

    def enumerate_foreign_group_members(self):
        """
        Find users from OTHER domains who are members of groups in THIS domain.
        Equivalent to PowerView's Get-DomainForeignGroupMember.
        Looks for group members whose SID domain part differs from this domain's SID.
        """
        conn = self._ldap or self._connect()
        base = self._base_dn()

        # Get this domain's SID prefix first
        domain_sid = self._get_domain_sid()

        resp = conn.search(
            searchBase=base,
            searchFilter='(&(objectClass=group)(member=*))',
            attributes=['sAMAccountName', 'member', 'distinguishedName'],
            sizeLimit=0,
        )

        results = []
        for entry in resp:
            if 'objectName' not in entry:
                continue
            try:
                group_name = ''
                members = []
                for a in entry['attributes']:
                    t = str(a['type']).lower()
                    if t == 'samaccountname':
                        group_name = str(a['vals'][0])
                    elif t == 'member':
                        members = [str(v) for v in a['vals']]
                # Filter members: only real cross-domain accounts (S-1-5-21-* FSPs or cross-domain DNs)
                foreign = []
                for m in members:
                    if 'ForeignSecurityPrincipals' in m:
                        cn = m.split(',')[0].replace('CN=', '').replace('cn=', '')
                        if cn.startswith('S-1-5-21-'):
                            foreign.append(m)
                    elif 'DC=' in m:
                        m_domain = ','.join(p for p in m.split(',') if p.upper().startswith('DC='))
                        our_domain = ','.join('DC=%s' % p for p in self.domain.split('.'))
                        if m_domain.upper() != our_domain.upper():
                            foreign.append(m)
                if foreign:
                    results.append({'group': group_name, 'group_dn': str(entry['objectName']), 'foreign_members': foreign})
            except Exception:
                pass
        return results

    def enumerate_foreign_acls(self):
        """
        Find ACEs where the trustee SID belongs to a foreign domain.
        Scans high-value targets: domain root, AdminSDHolder, builtin groups.
        """
        conn = self._ldap or self._connect()
        base = self._base_dn()

        domain_sid = self._get_domain_sid()
        if not domain_sid:
            return []

        # Scan high-value objects + all users for foreign ACLs
        config_nc = 'CN=Configuration,%s' % base
        targets = [
            base,
            config_nc,  # Configuration NC - replicates forest-wide
            'CN=AdminSDHolder,CN=System,%s' % base,
            'CN=Domain Admins,CN=Users,%s' % base,
            'CN=Enterprise Admins,CN=Users,%s' % base,
            'CN=Administrators,CN=Builtin,%s' % base,
            'CN=Group Policy Creator Owners,CN=Users,%s' % base,
        ]
        
        if self.debug:
            print(f'[DEBUG] Scanning {len(targets)} high-value targets including Configuration NC')
        
        # Add all user objects
        try:
            resp = conn.search(
                searchBase=base,
                searchFilter='(&(objectClass=user)(!(objectClass=computer)))',
                attributes=['distinguishedName'],
                sizeLimit=0,
            )
            user_count = 0
            for entry in resp:
                if 'objectName' in entry:
                    targets.append(entry['objectName'])
                    user_count += 1
            if self.debug:
                print(f'[DEBUG] Added {user_count} users to ACL scan')
        except Exception:
            pass
        
        # Add all group objects
        try:
            resp = conn.search(
                searchBase=base,
                searchFilter='(objectClass=group)',
                attributes=['distinguishedName'],
                sizeLimit=0,
            )
            group_count = 0
            for entry in resp:
                if 'objectName' in entry:
                    targets.append(entry['objectName'])
                    group_count += 1
            if self.debug:
                print(f'[DEBUG] Added {group_count} groups to ACL scan')
        except Exception:
            pass
        
        # Add all OUs
        try:
            resp = conn.search(
                searchBase=base,
                searchFilter='(objectClass=organizationalUnit)',
                attributes=['distinguishedName'],
                sizeLimit=0,
            )
            ou_count = 0
            for entry in resp:
                if 'objectName' in entry:
                    targets.append(entry['objectName'])
                    ou_count += 1
            if self.debug:
                print(f'[DEBUG] Added {ou_count} OUs to ACL scan')
        except Exception:
            pass

        INTERESTING_RIGHTS = {
            0xF01FF: 'GenericAll',
            0x40000: 'GenericWrite',
            0x20: 'WriteProperty',
            0x20000: 'WriteDACL',
            0x80000: 'WriteOwner',
        }

        results = []
        for target_dn in targets:
            target_str = str(target_dn)
            try:
                # For Configuration NC, use distinguishedName filter to get exact object
                if 'Configuration' in target_str:
                    search_filter = f'(distinguishedName={target_dn})'
                else:
                    search_filter = '(objectClass=*)'
                    
                resp = conn.search(
                    searchBase=target_dn,
                    searchFilter=search_filter,
                    attributes=['sAMAccountName', 'nTSecurityDescriptor'],
                    sizeLimit=1,
                )
                for entry in resp:
                    if 'objectName' not in entry:
                        continue
                    try:
                        sd_raw = obj_name = None
                        for a in entry['attributes']:
                            t = str(a['type']).lower()
                            if t == 'ntsecuritydescriptor':
                                v = a['vals'][0]
                                sd_raw = bytes(v) if hasattr(v, '__bytes__') else (v if isinstance(v, bytes) else v.encode('latin-1'))
                            elif t == 'samaccountname':
                                obj_name = str(a['vals'][0])
                        if self.debug and 'Configuration' in target_str:
                            print(f'[DEBUG] Config NC has SD: {sd_raw is not None}')
                        if not sd_raw:
                            if self.debug and 'Configuration' in target_str:
                                print(f'[DEBUG] No SD for Configuration NC')
                            continue
                        obj_name = obj_name or str(target_dn).split(',')[0].replace('CN=', '')
                        if self.debug and 'Configuration' in target_str:
                            print(f'[DEBUG] Config NC obj_name: {obj_name}, has SD')

                        from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
                        sd = SR_SECURITY_DESCRIPTOR(data=sd_raw)
                        if not sd['Dacl']:
                            continue
                        
                        if self.debug and 'Configuration' in target_str:
                            print(f'[DEBUG] Config NC has {len(sd["Dacl"]["Data"])} ACEs')

                        for ace in sd['Dacl']['Data']:
                            try:
                                sid = ace['Ace']['Sid'].formatCanonical()
                                if (not sid.startswith(domain_sid) and
                                        not sid.startswith('S-1-5-32') and
                                        not sid.startswith('S-1-1') and
                                        not sid.startswith('S-1-5-18') and
                                        not sid.startswith('S-1-5-10') and
                                        not sid.startswith('S-1-3') and
                                        sid.startswith('S-1-5-21-')):
                                    mask = ace['Ace']['Mask']['Mask']
                                    if self.debug and 'Configuration' in obj_name:
                                        print(f'[DEBUG] Config NC foreign SID {sid}, mask={hex(mask)}')
                                    for right_mask, right_name in INTERESTING_RIGHTS.items():
                                        if mask & right_mask == right_mask:
                                            results.append({
                                                'object': obj_name,
                                                'object_dn': target_dn,
                                                'trustee_sid': sid,
                                                'right': right_name,
                                            })
                                            break
                            except Exception:
                                pass
                    except Exception:
                        pass
            except Exception:
                pass
        return results

    def enumerate_sid_history(self):
        """Find accounts with sIDHistory set — potential privilege escalation."""
        conn = self._ldap or self._connect()
        base = self._base_dn()
        resp = conn.search(
            searchBase=base,
            searchFilter='(sIDHistory=*)',
            attributes=['sAMAccountName', 'sIDHistory', 'objectClass'],
            sizeLimit=0,
        )
        results = []
        for entry in resp:
            if 'objectName' not in entry:
                continue
            try:
                name = ''
                sids = []
                for a in entry['attributes']:
                    t = str(a['type']).lower()
                    if t == 'samaccountname':
                        name = str(a['vals'][0])
                    elif t == 'sidhistory':
                        for v in a['vals']:
                            try:
                                from impacket.ldap.ldaptypes import LDAP_SID
                                sids.append(LDAP_SID(bytes(v)).formatCanonical())
                            except Exception:
                                sids.append(bytes(v).hex())
                if name and sids:
                    results.append({'name': name, 'sid_history': sids})
            except Exception:
                pass
        return results

    def enumerate_constrained_delegation_across_trust(self, target_domain, target_dc_ip):
        """Find constrained delegation in trusted domain."""
        try:
            sub = TrustEnumerator(
                domain=self.domain, username=self.username, password=self.password,
                lmhash=self.lmhash, nthash=self.nthash, aes_key=self.aes_key,
                use_kerberos=self.use_kerberos, dc_ip=target_dc_ip, debug=self.debug,
            )
            conn = sub._connect()
            base = ','.join('DC=%s' % p for p in target_domain.split('.'))
            resp = conn.search(
                searchBase=base,
                searchFilter='(msDS-AllowedToDelegateTo=*)',
                attributes=['sAMAccountName', 'msDS-AllowedToDelegateTo', 'userAccountControl'],
                sizeLimit=0,
            )
            accounts = []
            for entry in resp:
                if 'objectName' not in entry:
                    continue
                try:
                    name = spns = uac = ''
                    for a in entry['attributes']:
                        t = str(a['type']).lower()
                        if t == 'samaccountname': name = str(a['vals'][0])
                        elif t == 'msds-allowedtodelegateto': spns = [str(v) for v in a['vals']]
                        elif t == 'useraccountcontrol': uac = int(a['vals'][0])
                    protocol_transition = bool(uac & 0x01000000)
                    accounts.append({'name': name, 'spns': spns, 'protocol_transition': protocol_transition})
                except Exception:
                    pass
            return accounts
        except Exception as e:
            logging.debug(f'Cross-trust constrained delegation failed: {e}')
            return []

    def enumerate_rbcd_across_trust(self, target_domain, target_dc_ip):
        """Find RBCD in trusted domain."""
        try:
            sub = TrustEnumerator(
                domain=self.domain, username=self.username, password=self.password,
                lmhash=self.lmhash, nthash=self.nthash, aes_key=self.aes_key,
                use_kerberos=self.use_kerberos, dc_ip=target_dc_ip, debug=self.debug,
            )
            conn = sub._connect()
            base = ','.join('DC=%s' % p for p in target_domain.split('.'))
            resp = conn.search(
                searchBase=base,
                searchFilter='(msDS-AllowedToActOnBehalfOfOtherIdentity=*)',
                attributes=['sAMAccountName', 'msDS-AllowedToActOnBehalfOfOtherIdentity'],
                sizeLimit=0,
            )
            accounts = []
            for entry in resp:
                if 'objectName' not in entry:
                    continue
                try:
                    name = sd_bytes = None
                    for a in entry['attributes']:
                        t = str(a['type']).lower()
                        if t == 'samaccountname': name = str(a['vals'][0])
                        elif t == 'msds-allowedtoactonbehalfofotheridentity':
                            v = a['vals'][0]
                            sd_bytes = bytes(v) if hasattr(v, '__bytes__') else (v if isinstance(v, bytes) else v.encode('latin-1'))
                    if name and sd_bytes:
                        from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
                        sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)
                        sids = []
                        if sd['Dacl']:
                            for ace in sd['Dacl']['Data']:
                                sid = ace['Ace']['Sid'].formatCanonical()
                                resolved = sub._resolve_sid_in_domain(sid, target_domain, target_dc_ip)
                                sids.append(resolved or sid)
                        if sids:
                            accounts.append({'name': name, 'allowed_sids': sids})
                except Exception:
                    pass
            return accounts
        except Exception as e:
            logging.debug(f'Cross-trust RBCD failed: {e}')
            return []

    def enumerate_shadow_principals(self):
        """Find PAM trust shadow principals (msDS-ShadowPrincipal objects in bastion forest)."""
        conn = self._ldap or self._connect()
        base = self._base_dn()
        try:
            resp = conn.search(
                searchBase='CN=Shadow Principal Configuration,CN=Services,CN=Configuration,%s' % base,
                searchFilter='(objectClass=msDS-ShadowPrincipal)',
                attributes=['cn', 'msDS-ShadowPrincipalSid', 'member'],
                sizeLimit=0,
            )
            results = []
            for entry in resp:
                if 'objectName' not in entry:
                    continue
                try:
                    name = members = sid = ''
                    for a in entry['attributes']:
                        t = str(a['type']).lower()
                        if t == 'cn': name = str(a['vals'][0])
                        elif t == 'msds-shadowprincipalsid':
                            try:
                                from impacket.ldap.ldaptypes import LDAP_SID
                                sid = LDAP_SID(bytes(a['vals'][0])).formatCanonical()
                            except Exception:
                                sid = bytes(a['vals'][0]).hex()
                        elif t == 'member':
                            members = [str(v) for v in a['vals']]
                    results.append({'name': name, 'mapped_sid': sid, 'members': members})
                except Exception:
                    pass
            return results
        except Exception:
            return []

    def enumerate_unconstrained_delegation_across_trust(self, target_domain, target_dc_ip):
        """Find unconstrained delegation hosts in a trusted domain."""
        try:
            sub = TrustEnumerator(
                domain=self.domain, username=self.username, password=self.password,
                lmhash=self.lmhash, nthash=self.nthash, aes_key=self.aes_key,
                use_kerberos=self.use_kerberos, dc_ip=target_dc_ip, debug=self.debug,
            )
            conn = sub._connect()
            base = ','.join('DC=%s' % p for p in target_domain.split('.'))
            resp = conn.search(
                searchBase=base,
                searchFilter='(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))',
                attributes=['sAMAccountName', 'dNSHostName', 'userAccountControl'],
                sizeLimit=0,
            )
            results = []
            for entry in resp:
                if 'objectName' not in entry:
                    continue
                try:
                    name = dns = uac = ''
                    for a in entry['attributes']:
                        t = str(a['type']).lower()
                        if t == 'samaccountname': name = str(a['vals'][0])
                        elif t == 'dnshostname': dns = str(a['vals'][0])
                        elif t == 'useraccountcontrol': uac = int(a['vals'][0])
                    is_dc = bool(uac & 0x2000)
                    if name:
                        results.append({'name': name, 'dns': dns, 'is_dc': is_dc})
                except Exception:
                    pass
            return results
        except Exception:
            return []

    def enumerate_foreign_acls_across_trust(self, target_domain, target_dc_ip):
        """Find ACLs in trusted domain where current domain users have permissions."""
        try:
            sub = TrustEnumerator(
                domain=self.domain, username=self.username, password=self.password,
                lmhash=self.lmhash, nthash=self.nthash, aes_key=self.aes_key,
                use_kerberos=self.use_kerberos, dc_ip=target_dc_ip, debug=self.debug,
            )
            conn = sub._connect()
            base = ','.join('DC=%s' % p for p in target_domain.split('.'))
            
            # Get current domain SID to identify foreign principals
            current_domain_sid = self._get_domain_sid()
            if not current_domain_sid:
                return []
            
            # Scan Configuration NC and high-value targets in trusted domain
            config_nc = 'CN=Configuration,%s' % base
            targets = [config_nc, base]
            
            INTERESTING_RIGHTS = {
                0xF01FF: 'GenericAll',
                0x40000: 'GenericWrite',
                0x20: 'WriteProperty',
                0x20000: 'WriteDACL',
                0x80000: 'WriteOwner',
            }
            
            results = []
            for target_dn in targets:
                target_str = str(target_dn)
                try:
                    if 'Configuration' in target_str:
                        search_filter = f'(distinguishedName={target_dn})'
                    else:
                        search_filter = '(objectClass=*)'
                    
                    resp = conn.search(
                        searchBase=target_dn,
                        searchFilter=search_filter,
                        attributes=['nTSecurityDescriptor'],
                        sizeLimit=1,
                    )
                    for entry in resp:
                        if 'objectName' not in entry:
                            continue
                        try:
                            sd_raw = None
                            for a in entry['attributes']:
                                if str(a['type']).lower() == 'ntsecuritydescriptor':
                                    v = a['vals'][0]
                                    sd_raw = bytes(v) if hasattr(v, '__bytes__') else (v if isinstance(v, bytes) else v.encode('latin-1'))
                            if not sd_raw:
                                continue
                            
                            obj_name = str(target_dn).split(',')[0].replace('CN=', '')
                            from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
                            sd = SR_SECURITY_DESCRIPTOR(data=sd_raw)
                            if not sd['Dacl']:
                                continue
                            
                            for ace in sd['Dacl']['Data']:
                                try:
                                    sid = ace['Ace']['Sid'].formatCanonical()
                                    # Check if SID is from current domain (foreign to target domain)
                                    if sid.startswith(current_domain_sid):
                                        mask = ace['Ace']['Mask']['Mask']
                                        for right_mask, right_name in INTERESTING_RIGHTS.items():
                                            if mask & right_mask == right_mask:
                                                results.append({
                                                    'object': obj_name,
                                                    'object_dn': target_dn,
                                                    'trustee_sid': sid,
                                                    'right': right_name,
                                                })
                                                break
                                except Exception:
                                    pass
                        except Exception:
                            pass
                except Exception:
                    pass
            return results
        except Exception:
            return []

    def enumerate_kerberoastable_across_trust(self, target_domain, target_dc_ip):
        """Find Kerberoastable accounts in a trusted domain."""
        try:
            sub = TrustEnumerator(
                domain=self.domain, username=self.username, password=self.password,
                lmhash=self.lmhash, nthash=self.nthash, aes_key=self.aes_key,
                use_kerberos=self.use_kerberos, dc_ip=target_dc_ip, debug=self.debug,
            )
            conn = sub._connect()
            base = ','.join('DC=%s' % p for p in target_domain.split('.'))
            resp = conn.search(
                searchBase=base,
                searchFilter='(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                attributes=['sAMAccountName', 'servicePrincipalName', 'memberOf'],
                sizeLimit=0,
            )
            results = []
            for entry in resp:
                if 'objectName' not in entry:
                    continue
                try:
                    name = spns = ''
                    for a in entry['attributes']:
                        t = str(a['type']).lower()
                        if t == 'samaccountname': name = str(a['vals'][0])
                        elif t == 'serviceprincipalname': spns = [str(v) for v in a['vals']]
                    if name and spns:
                        results.append({'name': name, 'spns': spns})
                except Exception:
                    pass
            return results
        except Exception as e:
            logging.debug(f'Cross-trust Kerberoast failed: {e}')
            if self.debug:
                logging.debug('Kerberoast across trust failed: %s' % e)
            return []

    def enumerate_asreproastable_across_trust(self, target_domain, target_dc_ip):
        """Find ASREPRoastable accounts in a trusted domain."""
        try:
            sub = TrustEnumerator(
                domain=self.domain, username=self.username, password=self.password,
                lmhash=self.lmhash, nthash=self.nthash, aes_key=self.aes_key,
                use_kerberos=self.use_kerberos, dc_ip=target_dc_ip, debug=self.debug,
            )
            conn = sub._connect()
            base = ','.join('DC=%s' % p for p in target_domain.split('.'))
            resp = conn.search(
                searchBase=base,
                searchFilter='(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                attributes=['sAMAccountName'],
                sizeLimit=0,
            )
            results = []
            for entry in resp:
                if 'objectName' not in entry:
                    continue
                try:
                    for a in entry['attributes']:
                        if str(a['type']).lower() == 'samaccountname':
                            results.append(str(a['vals'][0]))
                except Exception:
                    pass
            return results
        except Exception:
            return []

    def _get_domain_sid(self):
        """Get this domain's SID."""
        try:
            conn = self._ldap or self._connect()
            base = self._base_dn()
            resp = conn.search(
                searchBase=base,
                searchFilter='(objectClass=domain)',
                attributes=['objectSid'],
                sizeLimit=1,
            )
            for entry in resp:
                if 'objectName' not in entry:
                    continue
                for a in entry['attributes']:
                    if str(a['type']).lower() == 'objectsid':
                        from impacket.ldap.ldaptypes import LDAP_SID
                        return LDAP_SID(bytes(a['vals'][0])).formatCanonical()
        except Exception:
            pass
        return None


if __name__ == '__main__':
    main()
