# Changelog

## [1.0.0] - 2026-04-02

### Added
- Trust enumeration with comprehensive security property analysis
- Cross-trust Kerberoasting detection
- Cross-trust ASREProasting detection
- Unconstrained delegation detection (local and cross-trust)
- Constrained delegation detection (local and cross-trust)
- Resource-Based Constrained Delegation (RBCD) detection
- Foreign ACL scanning (64+ objects per domain)
- Foreign group membership detection
- SID history enumeration
- gMSA account detection
- Shadow principal enumeration (PAM trusts)
- Cross-domain SID resolution
- badChild attack module (ExtraSids via trust key or golden ticket)
- Fixed PAC buffer handling for Windows Server 2022+

### Fixed
- PAC_REQUESTOR buffer preservation (fixes Server 2022 compatibility)
- Cross-trust authentication (use source domain credentials)
- Configuration NC query (exact DN match to avoid sizeLimitExceeded)
- Security descriptor byte conversion for nTSecurityDescriptor
- RBCD security descriptor parsing

### Tested
- Windows Server 2019
- Windows Server 2022
- Parent-child trusts
- Cross-domain enumeration from both directions
- All delegation types
- Foreign ACL detection with 5 test scenarios
- Kerberoasting/ASREProasting across trusts

### Known Issues
- Foreign ACL enumeration requires Domain Admin privileges
- Configuration NC attacks require local SYSTEM access
- CVE-2020-0665 not implemented (planned for v2.0)
- SQL Server link enumeration not implemented (planned for v2.0)
