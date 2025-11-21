# Changelog

All notable changes to cyba-Inspector will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2025-01-20

### Added
- **LDAP Enumeration Module** - Complete LDAP/Active Directory enumeration
  - Anonymous bind testing
  - User, group, and computer enumeration
  - Domain Admin discovery
  - Kerberoasting target identification (SPN enumeration)
  - AS-REP Roastable account detection
  - Automatic domain context detection
  - Support for LDAP (389), LDAPS (636), and Global Catalog (3268/3269)

- **RDP Enumeration Module** - Remote Desktop Protocol reconnaissance
  - BlueKeep (CVE-2019-0708) vulnerability detection
  - MS12-020 vulnerability checking
  - Network Level Authentication (NLA) detection
  - SSL/TLS certificate extraction and hostname discovery
  - Encryption level analysis
  - NTLM information gathering
  - Security configuration assessment

- **DNS Enumeration Module** - Comprehensive DNS reconnaissance
  - DNS server version detection
  - Zone transfer (AXFR) attempts
  - A, AAAA, MX, NS, SOA, TXT record enumeration
  - SRV record discovery (Active Directory services)
  - Subdomain enumeration (30+ common prefixes)
  - Reverse DNS lookups
  - SPF and DMARC policy detection
  - DNSRecon integration
  - Nmap DNS script automation

- **Test Suite** - Comprehensive testing for new modules
  - Unit tests for module initialization
  - Inheritance verification
  - Method testing
  - Controller integration tests
  - Dry-run mode testing

- **Documentation** - Extensive documentation for new features
  - NEW_MODULES.md with detailed usage examples
  - Scenario-based usage guides
  - Troubleshooting section
  - Security considerations
  - Performance metrics

### Changed
- Updated `EnumerationController` to include new modules (ldap, rdp, dns)
- Enhanced module imports in `__init__.py`
- Extended profile definitions to leverage new modules

### Technical Details
- Total lines of code added: ~800 lines
- New dependencies: ldap-utils, dnsutils, dnsrecon
- Test coverage: 5/5 tests passing
- Modules registered in controller: 8 total (nmap, web, smb, ssh, ftp, ldap, rdp, dns)

## [1.0.0] - 2025-01-15

### Added
- Initial release of cyba-Inspector
- Core enumeration framework with BaseModule architecture
- Nmap enumeration module
- Web enumeration module (gobuster, nikto, whatweb)
- SMB enumeration module (smbclient, enum4linux, smbmap)
- SSH enumeration module
- FTP enumeration module
- Version scanner module
- Tor OSINT module for dark web reconnaissance
- Session management system
- Report generation (Markdown, HTML, JSON)
- Profile system (basic, linux-basic, windows-basic, windows-ad, web-app, database)
- Input validation and security features
- GitBook integration
- Interactive mode with cmd2/rich
- HTB questions helper

### Security
- Command injection prevention with shlex.quote()
- Input validation for IPs, ports, domains, paths
- No hardcoded credentials
- Environment-based configuration
- Path traversal protection

## [Unreleased]

### Planned
- SSL/TLS enumeration module
- MySQL enumeration module
- PostgreSQL enumeration module
- MSSQL enumeration module
- MongoDB enumeration module
- Kerberos enumeration module
- API enumeration module
- Parallel module execution
- Enhanced logging system with structured logs
- Performance optimizations and caching
- Web dashboard for results visualization
- Plugin system for custom modules
- CI/CD integration
- Extended test coverage (target: 80%)

---

## Version Naming Convention

- **Major version** (1.x.x): Breaking changes or significant architecture changes
- **Minor version** (x.1.x): New features, modules, or significant enhancements
- **Patch version** (x.x.1): Bug fixes, documentation updates, small improvements

## Module Status

| Module | Status | Version Added |
|--------|--------|---------------|
| nmap |  Stable | 1.0.0 |
| web |  Stable | 1.0.0 |
| smb |  Stable | 1.0.0 |
| ssh |  Stable | 1.0.0 |
| ftp |  Stable | 1.0.0 |
| ldap |  Stable | 1.0.1 |
| rdp |  Stable | 1.0.1 |
| dns |  Stable | 1.0.1 |
| version_scanner |  Stable | 1.0.0 |
| tor_osint |  Stable | 1.0.0 |
| ssl |  Planned | TBD |
| mysql |  Planned | TBD |
| postgres |  Planned | TBD |
| mssql |  Planned | TBD |
| mongodb |  Planned | TBD |
| kerberos |  Planned | TBD |
| api |  Planned | TBD |

---

## Contributors

- **Karl Block** - Initial work and development
- **Community** - Bug reports and feature requests welcome

## Support

For issues, questions, or feature requests:
- GitHub Issues: [github.com/Karlblock/cyba-Inspector](https://github.com/Karlblock/cyba-Inspector)
- Documentation: `/docs` directory
- Examples: `/examples` directory
