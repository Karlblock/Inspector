# cyba-Inspector - CLI Tool for HTB Enumeration & Analysis

A specialized CLI tool designed for Hack The Box enumeration, analysis, and reporting. This tool provides structured enumeration workflows based on machine types and services.

## Features

- **Smart Enumeration**: Service-specific enumeration scripts
- **Machine Profiles**: Pre-configured profiles for different machine types
- **Automated Reporting**: Generate structured reports for findings
- **Extensible Modules**: Easy to add new enumeration techniques
- **Note Management**: Integrated note-taking during enumeration
- **Session Management**: Save and resume enumeration sessions
- **Tor OSINT Module**: Defensive dark web research for threat intelligence
- **Security Focused**: Built-in protections and compliance checks
- **LDAP/AD Enumeration**: Complete Active Directory reconnaissance
- **RDP Analysis**: Remote Desktop vulnerability detection
- **DNS Discovery**: Comprehensive DNS enumeration and subdomain discovery

## Enumeration Modules

| Module | Description | Status |
|--------|-------------|--------|
| nmap | Network scanning and service detection | Stable |
| web | Web application enumeration (gobuster, nikto, whatweb) | Stable |
| smb | SMB/CIFS enumeration (smbclient, enum4linux, smbmap) | Stable |
| ssh | SSH service enumeration | Stable |
| ftp | FTP enumeration and anonymous access testing | Stable |
| ldap | LDAP/AD enumeration, Kerberoasting, AS-REP Roasting | Stable (NEW) |
| rdp | RDP reconnaissance, BlueKeep detection | Stable (NEW) |
| dns | DNS enumeration, zone transfers, subdomain discovery | Stable (NEW) |
| version_scanner | Service version detection and CVE lookup | Stable |
| tor_osint | Dark web OSINT for threat intelligence | Stable |

## Installation

```bash
# Clone or navigate to repository
cd /home/user1/HTB/cyba-Inspector

# Install Python dependencies
pip install -r requirements.txt

# Install system dependencies (Debian/Ubuntu)
sudo apt install -y nmap gobuster smbclient smbmap whatweb dirb \
    ldap-utils dnsutils dnsrecon enum4linux

# Make executable
chmod +x cyba-inspector.py

# Optional: Create symlink for global access
sudo ln -s $(pwd)/cyba-inspector.py /usr/local/bin/cyba-inspector
```

### Quick Start
```bash
# Verify installation
cyba-inspector --help

# List available profiles
cyba-inspector profiles list

# Run your first scan
cyba-inspector enum -t 10.10.10.100 -n "TestMachine" -p linux-basic
```

## Usage

### Basic Commands

```bash
# Start new enumeration
cyba-inspector enum -t <target_ip> -n <machine_name>

# Use specific profile
cyba-inspector enum -t <target_ip> -p windows-ad

# Resume previous session
cyba-inspector resume <session_id>

# Generate report
cyba-inspector report <session_id> -f markdown

# List available profiles
cyba-inspector profiles list
```

### Enumeration Profiles

| Profile | Modules | Use Case |
|---------|---------|----------|
| `basic` | nmap | Quick initial reconnaissance |
| `linux-basic` | nmap, ssh, web, ftp | Standard Linux machines |
| `windows-basic` | nmap, smb, rdp, web | Standard Windows machines |
| `windows-ad` | nmap, smb, ldap, kerberos, rdp, dns | Active Directory environments |
| `web-app` | nmap, web, api, ssl | Web applications |
| `database` | nmap, mysql, postgres, mssql, mongodb | Database servers |
| `quick` | nmap, web | Fast CTF enumeration |
| `full` | All modules | Complete enumeration |

### Examples

**Basic Enumeration**
```bash
# Linux machine
cyba-inspector enum -t 10.10.10.100 -n "Lame" -p linux-basic

# Windows machine with Active Directory
cyba-inspector enum -t 10.10.10.175 -n "Forest" -p windows-ad

# Web application
cyba-inspector enum -t 10.10.10.100 -n "Cronos" -p web-app
```

**Advanced Usage**

```bash
# Full enumeration with auto-detection
cyba-inspector enum -t 10.10.10.100 -n "Cronos" --auto-detect

# Web-focused enumeration
cyba-inspector enum -t 10.10.10.100 -p web-app --ports 80,443,8080

# Quick scan for CTF
cyba-inspector quick -t 10.10.10.100

# Export findings to different formats
cyba-inspector report session_123 -f json -o findings.json
cyba-inspector report session_123 -f html -o report.html

# Tor/Dark Web OSINT (defensive security research)
cyba-inspector tor-osint -t example.com --use-tor
cyba-inspector tor-osint -t example.com --check-hibp --check-shodan
cyba-inspector tor-osint -t example.com --executive-report --include-opsec
```

## Architecture

```
cyba-Inspector/
├── src/
│   ├── enumeration/     # Enumeration modules
│   ├── exploitation/    # Exploitation helpers
│   ├── reporting/       # Report generators
│   └── utils/          # Utility functions
├── templates/          # Report templates
├── config/            # Configuration files
└── scripts/           # Standalone scripts
```

## Contributing

Feel free to add new enumeration modules or improve existing ones. Follow the module template in `src/enumeration/template.py`.

## License

MIT License - Created for educational purposes (HTB/CPTS preparation)