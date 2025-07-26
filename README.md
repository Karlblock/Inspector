# cyba-Inspector - CLI Tool for HTB Enumeration & Analysis

A specialized CLI tool designed for Hack The Box enumeration, analysis, and reporting. This tool provides structured enumeration workflows based on machine types and services.

## Features

- 🔍 **Smart Enumeration**: Service-specific enumeration scripts
- 🎯 **Machine Profiles**: Pre-configured profiles for different machine types
- 📊 **Automated Reporting**: Generate structured reports for findings
- 🛠️ **Extensible Modules**: Easy to add new enumeration techniques
- 📝 **Note Management**: Integrated note-taking during enumeration
- 🔄 **Session Management**: Save and resume enumeration sessions
- 🌐 **Tor OSINT Module**: Defensive dark web research for threat intelligence
- 🛡️ **Security Focused**: Built-in protections and compliance checks

## Installation

```bash
cd /home/user1/HTB/cyba-Inspector
chmod +x cyba-inspector.py
# Optional: Create symlink for global access
sudo ln -s $(pwd)/cyba-inspector.py /usr/local/bin/cyba-inspector
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

- `linux-basic`: Standard Linux enumeration
- `windows-basic`: Standard Windows enumeration
- `windows-ad`: Active Directory focused
- `web-app`: Web application enumeration
- `database`: Database server enumeration
- `custom`: Custom enumeration workflow

### Examples

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