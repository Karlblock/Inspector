# cyba-HTB - CLI Tool for HTB Enumeration & Analysis

A specialized CLI tool designed for Hack The Box enumeration, analysis, and reporting. This tool provides structured enumeration workflows based on machine types and services.

## Features

- 🔍 **Smart Enumeration**: Service-specific enumeration scripts
- 🎯 **Machine Profiles**: Pre-configured profiles for different machine types
- 📊 **Automated Reporting**: Generate structured reports for findings
- 🛠️ **Extensible Modules**: Easy to add new enumeration techniques
- 📝 **Note Management**: Integrated note-taking during enumeration
- 🔄 **Session Management**: Save and resume enumeration sessions

## Installation

```bash
cd /home/user1/HTB/cyba-HTB
chmod +x cyba-htb.py
# Optional: Create symlink for global access
sudo ln -s $(pwd)/cyba-htb.py /usr/local/bin/cyba-htb
```

## Usage

### Basic Commands

```bash
# Start new enumeration
cyba-htb enum -t <target_ip> -n <machine_name>

# Use specific profile
cyba-htb enum -t <target_ip> -p windows-ad

# Resume previous session
cyba-htb resume <session_id>

# Generate report
cyba-htb report <session_id> -f markdown

# List available profiles
cyba-htb profiles list
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
cyba-htb enum -t 10.10.10.100 -n "Cronos" --auto-detect

# Web-focused enumeration
cyba-htb enum -t 10.10.10.100 -p web-app --ports 80,443,8080

# Quick scan for CTF
cyba-htb quick -t 10.10.10.100

# Export findings to different formats
cyba-htb report session_123 -f json -o findings.json
cyba-htb report session_123 -f html -o report.html
```

## Architecture

```
cyba-HTB/
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