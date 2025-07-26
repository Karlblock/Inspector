# 🚀 Quick Start - cyba-HTB Interactive CLI

## Installation
```bash
# Setup environment (only once)
./setup.sh

# Launch interactive mode
./cyba-interactive
```

## Basic Commands

### 1. Set Target
```bash
cyba-htb> target 10.10.10.10
Target set to: 10.10.10.10
```

### 2. Quick Scan
```bash
cyba-htb> scan
# Or with options:
cyba-htb> scan -p 80,443,8080 -sV
```

### 3. Run Enumeration
```bash
# Interactive wizard
cyba-htb> enum

# Direct profile
cyba-htb> enum web-app
```

### 4. Session Management
```bash
# List sessions
cyba-htb> session list

# Create new session
cyba-htb> session new

# Load session
cyba-htb> session load abc12345

# Save current session
cyba-htb> session save
```

### 5. Generate Report
```bash
# Markdown report
cyba-htb> report markdown

# HTML report to file
cyba-htb> report html /tmp/report.html
```

## Example Workflow
```bash
cyba-htb> target 10.10.10.100
cyba-htb> scan -p 1-10000
cyba-htb> enum web-app
cyba-htb> report markdown
cyba-htb> exit
```

## Tips
- Use TAB for command completion
- Command history saved in ~/.cyba_htb_history
- Type 'help <command>' for detailed help
- Sessions auto-save when auto_save is enabled

## Debugging
```bash
# Enable debug mode
cyba-htb> set debug true

# Show current settings
cyba-htb> show
```