# 🚀 Quick Start - cyba-Inspector Interactive CLI

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
cyba-inspector> target 10.10.10.10
Target set to: 10.10.10.10
```

### 2. Quick Scan
```bash
cyba-inspector> scan
# Or with options:
cyba-inspector> scan -p 80,443,8080 -sV
```

### 3. Run Enumeration
```bash
# Interactive wizard
cyba-inspector> enum

# Direct profile
cyba-inspector> enum web-app
```

### 4. Session Management
```bash
# List sessions
cyba-inspector> session list

# Create new session
cyba-inspector> session new

# Load session
cyba-inspector> session load abc12345

# Save current session
cyba-inspector> session save
```

### 5. Generate Report
```bash
# Markdown report
cyba-inspector> report markdown

# HTML report to file
cyba-inspector> report html /tmp/report.html
```

## Example Workflow
```bash
cyba-inspector> target 10.10.10.100
cyba-inspector> scan -p 1-10000
cyba-inspector> enum web-app
cyba-inspector> report markdown
cyba-inspector> exit
```

## Tips
- Use TAB for command completion
- Command history saved in ~/.cyba_inspector_history
- Type 'help <command>' for detailed help
- Sessions auto-save when auto_save is enabled

## Debugging
```bash
# Enable debug mode
cyba-inspector> set debug true

# Show current settings
cyba-inspector> show
```