# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

cyba-HTB is a specialized CLI tool for Hack The Box enumeration, analysis, and reporting. It provides structured enumeration workflows based on machine types and services.

## Development Commands

### Installation & Setup
```bash
# Install Python dependencies
pip install -r requirements.txt

# Install system dependencies (Debian/Ubuntu)
sudo apt install nmap gobuster smbclient smbmap whatweb dirb

# Create global symlink (after moving to /home/user1/cyba-HTB)
sudo ln -sf /home/user1/cyba-HTB/cyba-htb.py /usr/local/bin/cyba-htb
```

### Testing
```bash
# Run unit tests for validators
python3 tests/test_validators.py

# Run integration tests
python3 tests/test_integration.py

# Run comprehensive workflow tests
./tests/test_workflow.sh

# Test specific functionality
cyba-htb enum -t 127.0.0.1 -n test --ports 80,443
```

### Common Development Tasks
```bash
# Quick scan a target
cyba-htb quick -t <IP>

# Full enumeration with profile
cyba-htb enum -t <IP> -n <machine_name> -p <profile>

# Generate report from session
cyba-htb report <session_id> -f markdown

# List available profiles
cyba-htb profiles list
```

## Architecture Overview

### Core Components

1. **Main Entry Point** (`cyba-htb.py`)
   - Handles CLI argument parsing
   - Routes commands to appropriate handlers
   - Manages input validation and error codes

2. **Enumeration System** (`src/enumeration/`)
   - `controller.py`: Orchestrates enumeration workflow
   - `profiles.py`: Defines machine-type specific enumeration profiles
   - `modules/`: Individual enumeration modules (nmap, web, smb, etc.)
   - All modules inherit from `BaseModule` for consistent interface

3. **Session Management** (`src/utils/session.py`)
   - Stores enumeration state in `~/.cyba-htb/sessions/`
   - JSON-based persistence for resumable sessions
   - Tracks findings per module

4. **Security & Validation** (`src/utils/validators.py`)
   - Input validation for IPs, ports, machine names
   - Command sanitization to prevent shell injection
   - Path validation to prevent traversal attacks

5. **Configuration** (`src/utils/config.py`)
   - Environment-based configuration (CYBA_* variables)
   - No hardcoded secrets - uses env vars for API keys
   - Runtime configuration override support

### Module Architecture

Each enumeration module must:
- Inherit from `BaseModule`
- Implement `run(target, session_id, output_dir, **kwargs)`
- Use `execute_command()` for safe subprocess execution
- Return results dictionary for session storage

### Security Considerations

- All user inputs pass through `InputValidator` before use
- Commands use `shlex.quote()` or list-based subprocess calls
- API keys managed via environment variables only
- Exit codes: 0 (success), 1 (validation/error), 2 (missing args)

### Adding New Modules

1. Create file in `src/enumeration/modules/`
2. Inherit from `BaseModule`
3. Implement the `run()` method
4. Add module name to relevant profiles in `profiles.py`

Currently implemented: nmap, web, smb, ssh, ftp, version_scanner
Planned: ldap, kerberos, dns, mysql, postgres, mssql, mongodb, api, ssl, rdp

### Report Generation

Reports support multiple formats (markdown, html, json, pdf) and are generated from session data. The system analyzes findings and can auto-generate documentation structures for different platforms.

## Key Files to Understand

- `src/enumeration/modules/base.py`: Base class for all modules
- `src/enumeration/profiles.py`: Available enumeration profiles
- `src/utils/validators.py`: Input validation logic
- `src/utils/config.py`: Configuration management
- `tests/test_workflow.sh`: Comprehensive test suite