# Project Structure

```
cyba-Inspector/
├── cyba-inspector.py           # Main entry point
├── cyba                         # Symlink/wrapper
├── cyba-cli.py                  # CLI wrapper
├── cyba-interactive             # Interactive mode launcher
├── cyba-inspector-wrapper.sh    # Shell wrapper
├── activate_cyba.sh             # Environment activation
│
├── src/                         # Source code
│   ├── enumeration/             # Enumeration modules
│   │   ├── modules/             # Individual scan modules
│   │   │   ├── base.py          # Base module class
│   │   │   ├── nmap.py          # Network scanning
│   │   │   ├── web.py           # Web enumeration
│   │   │   ├── smb.py           # SMB enumeration
│   │   │   ├── ssh.py           # SSH enumeration
│   │   │   ├── ftp.py           # FTP enumeration
│   │   │   ├── ldap.py          # LDAP/AD enumeration (NEW)
│   │   │   ├── rdp.py           # RDP reconnaissance (NEW)
│   │   │   ├── dns.py           # DNS enumeration (NEW)
│   │   │   ├── version_scanner.py
│   │   │   └── tor_osint.py     # Dark web OSINT
│   │   ├── controller.py        # Enumeration orchestration
│   │   └── profiles.py          # Scan profiles
│   │
│   ├── reporting/               # Report generation
│   │   └── generator.py
│   │
│   ├── utils/                   # Utilities
│   │   ├── validators.py        # Input validation
│   │   ├── session.py           # Session management
│   │   ├── config.py            # Configuration
│   │   ├── colors.py            # Terminal colors
│   │   └── banner.py            # CLI banner
│   │
│   ├── integrations/            # External integrations
│   │   └── platform_sync.py
│   │
│   ├── cli/                     # CLI interface
│   │   └── interactive.py
│   │
│   └── htb_questions.py         # HTB question helper
│
├── scripts/                     # Utility scripts
│   ├── setup/                   # Installation scripts
│   │   ├── install.sh
│   │   ├── install_dependencies.sh
│   │   ├── install-tools-manual.sh
│   │   ├── setup.sh
│   │   └── setup-repos.sh
│   ├── migration/               # Migration scripts
│   │   ├── migrate_to_inspector.sh
│   │   └── rename_to_inspector.sh
│   ├── guardian_check.py
│   └── README.md
│
├── rapports/                    # Scan outputs (gitignored)
│   ├── <machine_name>/         # Per-machine reports
│   │   ├── nmap_*.xml
│   │   ├── ldap_*.txt
│   │   ├── rdp_*.txt
│   │   ├── dns_*.txt
│   │   └── <machine>_enum.md
│   ├── README.md
│   └── .gitignore
│
├── tests/                       # Test suite
│   ├── test_validators.py
│   ├── test_integration.py
│   ├── test_new_modules.py      # NEW module tests
│   └── test_workflow.sh
│
├── docs/                        # Documentation
│   ├── NEW_MODULES.md           # New modules guide
│   ├── CLI_INTERACTIVE_MODE.md
│   ├── TOR_OSINT_GUIDE.md
│   └── ...
│
├── agents/                      # Agent configurations
│   ├── disciplines/
│   └── repository-guardian.md
│
├── examples/                    # Usage examples
│   └── tor_osint_example.py
│
├── README.md                    # Main documentation
├── CHANGELOG.md                 # Version history
├── CONTRIBUTING.md              # Contribution guide
├── CLAUDE.md                    # IDE instructions
├── LICENSE                      # License file
├── requirements.txt             # Python dependencies
├── .gitignore                   # Git ignore rules
└── .env.example                 # Environment template
```

## Directory Purpose

### Source Code (`src/`)
Contains all Python source code organized by functionality.

### Scripts (`scripts/`)
Utility scripts organized by purpose:
- `setup/` - Installation and configuration
- `migration/` - Legacy migration tools

### Rapports (`rapports/`)
All scan outputs and reports. Automatically created per target.
This directory is gitignored except for README and .gitignore.

### Tests (`tests/`)
Test suite for validation and integration testing.

### Docs (`docs/`)
Comprehensive documentation for all features.

## Key Files

- `cyba-inspector.py` - Main CLI entry point
- `src/enumeration/controller.py` - Core enumeration logic
- `src/enumeration/modules/base.py` - Module base class
- `src/utils/validators.py` - Security validation
- `rapports/` - All scan outputs (gitignored)

## Data Flow

1. User runs: `cyba-inspector enum -t <IP> -n <name>`
2. Main script creates session in `~/.cyba-inspector/sessions/`
3. Controller loads appropriate profile
4. Modules execute and save to `rapports/<name>/`
5. Report generator creates markdown summary
6. Session saved for resume capability

## Output Locations

- Scan outputs: `rapports/<machine_name>/`
- Session data: `~/.cyba-inspector/sessions/`
- Logs: `.last_session`
- Reports: `rapports/<machine_name>/<machine>_enum.md`

## Installation Locations

Default installation:
- Source: `/path/to/cyba-Inspector/`
- Symlink: `/usr/local/bin/cyba-inspector` (optional)
- Sessions: `~/.cyba-inspector/sessions/`
- Config: `~/.cyba-inspector/config/`
