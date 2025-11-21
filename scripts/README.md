# Scripts Directory

This directory contains utility scripts for cyba-Inspector.

## Structure

```
scripts/
├── setup/          # Installation and setup scripts
├── migration/      # Migration and renaming scripts
└── guardian_check.py  # Security guardian script
```

## Setup Scripts

Located in `setup/`:
- `install.sh` - Main installation script
- `install_dependencies.sh` - Install Python dependencies
- `install-tools-manual.sh` - Manual tool installation
- `setup.sh` - Initial setup
- `setup-repos.sh` - Repository setup

## Migration Scripts

Located in `migration/`:
- `migrate_to_inspector.sh` - Migrate from old structure
- `rename_to_inspector.sh` - Rename project files

## Usage

Installation:
```bash
./scripts/setup/install.sh
```

Setup dependencies:
```bash
./scripts/setup/install_dependencies.sh
```

Guardian check:
```bash
python3 scripts/guardian_check.py
```
