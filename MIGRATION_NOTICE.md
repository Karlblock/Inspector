# 🔄 Project Renamed: cyba-htb → cyba-Inspector

## Important Notice

This project has been renamed from **cyba-htb** to **cyba-Inspector** to better reflect its comprehensive security inspection capabilities beyond just Hack The Box.

## What Changed?

### 1. Project Name
- Old: `cyba-htb`
- New: `cyba-Inspector`

### 2. Command Line
- Old: `cyba-htb [command]`
- New: `cyba-inspector [command]`

### 3. Configuration Directory
- Old: `~/.cyba-htb/`
- New: `~/.cyba-inspector/`

### 4. Environment Variables
- Old: `CYBA_HTB_*`
- New: `CYBA_INSPECTOR_*`

### 5. Project Directory
- Recommended to rename: `/home/user1/cyba-HTB` → `/home/user1/cyba-Inspector`

## Migration Steps

### For New Users
Simply use the new name `cyba-inspector` for all commands.

### For Existing Users

1. **Run the migration script:**
   ```bash
   ./migrate_to_inspector.sh
   ```

2. **Reload your shell:**
   ```bash
   source ~/.bashrc  # or ~/.zshrc
   ```

3. **Test the new command:**
   ```bash
   cyba-inspector --help
   ```

## Manual Migration (if needed)

1. **Rename configuration directory:**
   ```bash
   mv ~/.cyba-htb ~/.cyba-inspector
   ```

2. **Update symlink:**
   ```bash
   sudo rm /usr/local/bin/cyba-htb
   sudo ln -sf $(pwd)/cyba-inspector.py /usr/local/bin/cyba-inspector
   ```

3. **Update environment variables in your shell config:**
   - Replace `CYBA_HTB_` with `CYBA_INSPECTOR_`

## Why the Change?

The tool has evolved beyond just Hack The Box enumeration to become a comprehensive security inspection tool with features like:
- Tor/Dark Web OSINT capabilities
- Advanced threat intelligence
- AI-powered analysis
- Multi-platform support

The new name better reflects these expanded capabilities.

## Compatibility

- All existing features remain the same
- Your sessions and data are preserved
- The migration is one-time only

## Support

If you encounter any issues during migration:
1. Check the backup directory: `~/.cyba-htb.backup.*`
2. Review the migration logs
3. Open an issue on the project repository

Thank you for using cyba-Inspector! 🚀