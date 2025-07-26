#!/bin/bash
# Migration script for existing cyba-htb users to cyba-inspector

echo "🔄 Migration Script: cyba-htb → cyba-inspector"
echo "============================================"

# Check if running as the correct user
if [ "$EUID" -eq 0 ]; then 
   echo "❌ Please run this script as a regular user, not as root"
   exit 1
fi

echo "📋 This script will help migrate your existing cyba-htb installation to cyba-inspector"
echo ""

# Step 1: Check for existing installation
echo "🔍 Checking for existing cyba-htb installation..."

if [ -d "$HOME/.cyba-htb" ]; then
    echo "✅ Found existing configuration directory: ~/.cyba-htb"
    
    # Backup existing data
    echo "💾 Creating backup..."
    cp -r "$HOME/.cyba-htb" "$HOME/.cyba-htb.backup.$(date +%Y%m%d_%H%M%S)"
    
    # Migrate configuration
    echo "📁 Migrating configuration directory..."
    mv "$HOME/.cyba-htb" "$HOME/.cyba-inspector"
    echo "✅ Configuration migrated to: ~/.cyba-inspector"
else
    echo "ℹ️  No existing configuration found"
fi

# Step 2: Update environment variables
echo ""
echo "🔧 Updating environment variables..."

# Check common shell configuration files
for config_file in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    if [ -f "$config_file" ]; then
        echo "📝 Updating $config_file..."
        
        # Replace CYBA_HTB with CYBA_INSPECTOR
        sed -i.bak 's/CYBA_HTB/CYBA_INSPECTOR/g' "$config_file"
        
        # Replace cyba-htb with cyba-inspector in PATH and aliases
        sed -i 's/cyba-htb/cyba-inspector/g' "$config_file"
        
        echo "✅ Updated $config_file"
    fi
done

# Step 3: Update symlinks
echo ""
echo "🔗 Updating system symlinks..."

if [ -L "/usr/local/bin/cyba-htb" ]; then
    echo "Found existing symlink: /usr/local/bin/cyba-htb"
    echo "⚠️  Need sudo permission to update system symlink"
    
    sudo rm /usr/local/bin/cyba-htb 2>/dev/null
    
    # Get the directory of this script
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
    
    sudo ln -sf "$SCRIPT_DIR/cyba-inspector.py" /usr/local/bin/cyba-inspector
    echo "✅ Created new symlink: /usr/local/bin/cyba-inspector"
fi

# Step 4: Migrate session data
echo ""
echo "📊 Migrating session data..."

if [ -d "$HOME/.cyba-inspector/sessions" ]; then
    # Update session files to reflect new name
    find "$HOME/.cyba-inspector/sessions" -name "*.json" -type f -exec sed -i 's/cyba-htb/cyba-inspector/g' {} \;
    echo "✅ Session data migrated"
fi

# Step 5: Summary and next steps
echo ""
echo "✨ Migration Complete!"
echo "===================="
echo ""
echo "📋 Summary of changes:"
echo "  • Project renamed: cyba-htb → cyba-inspector"
echo "  • Config directory: ~/.cyba-htb → ~/.cyba-inspector"
echo "  • Command: cyba-htb → cyba-inspector"
echo "  • Environment variables: CYBA_HTB_* → CYBA_INSPECTOR_*"
echo ""
echo "🚀 Next steps:"
echo "  1. Reload your shell configuration:"
echo "     source ~/.bashrc  (or ~/.zshrc if using zsh)"
echo ""
echo "  2. Test the new command:"
echo "     cyba-inspector --help"
echo ""
echo "  3. Update any scripts or documentation that reference cyba-htb"
echo ""
echo "💡 Your old configuration has been backed up to: ~/.cyba-htb.backup.*"
echo ""
echo "Thank you for using cyba-inspector! 🎉"