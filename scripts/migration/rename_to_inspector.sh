#!/bin/bash
# Script to rename cyba-inspector to cyba-inspector throughout the project

echo "🔄 Renaming cyba-inspector to cyba-inspector..."

# Function to update references in a file
update_file() {
    local file="$1"
    if [ -f "$file" ]; then
        # Create backup
        cp "$file" "$file.bak"
        
        # Replace cyba-inspector with cyba-inspector (case sensitive)
        sed -i 's/cyba-inspector/cyba-inspector/g' "$file"
        
        # Replace cyba-Inspector with cyba-Inspector (case sensitive)
        sed -i 's/cyba-Inspector/cyba-Inspector/g' "$file"
        
        # Replace CYBA_INSPECTOR with CYBA_INSPECTOR
        sed -i 's/CYBA_INSPECTOR/CYBA_INSPECTOR/g' "$file"
        
        # Replace cyba_inspector with cyba_inspector
        sed -i 's/cyba_inspector/cyba_inspector/g' "$file"
        
        echo "✅ Updated: $file"
    fi
}

# Update all Python files
echo "📝 Updating Python files..."
find . -name "*.py" -type f | while read file; do
    update_file "$file"
done

# Update all Markdown files
echo "📝 Updating Markdown files..."
find . -name "*.md" -type f | while read file; do
    update_file "$file"
done

# Update all shell scripts
echo "📝 Updating shell scripts..."
find . -name "*.sh" -type f | while read file; do
    update_file "$file"
done

# Update specific files
echo "📝 Updating specific files..."
update_file "requirements.txt"
update_file ".env.example"
update_file "setup.cfg"
update_file "cyba"
update_file "cyba-interactive"

# Rename shell scripts
echo "🔄 Renaming shell scripts..."
if [ -f "cyba-inspector-wrapper.sh" ]; then
    mv cyba-inspector-wrapper.sh cyba-inspector-wrapper.sh
    echo "✅ Renamed: cyba-inspector-wrapper.sh → cyba-inspector-wrapper.sh"
fi

# Update the main executable link
echo "🔗 Updating symlinks..."
if [ -L "/usr/local/bin/cyba-inspector" ]; then
    sudo rm /usr/local/bin/cyba-inspector
    sudo ln -sf /home/user1/cyba-Inspector/cyba-inspector.py /usr/local/bin/cyba-inspector
    echo "✅ Updated symlink: /usr/local/bin/cyba-inspector"
fi

# Update configuration directory
echo "📁 Updating configuration directories..."
if [ -d "$HOME/.cyba-inspector" ]; then
    mv "$HOME/.cyba-inspector" "$HOME/.cyba-inspector"
    echo "✅ Renamed: ~/.cyba-inspector → ~/.cyba-inspector"
fi

# Remove backup files
echo "🧹 Cleaning up backup files..."
find . -name "*.bak" -type f -delete

echo "✨ Renaming complete!"
echo ""
echo "⚠️  Important notes:"
echo "1. The project has been renamed from cyba-inspector to cyba-inspector"
echo "2. Configuration directory is now: ~/.cyba-inspector"
echo "3. Command is now: cyba-inspector (instead of cyba-inspector)"
echo "4. Environment variables now use CYBA_INSPECTOR_ prefix"
echo ""
echo "🔧 To complete the setup:"
echo "1. Update your environment variables"
echo "2. Run: source ~/.bashrc"
echo "3. Test with: cyba-inspector --help"