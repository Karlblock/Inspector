#!/bin/bash
# Install dependencies for cyba-Inspector

echo "📦 Installing dependencies for cyba-Inspector..."

# Check if we're in a virtual environment
if [[ "$VIRTUAL_ENV" != "" ]]; then
    echo "✅ Virtual environment detected: $VIRTUAL_ENV"
    PIP="$VIRTUAL_ENV/bin/pip"
else
    echo "❌ No virtual environment detected!"
    echo "Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    PIP="venv/bin/pip"
fi

# Upgrade pip first
echo "⬆️ Upgrading pip..."
$PIP install --upgrade pip

# Install core dependencies
echo "📦 Installing core dependencies..."
$PIP install -r requirements.txt

# Install additional Tor OSINT dependencies that might fail
echo "📦 Installing optional dependencies..."
for package in ssdeep tlsh scikit-learn nltk; do
    echo "  - Trying to install $package..."
    $PIP install $package 2>/dev/null || echo "    ⚠️ $package installation failed (optional)"
done

echo ""
echo "✅ Installation complete!"
echo ""
echo "To use cyba-Inspector with all features:"
echo "1. Activate the virtual environment: source venv/bin/activate"
echo "2. Run: cyba-inspector --help"
echo ""
echo "For Tor OSINT features, also install:"
echo "  sudo apt install tor"
echo "  sudo systemctl start tor"