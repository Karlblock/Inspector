#!/bin/bash
# Setup script for cyba-HTB with virtual environment

echo "🚀 Setting up cyba-HTB environment..."

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
echo "⬆️ Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "📥 Installing dependencies..."
pip install -r requirements.txt

# Create activation script
cat > activate_cyba.sh << 'EOF'
#!/bin/bash
# Activate cyba-HTB environment
source $(dirname "$0")/venv/bin/activate
echo "✅ cyba-HTB environment activated!"
echo "Run: python3 cyba-htb.py interactive"
EOF

chmod +x activate_cyba.sh

# Create direct launcher for interactive mode
cat > cyba-interactive << 'EOF'
#!/bin/bash
# Direct launcher for cyba-HTB interactive mode
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source $DIR/venv/bin/activate
python3 $DIR/cyba-htb.py interactive
EOF

chmod +x cyba-interactive

echo ""
echo "✅ Setup complete!"
echo ""
echo "To use cyba-HTB:"
echo "1. Activate environment: source venv/bin/activate"
echo "2. Run interactive mode: python3 cyba-htb.py interactive"
echo ""
echo "Or use the direct launcher:"
echo "./cyba-interactive"
echo ""