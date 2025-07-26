#!/bin/bash

# cyba-Inspector Installation Script
# Author: Karl Block
# Version: 1.0.0

echo "========================================"
echo "     cyba-Inspector Installation Script       "
echo "========================================"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -eq 0 ]; then
   echo -e "${RED}Please do not run this script as root!${NC}"
   exit 1
fi

# Get the directory of the script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

echo -e "${GREEN}[+] Installing cyba-Inspector...${NC}"

# Make the main script executable
chmod +x "$SCRIPT_DIR/cyba-inspector.py"

# Create symlink
echo -e "${GREEN}[+] Creating symlink...${NC}"
sudo ln -sf "$SCRIPT_DIR/cyba-inspector.py" /usr/local/bin/cyba-inspector

# Create config directory
echo -e "${GREEN}[+] Creating configuration directory...${NC}"
mkdir -p ~/.cyba-inspector/{sessions,config}

# Check for required tools
echo -e "${GREEN}[+] Checking dependencies...${NC}"

REQUIRED_TOOLS="nmap gobuster nikto smbclient enum4linux smbmap whatweb"
MISSING_TOOLS=""

for tool in $REQUIRED_TOOLS; do
    if ! command -v $tool &> /dev/null; then
        MISSING_TOOLS="$MISSING_TOOLS $tool"
    fi
done

if [ -n "$MISSING_TOOLS" ]; then
    echo -e "${YELLOW}[!] Missing tools:${MISSING_TOOLS}${NC}"
    echo -e "${YELLOW}[!] Install them with: sudo apt install${MISSING_TOOLS}${NC}"
else
    echo -e "${GREEN}[+] All required tools are installed${NC}"
fi

# Check for wordlists
echo -e "${GREEN}[+] Checking wordlists...${NC}"

if [ ! -f "/usr/share/wordlists/dirb/common.txt" ]; then
    echo -e "${YELLOW}[!] dirb wordlists not found${NC}"
    echo -e "${YELLOW}[!] Install with: sudo apt install dirb${NC}"
fi

if [ ! -d "/usr/share/seclists" ]; then
    echo -e "${YELLOW}[!] SecLists not found${NC}"
    echo -e "${YELLOW}[!] Install with: sudo apt install seclists${NC}"
fi

echo -e "${GREEN}[+] Installation complete!${NC}"
echo ""
echo "Usage: cyba-inspector --help"
echo ""
echo "Quick start:"
echo "  cyba-inspector enum -t <target_ip> -n <machine_name>"
echo "  cyba-inspector quick -t <target_ip>"
echo ""