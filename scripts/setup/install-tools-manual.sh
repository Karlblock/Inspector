#!/bin/bash

# Installation manuelle des outils de sécurité
echo "========================================"
echo "  Installation manuelle des outils HTB  "
echo "========================================"

# Créer un dossier pour les outils
mkdir -p ~/HTB/tools
cd ~/HTB/tools

# 1. enum4linux
echo "[+] Installation d'enum4linux..."
wget https://raw.githubusercontent.com/CiscoCXSecurity/enum4linux/master/enum4linux.pl -O enum4linux
chmod +x enum4linux
sudo cp enum4linux /usr/local/bin/

# 2. smbmap via GitHub
echo "[+] Installation de smbmap..."
git clone https://github.com/ShawnDEvans/smbmap.git
cd smbmap
sudo python3 setup.py install
cd ..

# 3. Nikto
echo "[+] Installation de Nikto..."
git clone https://github.com/sullo/nikto.git
cd nikto/program
sudo cp nikto.pl /usr/local/bin/nikto
sudo cp -r plugins /usr/local/bin/
sudo cp -r templates /usr/local/bin/
sudo cp -r databases /usr/local/bin/
sudo chmod +x /usr/local/bin/nikto
cd ../..

# 4. SecLists
echo "[+] Clonage de SecLists..."
if [ ! -d "/usr/share/seclists" ]; then
    sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists
fi

# 5. Dirb wordlists (alternative)
echo "[+] Téléchargement des wordlists dirb..."
mkdir -p wordlists/dirb
cd wordlists/dirb
wget https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt
wget https://raw.githubusercontent.com/v0re/dirb/master/wordlists/big.txt
sudo mkdir -p /usr/share/wordlists/dirb
sudo cp *.txt /usr/share/wordlists/dirb/
cd ../..

# 6. Installation de dirb depuis source
echo "[+] Installation de dirb..."
wget https://sourceforge.net/projects/dirb/files/dirb/2.22/dirb222.tar.gz
tar -xzf dirb222.tar.gz
cd dirb222
chmod +x configure
./configure
make
sudo make install
cd ..

echo ""
echo "[+] Installation terminée !"
echo ""
echo "Outils installés dans:"
echo "- /usr/local/bin/ (enum4linux, nikto, smbmap)"
echo "- /usr/share/seclists/ (wordlists)"
echo "- /usr/share/wordlists/dirb/ (wordlists dirb)"
echo ""

# Vérification
echo "Vérification des installations:"
echo "------------------------------"
for tool in enum4linux smbmap nikto dirb; do
    if command -v $tool &> /dev/null; then
        echo "✓ $tool installé"
    else
        echo "✗ $tool non trouvé"
    fi
done

# Wordlists
if [ -d "/usr/share/seclists" ]; then
    echo "✓ SecLists installé"
else
    echo "✗ SecLists non trouvé"
fi

if [ -f "/usr/share/wordlists/dirb/common.txt" ]; then
    echo "✓ Wordlists dirb installées"
else
    echo "✗ Wordlists dirb non trouvées"
fi