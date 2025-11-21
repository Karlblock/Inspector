#!/bin/bash

# Script pour ajouter les dépôts de sécurité
# Compatible avec Kali/Debian/Ubuntu

echo "========================================"
echo "     Configuration des dépôts de sécurité"
echo "========================================"

# Détection de la distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    echo "Impossible de détecter la distribution"
    exit 1
fi

echo "[+] Distribution détectée: $OS $VER"

# Pour Debian/Ubuntu - Ajouter les dépôts Kali
if [[ "$OS" == "debian" ]] || [[ "$OS" == "ubuntu" ]]; then
    echo "[+] Ajout des dépôts Kali Linux pour les outils de sécurité..."
    
    # Backup sources.list
    sudo cp /etc/apt/sources.list /etc/apt/sources.list.backup
    
    # Ajouter la clé GPG de Kali
    wget -q -O - https://archive.kali.org/archive-key.asc | sudo apt-key add -
    
    # Ajouter le dépôt Kali (en priorité basse pour éviter les conflits)
    echo "# Kali Linux repository for security tools" | sudo tee /etc/apt/sources.list.d/kali.list
    echo "deb http://http.kali.org/kali kali-rolling main contrib non-free" | sudo tee -a /etc/apt/sources.list.d/kali.list
    
    # Configurer les priorités pour éviter de casser le système
    echo "Package: *" | sudo tee /etc/apt/preferences.d/kali.pref
    echo "Pin: release o=Kali" | sudo tee -a /etc/apt/preferences.d/kali.pref
    echo "Pin-Priority: 50" | sudo tee -a /etc/apt/preferences.d/kali.pref
    
    echo "[+] Mise à jour des paquets..."
    sudo apt update
    
    echo "[+] Installation des outils de sécurité..."
    # Forcer l'installation depuis Kali avec -t kali-rolling
    sudo apt install -t kali-rolling -y nikto enum4linux dirb seclists smbmap
    
    # Installer smbclient depuis les dépôts normaux
    sudo apt install -y smbclient
    
elif [[ "$OS" == "kali" ]]; then
    echo "[+] Kali Linux détecté, installation directe..."
    sudo apt update
    sudo apt install -y nikto smbclient enum4linux dirb seclists smbmap
fi

# Alternative : Installation manuelle des outils manquants
echo ""
echo "[+] Installation alternative des outils..."

# enum4linux - Installation depuis GitHub
if ! command -v enum4linux &> /dev/null; then
    echo "[+] Installation d'enum4linux depuis GitHub..."
    cd /tmp
    wget https://raw.githubusercontent.com/CiscoCXSecurity/enum4linux/master/enum4linux.pl -O enum4linux
    chmod +x enum4linux
    sudo mv enum4linux /usr/local/bin/
fi

# smbmap - Installation via pipx pour éviter les conflits
if ! command -v smbmap &> /dev/null; then
    echo "[+] Installation de smbmap via pipx..."
    sudo apt install -y pipx
    pipx install smbmap
    pipx ensurepath
fi

# SecLists - Clone depuis GitHub
if [ ! -d "/usr/share/seclists" ]; then
    echo "[+] Clonage de SecLists..."
    sudo git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
fi

echo ""
echo "[!] Configuration terminée !"
echo "[!] Vous devrez peut-être relancer votre terminal pour que les changements prennent effet"
echo ""
echo "Vérification des outils installés:"
for tool in nmap gobuster nikto smbclient enum4linux dirb whatweb; do
    if command -v $tool &> /dev/null; then
        echo "✓ $tool"
    else
        echo "✗ $tool"
    fi
done