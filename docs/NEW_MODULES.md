# Nouveaux Modules d'Énumération

##  Vue d'ensemble

Trois nouveaux modules d'énumération critiques ont été ajoutés à cyba-Inspector :

1. **LDAP Module** - Énumération Active Directory via LDAP
2. **RDP Module** - Détection et analyse du protocole Remote Desktop
3. **DNS Module** - Énumération DNS complète

---

##  Module LDAP

### Description
Le module LDAP permet l'énumération approfondie des environnements Active Directory via le protocole LDAP/LDAPS.

### Ports Ciblés
- **389** - LDAP (non chiffré)
- **636** - LDAPS (chiffré SSL/TLS)
- **3268** - Global Catalog
- **3269** - Global Catalog SSL

### Fonctionnalités

#### 1. Détection et Contexte
- Détection automatique du domaine DN (Distinguished Name)
- Test de connexion anonyme
- Énumération des naming contexts

#### 2. Énumération des Objets
```bash
# Utilisateurs du domaine
- sAMAccountName
- userPrincipalName
- memberOf
- description
```

```bash
# Groupes du domaine
- Groupes et leurs membres
- Domain Admins
- Groupes privilégiés
```

```bash
# Ordinateurs
- Noms d'hôtes DNS
- Systèmes d'exploitation
```

#### 3. Vecteurs d'Attaque Identifiés

**Kerberoasting**
- Recherche de comptes avec Service Principal Names (SPN)
- Identification des cibles pour extraction de tickets TGS

**AS-REP Roasting**
- Détection des comptes avec `DONT_REQ_PREAUTH`
- Comptes vulnérables à l'extraction de hash sans authentification

#### 4. Outils Utilisés
- `ldapsearch` - Requêtes LDAP natives
- `nmap` - Scripts NSE LDAP
  - `ldap-rootdse`
  - `ldap-search`
  - `ldap-brute`

### Exemple d'Utilisation

```bash
# Avec profil Windows AD
cyba-inspector enum -t 10.10.10.100 -n "Forest" -p windows-ad

# Sortie attendue
[+] LDAP ports detected: 389, 636, 3268
[+] Found 50 user accounts
[!] Potential Kerberoasting targets found!
[!] AS-REP Roastable accounts found!
```

### Fichiers de Sortie
- `ldap_anonymous_bind.txt` - Test de connexion anonyme
- `ldap_naming_contexts.txt` - Contextes de nommage
- `ldap_users.txt` - Liste des utilisateurs
- `ldap_groups.txt` - Liste des groupes
- `ldap_computers.txt` - Liste des ordinateurs
- `ldap_domain_admins.txt` - Membres Domain Admins
- `ldap_spns.txt` - Comptes avec SPN (Kerberoasting)
- `ldap_asrep_roastable.txt` - Comptes AS-REP Roastable

---

##  Module RDP

### Description
Le module RDP effectue une reconnaissance complète du service Remote Desktop Protocol et détecte les vulnérabilités connues.

### Port Ciblé
- **3389** - RDP standard

### Fonctionnalités

#### 1. Détection de Vulnérabilités

**BlueKeep (CVE-2019-0708)**
- Vulnérabilité RCE critique
- Affecte Windows 7, Server 2008 R2 et antérieurs
- Detection automatique avec nmap

**MS12-020**
- Vulnérabilité DoS
- Affecte Windows XP, Server 2003

#### 2. Configuration de Sécurité

**Network Level Authentication (NLA)**
```bash
[+] NLA is enabled          # Sécurisé
[!] NLA may not be enabled  # Vulnérable
```

**Niveau de Chiffrement**
- Détection du chiffrement RDP
- Analyse des protocoles supportés

#### 3. Reconnaissance

**Certificats SSL/TLS**
- Extraction du nom d'hôte depuis le certificat
- Identification du domaine
- Validation de la configuration SSL

**Informations NTLM**
- Extraction du nom NetBIOS
- Nom de domaine
- Version du système

#### 4. Outils Utilisés
- `nmap` avec scripts NSE :
  - `rdp-enum-encryption`
  - `rdp-vuln-ms12-020`
  - `rdp-vuln-cve-2019-0708`
  - `rdp-ntlm-info`
  - `ssl-cert`

### Exemple d'Utilisation

```bash
# Avec profil Windows
cyba-inspector enum -t 10.10.10.100 -n "Blue" -p windows-basic

# Sortie attendue
[+] RDP port 3389 is open
[!] BlueKeep vulnerability detected!
[+] Network Level Authentication (NLA) is enabled
[+] Hostname from certificate: DC01.contoso.local
```

### Fichiers de Sortie
- `rdp_nmap_scripts.txt` - Résultats des scripts nmap
- `rdp_bluekeep_check.txt` - Test BlueKeep
- `rdp_security.txt` - Configuration de sécurité
- `rdp_encryption.txt` - Niveau de chiffrement
- `rdp_certificate.txt` - Informations du certificat

---

##  Module DNS

### Description
Le module DNS effectue une énumération complète du service DNS incluant la découverte de sous-domaines et la détection de mauvaises configurations.

### Port Ciblé
- **53** - DNS (UDP/TCP)

### Fonctionnalités

#### 1. Détection du Service

**Version du Serveur**
- Requête BIND version
- Détection du logiciel serveur
- Identification de versions vulnérables

#### 2. Zone Transfer (AXFR)

```bash
# Test de transfert de zone
dig @10.10.10.100 example.com AXFR

# Si réussi = Exposition complète du domaine
[!] Zone transfer successful! Domain data exposed
```

#### 3. Énumération des Enregistrements

**Enregistrements Standard**
- **A** - Adresses IPv4
- **AAAA** - Adresses IPv6
- **MX** - Serveurs de messagerie
- **NS** - Serveurs de noms
- **SOA** - Autorité de zone
- **TXT** - Enregistrements texte (SPF, DMARC, DKIM)

**Enregistrements SRV (Active Directory)**
```bash
_ldap._tcp.example.com
_kerberos._tcp.example.com
_kpasswd._tcp.example.com
_gc._tcp.example.com  # Global Catalog
```

#### 4. Découverte de Sous-domaines

Liste de 30+ préfixes communs :
```bash
www, mail, ftp, webmail, smtp, pop, ns1, ns2,
admin, portal, api, dev, staging, test, vpn,
ssh, remote, blog, shop, store, support, help,
secure, login, cpanel, backup, mysql, db, sql
```

#### 5. Reverse DNS
- Lookup inversé pour identifier les noms d'hôtes
- Découverte de domaine via PTR records

#### 6. Outils Utilisés
- `dig` - Requêtes DNS détaillées
- `host` - Lookups DNS simples
- `dnsrecon` - Énumération automatisée
- `nmap` avec scripts NSE :
  - `dns-brute`
  - `dns-zone-transfer`
  - `dns-nsid`
  - `dns-recursion`

### Exemple d'Utilisation

```bash
# Avec domaine spécifié
cyba-inspector enum -t 10.10.10.100 -n "Resolute" --domain example.com

# Sortie attendue
[+] Target domain: example.com
[+] DNS port 53 is open
[+] BIND DNS server detected
[+] Zone transfer denied (secure)
[+] Found 15 subdomains
[+] Mail servers found: mail.example.com, smtp.example.com
[+] SPF record found
[+] DMARC policy found
```

### Fichiers de Sortie
- `dns_version.txt` - Version du serveur DNS
- `dns_zone_transfer.txt` - Résultat du transfert de zone
- `dns_a_records.txt` - Enregistrements A
- `dns_mx_records.txt` - Serveurs mail
- `dns_ns_records.txt` - Serveurs de noms
- `dns_txt_records.txt` - Enregistrements TXT (SPF, DMARC)
- `dns_srv_records.txt` - Enregistrements SRV (AD)
- `dns_subdomains.txt` - Sous-domaines découverts
- `dns_reverse_lookup.txt` - Lookup inversé
- `dnsrecon_output.txt` - Sortie DNSRecon complète

---

##  Intégration dans les Profils

Les nouveaux modules sont automatiquement intégrés dans les profils existants :

### windows-ad
```python
modules: ['nmap', 'smb', 'ldap', 'kerberos', 'rdp', 'dns']
```
**Utilisation :** Machines Windows Active Directory

### windows-basic
```python
modules: ['nmap', 'smb', 'rdp', 'web']
```
**Utilisation :** Machines Windows standalone

### full
```python
modules: ['nmap', 'web', 'smb', 'ssh', 'ftp', 'ldap', 'rdp', 'dns', 'ssl']
```
**Utilisation :** Énumération complète

---

##  Prérequis Système

### Outils Requis

```bash
# Installation sur Debian/Ubuntu
sudo apt install -y \
    nmap \
    ldap-utils \
    dnsutils \
    dnsrecon \
    rdesktop \
    freerdp2-x11

# Vérification
which ldapsearch dig nmap xfreerdp
```

### Permissions
Certaines opérations nécessitent des privilèges élevés :
- Scans UDP (DNS) : `sudo` recommandé
- Connexions RDP : utilisateur standard OK

---

##  Scénarios d'Usage

### Scénario 1 : Pentest Active Directory

```bash
# 1. Énumération initiale
cyba-inspector enum -t 10.10.10.175 -n "Forest" -p windows-ad

# 2. Analyse des résultats LDAP
cat Forest/ldap_users.txt | grep -i "admin"
cat Forest/ldap_spns.txt    # Kerberoasting targets

# 3. Vérification RDP
cat Forest/rdp_certificate.txt  # Nom d'hôte du DC

# 4. Énumération DNS
cat Forest/dns_srv_records.txt  # Services AD
```

### Scénario 2 : Machine Windows Standalone

```bash
# 1. Scan rapide
cyba-inspector enum -t 10.10.10.40 -n "Blue" -p windows-basic

# 2. Vérification vulnérabilités RDP
cat Blue/rdp_bluekeep_check.txt
cat Blue/rdp_security.txt
```

### Scénario 3 : Énumération DNS Externe

```bash
# 1. Cible DNS publique
cyba-inspector enum -t 8.8.8.8 --domain example.com -p basic

# 2. Analyse des résultats
cat example_com/dns_subdomains.txt
cat example_com/dns_zone_transfer.txt
cat example_com/dns_txt_records.txt | grep -i "spf\|dmarc"
```

---

##  Considérations de Sécurité

### Légalité
Ces modules sont destinés à :
-  Pentesting autorisé
-  Capture The Flag (HTB, CTF)
-  Environnements de laboratoire
-  Bug bounty avec autorisation
-  **PAS** d'utilisation non autorisée

### Détection
Les activités d'énumération peuvent être détectées par :
- **IDS/IPS** : Signatures pour scans LDAP, RDP, DNS
- **SIEM** : Logs d'authentification échouée
- **EDR** : Comportement anormal

### Bonnes Pratiques
1. Toujours obtenir une autorisation écrite
2. Documenter les scopes et limitations
3. Utiliser des sessions isolées
4. Ne pas effectuer de DoS
5. Respecter les Rate Limits

---

##  Métriques et Performance

### Temps d'Exécution Moyens

| Module | Temps Moyen | Timeout |
|--------|-------------|---------|
| LDAP   | 2-5 min     | 120s par commande |
| RDP    | 1-3 min     | 60s par scan |
| DNS    | 3-8 min     | 300s pour nmap |

### Optimisations Futures
- [ ] Exécution parallèle des modules
- [ ] Cache des résultats DNS
- [ ] Timeout dynamiques
- [ ] Progression en temps réel

---

##  Dépannage

### Module LDAP

**Problème :** "No LDAP ports detected"
```bash
# Vérification manuelle
nc -zv 10.10.10.100 389
nmap -p389,636 10.10.10.100
```

**Problème :** "Transfer failed" pour zone transfer
```bash
# Normal - la plupart des serveurs DNS modernes bloquent AXFR
# Cela indique une configuration sécurisée
```

### Module RDP

**Problème :** "RDP port not detected"
```bash
# Vérification
nmap -p3389 10.10.10.100
telnet 10.10.10.100 3389
```

### Module DNS

**Problème :** "No domain specified"
```bash
# Solution : fournir le domaine explicitement
cyba-inspector enum -t 10.10.10.100 --domain example.com
```

---

##  Références

### LDAP / Active Directory
- [Microsoft LDAP Documentation](https://docs.microsoft.com/en-us/windows/win32/ad/active-directory-ldap)
- [LDAP Filter Syntax](https://ldap.com/ldap-filters/)
- [Kerberoasting Explained](https://www.qomplx.com/qomplx-knowledge-kerberoasting-attacks-explained/)

### RDP
- [BlueKeep CVE-2019-0708](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708)
- [RDP Security Best Practices](https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/security-guidelines)

### DNS
- [DNS Enumeration Techniques](https://owasp.org/www-community/attacks/DNS_Enumeration)
- [DNS Zone Transfer](https://www.acunetix.com/blog/articles/dns-zone-transfers-axfr/)

---

##  Tests de Validation

Pour valider les nouveaux modules :

```bash
# Tests unitaires
python3 tests/test_new_modules.py

# Tests d'intégration
./tests/test_workflow.sh

# Test manuel avec localhost
cyba-inspector enum -t 127.0.0.1 -n "test" -p full
```

---

**Version :** 1.0.0
**Date :** 2025-01-20
**Auteur :** Karl Block
**Statut :**  Production Ready
