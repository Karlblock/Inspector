# Bug Bounty & CTF Discipline Specialists

Collection complète d'agents spécialisés pour chaque discipline rencontrée en bug bounty et CTF. Chaque agent est un expert dans son domaine avec des connaissances approfondies et des techniques avancées.

## 🌐 Web & API Security

### 🔒 [Web Security Specialist](./web-security-specialist.md)
Expert OWASP Top 10, injection attacks, XSS, CSRF, SSRF. Maîtrise Burp Suite et techniques de bypass WAF.

### 🔌 [API Security Specialist](./api-security-specialist.md)
Spécialiste REST/GraphQL/gRPC, JWT attacks, OAuth flaws, rate limiting bypass, microservices security.

## 📱 Mobile & Applications

### 📲 [Mobile Security Specialist](./mobile-security-specialist.md)
Android/iOS reverse engineering, Frida hooking, SSL pinning bypass, malware analysis mobile.

## ☁️ Cloud & Infrastructure

### ☁️ [Cloud Security Specialist](./cloud-security-specialist.md)
AWS/Azure/GCP security, Kubernetes exploitation, serverless vulnerabilities, cloud-native attacks.

## 🔐 Cryptographie & Forensique

### 🔑 [Cryptography Specialist](./cryptography-specialist.md)
Cryptanalyse appliquée, RSA/AES attacks, hash collisions, side-channel analysis, protocoles crypto.

### 🔍 [Forensics Specialist](./forensics-specialist.md)
Analyse mémoire/disque, steganographie, malware analysis, log correlation, anti-forensics detection.

## 💻 Système & Binaire

### 🛡️ [Binary Exploitation Specialist](./binary-exploitation-specialist.md)
Buffer overflows, ROP chains, heap exploitation, kernel exploits, reverse engineering avancé.

### 🌐 [Network Security Specialist](./network-security-specialist.md)
Protocol exploitation, MITM attacks, wireless security, IDS/IPS evasion, traffic analysis.

## 🔗 Émergent & Spécialisé

### ⛓️ [Blockchain Security Specialist](./blockchain-security-specialist.md)
Smart contract auditing, DeFi exploits, consensus attacks, Web3 security, cross-chain vulnerabilities.

### 🔧 [Hardware/IoT Specialist](./hardware-iot-specialist.md)
Hardware hacking, firmware analysis, side-channel attacks, RF security, embedded exploitation.

## 🖥️ Systèmes d'Exploitation & Intelligence

### 🐧 [Linux/OSINT Specialist](./linux-osint-specialist.md)
Linux privilege escalation, OSINT reconnaissance, open source intelligence, container security, advanced shell techniques.

### 🪟 [Microsoft/AD Specialist](./microsoft-ad-specialist.md)
Active Directory exploitation, Windows security, Kerberos attacks, PowerShell mastery, Azure AD/Office 365.

---

## 🎯 Guide d'Utilisation

### Sélection d'Agent
1. **Identifier le domaine** du challenge ou bug
2. **Choisir le spécialiste** correspondant
3. **Fournir le contexte** spécifique (tools disponibles, contraintes)
4. **Demander une approche** méthodique

### Collaboration Multi-Agents
Certains scénarios nécessitent plusieurs spécialistes :
- **Web + API** : Applications modernes avec backend API
- **Cloud + Container** : Infrastructure cloud-native
- **Binary + Forensics** : Analyse de malware
- **Crypto + Network** : Protocoles sécurisés
- **Mobile + API** : Apps mobiles avec backend

### Workflow Type Bug Bounty
1. **Recon** : Network Security Specialist
2. **Enumeration** : Web/API Security Specialist  
3. **Exploitation** : Spécialiste du domaine identifié
4. **Escalation** : Binary/Cloud selon l'infrastructure
5. **Reporting** : Report Generator (agent principal)

### Workflow Type CTF
1. **Catégorie** : Identifier Web, Pwn, Crypto, etc.
2. **Spécialiste** : Engager l'expert du domaine
3. **Collaboration** : Combiner si multi-disciplinaire
4. **Flag** : Validation et writeup

---

## 📊 Matrice de Compétences

| Discipline | Bug Bounty | CTF | Outils Principaux |
|------------|------------|-----|-------------------|
| Web | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | Burp, SQLMap, XSStrike |
| Mobile | ⭐⭐⭐⭐ | ⭐⭐⭐ | Frida, MobSF, Objection |
| Cloud | ⭐⭐⭐⭐⭐ | ⭐⭐ | ScoutSuite, Pacu, kubectl |
| API | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | Postman, GraphQL Voyager |
| Binary | ⭐⭐ | ⭐⭐⭐⭐⭐ | GDB, IDA, pwntools |
| Crypto | ⭐⭐ | ⭐⭐⭐⭐⭐ | SageMath, hashcat, RsaCtfTool |
| Network | ⭐⭐⭐ | ⭐⭐⭐⭐ | Nmap, Wireshark, Responder |
| Forensics | ⭐⭐ | ⭐⭐⭐⭐ | Volatility, Autopsy, Steghide |
| Blockchain | ⭐⭐⭐⭐ | ⭐⭐⭐ | Slither, Mythril, Foundry |
| Hardware | ⭐⭐ | ⭐⭐⭐ | Logic Analyzer, SDR, JTAG |
| Linux/OSINT | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | LinPEAS, BloodHound, theHarvester |
| Microsoft/AD | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Mimikatz, Rubeus, BloodHound |

---

## 🚀 Quick Start

```bash
# Pour un challenge web avec SQLi potentiel
→ Web Security Specialist

# Pour une app mobile Android à reverser  
→ Mobile Security Specialist

# Pour un smart contract à auditer
→ Blockchain Security Specialist

# Pour un binaire avec protections modernes
→ Binary Exploitation Specialist

# Pour une infrastructure AWS compromise
→ Cloud Security Specialist
```

## 🔄 Mises à Jour
Les agents sont régulièrement mis à jour avec :
- Nouvelles techniques d'exploitation
- Outils émergents
- Tendances bug bounty
- Patterns CTF récents