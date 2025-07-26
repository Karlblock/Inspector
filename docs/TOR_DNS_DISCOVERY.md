# Tor DNS et Découverte d'Adresses - Guide Défensif

## 🔍 Comprendre le système d'adressage Tor

### Architecture des adresses .onion

Les adresses .onion ne sont PAS résolues via DNS traditionnel :

```
DNS Classique:              Tor Hidden Services:
example.com                 3g2upl4pq6kufc4m.onion
   ↓                              ↓
Serveur DNS                 Pas de serveur DNS!
   ↓                              ↓
IP: 93.184.216.34          Clé publique encodée
```

### Types d'adresses .onion

1. **Version 2 (Obsolète)**
   - 16 caractères : `thehiddenwiki.onion`
   - Basé sur RSA-1024
   - ⚠️ Considéré non sécurisé

2. **Version 3 (Actuel)**
   - 56 caractères : `thehiddenwikiv3rarg3kfuqmoysjlpv2ujjjlrqpkrlvz7wi6xzaod.onion`
   - Basé sur ed25519
   - ✅ Recommandé

## 🛡️ Méthodes de découverte défensive

### 1. Moteurs de recherche légitimes

```python
# Configuration pour recherche défensive
SAFE_SEARCH_ENGINES = {
    'ahmia': {
        'clearnet': 'https://ahmia.fi',
        'onion': 'http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion',
        'api': 'https://ahmia.fi/search/?q={query}',
        'filters': ['illegal_content_filter=True']
    },
    'duckduckgo': {
        'onion': 'https://3g2upl4pq6kufc4m.onion',
        'search_pattern': 'site:onion {query}'
    }
}
```

### 2. Outils de découverte défensive

```bash
# OnionScan - Analyse de sécurité
git clone https://github.com/s-rah/onionscan
go build -o onionscan
./onionscan --jsonReport --torProxyAddress=127.0.0.1:9050 target.onion

# Résultats typiques:
# - Technologies détectées
# - Fuites d'informations
# - Vulnérabilités potentielles
```

### 3. Création d'un découvreur défensif

```python
#!/usr/bin/env python3
"""
Defensive Onion Discovery Tool
Pour cyba-Inspector - Usage légal uniquement
"""

import re
import requests
from urllib.parse import urlparse

class DefensiveOnionDiscovery:
    def __init__(self):
        self.session = requests.Session()
        self.session.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        self.onion_pattern = re.compile(r'[a-z2-7]{16,56}\.onion')
        
    def search_brand_abuse(self, brand_terms):
        """
        Recherche d'abus de marque sur Tor
        """
        discovered_onions = set()
        
        # Recherche via Ahmia (légal et filtré)
        for term in brand_terms:
            try:
                # API Ahmia
                response = requests.get(
                    f'https://ahmia.fi/search/?q={term}',
                    headers={'User-Agent': 'Defensive-Security-Bot'}
                )
                
                # Extraire les adresses .onion
                onions = self.onion_pattern.findall(response.text)
                discovered_onions.update(onions)
                
            except Exception as e:
                print(f"Erreur recherche {term}: {e}")
        
        return self.verify_onions(discovered_onions)
    
    def verify_onions(self, onion_list):
        """
        Vérifie la validité et la nature des onions trouvés
        """
        verified = []
        
        for onion in onion_list:
            try:
                # Vérification basique
                url = f'http://{onion}'
                response = self.session.head(url, timeout=10)
                
                if response.status_code < 400:
                    verified.append({
                        'address': onion,
                        'status': 'active',
                        'title': self._get_title(url)
                    })
                    
            except:
                # Site inactif ou inaccessible
                pass
                
        return verified
    
    def _get_title(self, url):
        """Obtient le titre de la page de manière sécurisée"""
        try:
            response = self.session.get(url, timeout=10)
            # Parser sécurisé pour éviter XSS
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            return soup.title.string if soup.title else 'No title'
        except:
            return 'Unable to retrieve'
```

## 🔧 Techniques avancées

### 1. Analyse de liens croisés

```python
def discover_linked_onions(seed_onions):
    """
    Découvre de nouveaux onions via analyse de liens
    """
    discovered = set(seed_onions)
    to_crawl = list(seed_onions)
    
    while to_crawl:
        current = to_crawl.pop(0)
        
        # Obtenir les liens depuis la page
        links = extract_onion_links(current)
        
        # Ajouter les nouveaux
        new_links = links - discovered
        discovered.update(new_links)
        
        # Limiter la profondeur
        if len(discovered) < 100:
            to_crawl.extend(new_links)
    
    return discovered
```

### 2. Monitoring continu

```yaml
# Configuration monitoring défensif
monitoring:
  targets:
    - keyword: "CompanyName"
      check_frequency: 3600
      alert_on: ["new_onion", "brand_mention"]
    
  search_engines:
    - ahmia
    - torch
    
  notifications:
    email: security@company.com
    webhook: https://siem.company.com/tor-alerts
```

### 3. Honeypot .onion

```python
# Créer un piège pour détecter les attaquants
class OnionHoneypot:
    def create_trap_onion(self, organization):
        """
        Crée un faux service .onion pour détecter
        les tentatives d'accès non autorisées
        """
        trap_names = [
            f"{organization}-backup",
            f"{organization}-internal",
            f"{organization}-dev"
        ]
        
        # Configuration Tor Hidden Service
        torrc_config = """
HiddenServiceDir /var/lib/tor/honeypot/
HiddenServicePort 80 127.0.0.1:8080
"""
        
        # Logger tous les accès
        return trap_names
```

## ⚖️ Cadre légal et éthique

### ✅ Utilisations légitimes

1. **Recherche de fuites** de votre organisation
2. **Détection d'usurpation** de marque
3. **Veille sur les menaces** contre votre entreprise
4. **Tests de sécurité** autorisés

### ❌ À éviter absolument

1. **Accès à du contenu illégal**
2. **Interaction avec des criminels**
3. **Téléchargement de contenu douteux**
4. **Partage d'adresses illicites**

## 🚀 Intégration avec cyba-Inspector

```bash
# Ajouter la découverte d'onions à votre scan
cyba-inspector enum -t company.com \
  -p defensive-osint \
  --tor \
  --discover-onions \
  --keywords "company brand product"

# Monitoring continu
cyba-inspector monitor \
  --tor-discovery \
  --interval 3600 \
  --alert-new-onions
```

## 📚 Ressources additionnelles

### Documentation
- [Tor Project - Hidden Services](https://community.torproject.org/onion-services/)
- [OnionScan Documentation](https://github.com/s-rah/onionscan/wiki)
- [Ahmia API](https://ahmia.fi/documentation/)

### Outils recommandés
- **Whonix** : OS sécurisé pour recherche Tor
- **OnionShare** : Partage sécurisé via Tor
- **SecureDrop** : Communication sécurisée

### Formation
- SANS SEC597: Open Source Intelligence
- Dark Web Investigation Certification
- Tor OpSec Training

## 🔒 Checklist de sécurité

Avant toute recherche :
- [ ] Autorisation écrite obtenue
- [ ] VM isolée configurée
- [ ] Tor vérifié et fonctionnel
- [ ] Logs activés et sécurisés
- [ ] Plan d'incident préparé
- [ ] Contact légal disponible

Rappelez-vous : La découverte d'adresses .onion doit toujours servir des objectifs défensifs et légaux.