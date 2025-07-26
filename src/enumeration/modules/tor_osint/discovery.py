"""
Onion Discovery Engine - Advanced discovery capabilities for Tor hidden services
"""

import re
import json
import asyncio
import hashlib
from typing import Dict, List, Set, Optional, Tuple
from datetime import datetime
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import Levenshtein
from concurrent.futures import ThreadPoolExecutor, as_completed

from ....utils.logger import Logger
from ....utils.validators import InputValidator


class OnionDiscoveryEngine:
    """
    Advanced engine for discovering and classifying .onion addresses
    """
    
    def __init__(self):
        self.logger = Logger(__name__)
        self.validator = InputValidator()
        self.session = self._create_tor_session()
        
        # Regex patterns for onion addresses
        self.onion_v2_pattern = re.compile(r'[a-z2-7]{16}\.onion', re.IGNORECASE)
        self.onion_v3_pattern = re.compile(r'[a-z2-7]{56}\.onion', re.IGNORECASE)
        self.onion_pattern = re.compile(r'[a-z2-7]{16,56}\.onion', re.IGNORECASE)
        
        # Search engines and directories
        self.search_engines = {
            'ahmia': {
                'url': 'https://ahmia.fi/search/',
                'onion': 'http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/',
                'params': {'q': ''},
                'parser': self._parse_ahmia
            },
            'torch': {
                'url': 'http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion/search',
                'params': {'query': '', 'action': 'search'},
                'parser': self._parse_torch
            },
            'excavator': {
                'url': 'http://2fd6cemt4gmccflhm6imvdfvli3nf7zn6rfrwpsy7uhxrgbypvwf5fad.onion/search/',
                'params': {'q': ''},
                'parser': self._parse_excavator
            }
        }
        
        # Classification categories
        self.classification_rules = {
            'legitimate': {
                'keywords': ['official', 'mirror', 'news', 'journalism', 'whistleblow'],
                'patterns': [r'(bbc|nytimes|propublica|securedrop)'],
                'score_weight': 1.0
            },
            'suspicious': {
                'keywords': ['fake', 'phishing', 'scam', 'clone'],
                'patterns': [r'(paypal|amazon|ebay|bank).*login'],
                'score_weight': -0.5
            },
            'malicious': {
                'keywords': ['market', 'drugs', 'weapons', 'hack', 'exploit'],
                'patterns': [r'(market|shop|store).*(drug|weapon|hack)'],
                'score_weight': -1.0
            }
        }
        
    def _create_tor_session(self) -> requests.Session:
        """Create a requests session configured for Tor"""
        session = requests.Session()
        session.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0'
        })
        return session
    
    def discover_related_onions(self, organization: str, 
                              deep_search: bool = False,
                              include_variations: bool = True) -> Dict:
        """
        Discover onion addresses potentially related to the organization
        """
        self.logger.info(f"Starting onion discovery for: {organization}")
        
        discoveries = {
            'timestamp': datetime.now().isoformat(),
            'organization': organization,
            'search_terms': [],
            'discovered_onions': {
                'legitimate': [],
                'suspicious': [],
                'malicious': [],
                'uncategorized': []
            },
            'statistics': {
                'total_found': 0,
                'unique_onions': 0,
                'search_engines_used': [],
                'variations_checked': 0
            }
        }
        
        # Generate search terms
        search_terms = self._generate_search_terms(organization, include_variations)
        discoveries['search_terms'] = search_terms
        discoveries['statistics']['variations_checked'] = len(search_terms)
        
        # Perform multi-threaded search
        all_onions = set()
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_engine = {}
            
            for engine_name, engine_config in self.search_engines.items():
                for term in search_terms:
                    future = executor.submit(
                        self._search_engine, 
                        engine_name, 
                        engine_config, 
                        term
                    )
                    future_to_engine[future] = (engine_name, term)
            
            for future in as_completed(future_to_engine):
                engine_name, term = future_to_engine[future]
                try:
                    onions = future.result()
                    all_onions.update(onions)
                    self.logger.info(f"Found {len(onions)} onions from {engine_name} for '{term}'")
                except Exception as e:
                    self.logger.error(f"Error searching {engine_name}: {e}")
        
        discoveries['statistics']['total_found'] = len(all_onions)
        discoveries['statistics']['search_engines_used'] = list(self.search_engines.keys())
        
        # Classify discovered onions
        for onion in all_onions:
            classification = self._classify_onion(onion, organization)
            discoveries['discovered_onions'][classification['category']].append({
                'address': onion,
                'classification': classification,
                'discovered_at': datetime.now().isoformat()
            })
        
        # Deep search if requested
        if deep_search:
            self.logger.info("Performing deep search via link analysis")
            deep_results = self._deep_link_analysis(all_onions, organization)
            discoveries['deep_search_results'] = deep_results
        
        discoveries['statistics']['unique_onions'] = len(all_onions)
        
        return discoveries
    
    def _generate_search_terms(self, organization: str, include_variations: bool) -> List[str]:
        """Generate search terms including typosquatting variations"""
        terms = [organization]
        
        if include_variations:
            # Common variations
            variations = [
                organization.lower(),
                organization.upper(),
                organization.replace(' ', ''),
                organization.replace(' ', '-'),
                organization.replace(' ', '_')
            ]
            
            # Typosquatting variations
            typo_variations = self._generate_typosquatting(organization)
            variations.extend(typo_variations)
            
            # Common suffixes/prefixes
            for base in [organization, organization.lower()]:
                variations.extend([
                    f"{base}-official",
                    f"{base}-mirror",
                    f"official-{base}",
                    f"{base}-backup",
                    f"{base}-leak",
                    f"{base}-data",
                    f"{base}shop",
                    f"{base}market"
                ])
            
            terms.extend(variations)
        
        # Remove duplicates and return
        return list(set(terms))
    
    def _generate_typosquatting(self, domain: str) -> List[str]:
        """Generate common typosquatting variations"""
        variations = []
        
        # Character substitution
        substitutions = {
            'a': ['4', '@'],
            'e': ['3'],
            'i': ['1', 'l'],
            'o': ['0'],
            's': ['5', '$'],
            'l': ['1', 'i']
        }
        
        for i, char in enumerate(domain.lower()):
            if char in substitutions:
                for sub in substitutions[char]:
                    variation = domain[:i] + sub + domain[i+1:]
                    variations.append(variation)
        
        # Character omission
        for i in range(len(domain)):
            variation = domain[:i] + domain[i+1:]
            variations.append(variation)
        
        # Character duplication
        for i in range(len(domain)):
            variation = domain[:i] + domain[i] + domain[i] + domain[i+1:]
            variations.append(variation)
        
        # Adjacent character swap
        for i in range(len(domain) - 1):
            chars = list(domain)
            chars[i], chars[i + 1] = chars[i + 1], chars[i]
            variations.append(''.join(chars))
        
        return variations[:20]  # Limit to prevent too many variations
    
    def _search_engine(self, engine_name: str, config: Dict, search_term: str) -> Set[str]:
        """Search a specific engine for onion addresses"""
        onions = set()
        
        try:
            # Prepare request
            params = config['params'].copy()
            if 'q' in params:
                params['q'] = search_term
            elif 'query' in params:
                params['query'] = search_term
            
            # Use onion URL if available and Tor is working
            url = config.get('onion', config['url'])
            
            # Make request
            response = self.session.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                # Parse results using engine-specific parser
                parser = config.get('parser', self._generic_parser)
                found_onions = parser(response.text)
                onions.update(found_onions)
            
        except Exception as e:
            self.logger.error(f"Error searching {engine_name}: {e}")
        
        return onions
    
    def _parse_ahmia(self, html: str) -> Set[str]:
        """Parse Ahmia search results"""
        onions = set()
        soup = BeautifulSoup(html, 'html.parser')
        
        # Find result links
        for result in soup.find_all('cite'):
            text = result.get_text()
            found = self.onion_pattern.findall(text)
            onions.update(found)
        
        return onions
    
    def _parse_torch(self, html: str) -> Set[str]:
        """Parse Torch search results"""
        return self._generic_parser(html)
    
    def _parse_excavator(self, html: str) -> Set[str]:
        """Parse Excavator search results"""
        return self._generic_parser(html)
    
    def _generic_parser(self, html: str) -> Set[str]:
        """Generic parser for finding onion addresses in HTML"""
        # Find all onion addresses in the HTML
        v2_addresses = set(self.onion_v2_pattern.findall(html))
        v3_addresses = set(self.onion_v3_pattern.findall(html))
        
        return v2_addresses.union(v3_addresses)
    
    def _classify_onion(self, onion_address: str, organization: str) -> Dict:
        """Classify an onion address based on various factors"""
        classification = {
            'address': onion_address,
            'category': 'uncategorized',
            'confidence': 0.0,
            'indicators': [],
            'similarity_score': 0.0
        }
        
        # Calculate string similarity to organization name
        base_name = onion_address.split('.')[0]
        similarity = Levenshtein.ratio(organization.lower(), base_name.lower())
        classification['similarity_score'] = similarity
        
        # Check against classification rules
        scores = {'legitimate': 0, 'suspicious': 0, 'malicious': 0}
        
        for category, rules in self.classification_rules.items():
            # Check keywords
            for keyword in rules['keywords']:
                if keyword in base_name.lower():
                    scores[category] += 0.3
                    classification['indicators'].append(f"Keyword: {keyword}")
            
            # Check patterns
            for pattern in rules['patterns']:
                if re.search(pattern, base_name, re.IGNORECASE):
                    scores[category] += 0.5
                    classification['indicators'].append(f"Pattern: {pattern}")
        
        # High similarity to organization name
        if similarity > 0.8:
            scores['suspicious'] += 0.4
            classification['indicators'].append(f"High similarity: {similarity:.2f}")
        elif similarity > 0.6:
            scores['legitimate'] += 0.2
            classification['indicators'].append(f"Moderate similarity: {similarity:.2f}")
        
        # Determine category based on scores
        if scores['malicious'] > 0.5:
            classification['category'] = 'malicious'
            classification['confidence'] = min(scores['malicious'], 1.0)
        elif scores['suspicious'] > 0.3:
            classification['category'] = 'suspicious'
            classification['confidence'] = min(scores['suspicious'], 1.0)
        elif scores['legitimate'] > 0.2:
            classification['category'] = 'legitimate'
            classification['confidence'] = min(scores['legitimate'], 1.0)
        
        return classification
    
    def _deep_link_analysis(self, seed_onions: Set[str], organization: str) -> Dict:
        """Perform deep link analysis to discover more related onions"""
        deep_results = {
            'crawled_onions': 0,
            'new_discoveries': [],
            'link_graph': {},
            'error_count': 0
        }
        
        discovered = set()
        to_crawl = list(seed_onions)[:10]  # Limit initial crawl
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = []
            
            for onion in to_crawl:
                future = executor.submit(self._crawl_onion_links, onion)
                futures.append((future, onion))
            
            for future, source_onion in futures:
                try:
                    links = future.result()
                    deep_results['crawled_onions'] += 1
                    
                    # Filter for new onions
                    new_onions = links - seed_onions - discovered
                    discovered.update(new_onions)
                    
                    if new_onions:
                        deep_results['link_graph'][source_onion] = list(new_onions)
                        
                        for new_onion in new_onions:
                            classification = self._classify_onion(new_onion, organization)
                            deep_results['new_discoveries'].append({
                                'address': new_onion,
                                'found_on': source_onion,
                                'classification': classification
                            })
                    
                except Exception as e:
                    deep_results['error_count'] += 1
                    self.logger.error(f"Error crawling {source_onion}: {e}")
        
        return deep_results
    
    def _crawl_onion_links(self, onion_address: str) -> Set[str]:
        """Crawl an onion site for links to other onions"""
        links = set()
        
        try:
            url = f"http://{onion_address}"
            response = self.session.get(url, timeout=20)
            
            if response.status_code == 200:
                # Parse HTML for onion links
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Check all href attributes
                for tag in soup.find_all(['a', 'link']):
                    href = tag.get('href', '')
                    found = self.onion_pattern.findall(href)
                    links.update(found)
                
                # Check text content
                text_onions = self.onion_pattern.findall(response.text)
                links.update(text_onions)
        
        except Exception as e:
            self.logger.debug(f"Error crawling {onion_address}: {e}")
        
        return links
    
    def check_onion_similarity(self, onion1: str, onion2: str) -> float:
        """Calculate similarity between two onion addresses"""
        base1 = onion1.split('.')[0].lower()
        base2 = onion2.split('.')[0].lower()
        
        return Levenshtein.ratio(base1, base2)
    
    def generate_threat_report(self, discoveries: Dict) -> str:
        """Generate a threat report from discovery results"""
        report = f"""
# Onion Discovery Report
Generated: {discoveries['timestamp']}
Organization: {discoveries['organization']}

## Executive Summary
- Total Unique Onions Found: {discoveries['statistics']['unique_onions']}
- Search Terms Used: {len(discoveries['search_terms'])}
- Search Engines: {', '.join(discoveries['statistics']['search_engines_used'])}

## Classification Results

### 🔴 Malicious ({len(discoveries['discovered_onions']['malicious'])})
"""
        
        for item in discoveries['discovered_onions']['malicious'][:5]:
            report += f"- `{item['address']}`\n"
            report += f"  - Confidence: {item['classification']['confidence']:.2%}\n"
            report += f"  - Indicators: {', '.join(item['classification']['indicators'])}\n"
        
        report += f"""
### 🟡 Suspicious ({len(discoveries['discovered_onions']['suspicious'])})
"""
        
        for item in discoveries['discovered_onions']['suspicious'][:5]:
            report += f"- `{item['address']}`\n"
            report += f"  - Similarity Score: {item['classification']['similarity_score']:.2%}\n"
        
        report += f"""
### 🟢 Legitimate ({len(discoveries['discovered_onions']['legitimate'])})
"""
        
        for item in discoveries['discovered_onions']['legitimate'][:5]:
            report += f"- `{item['address']}`\n"
        
        report += """
## Recommendations

1. **Immediate Actions**:
   - Investigate all suspicious and malicious onions
   - Check for brand impersonation
   - Document evidence for potential takedowns

2. **Monitoring**:
   - Add discovered onions to monitoring list
   - Set up alerts for new similar onions
   - Regular re-scanning recommended

3. **Protection**:
   - Consider registering legitimate mirrors
   - Implement brand protection measures
   - Educate users about official channels
"""
        
        return report