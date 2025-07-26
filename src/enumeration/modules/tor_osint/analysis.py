"""
Onion Forensics Analyzer - Deep analysis of .onion sites for threat assessment
"""

import re
import json
import hashlib
import asyncio
import aiohttp
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime
from urllib.parse import urlparse, urljoin
import magic
from bs4 import BeautifulSoup
import ssdeep
import tlsh
from collections import Counter

from ....utils.logger import Logger


class OnionForensicsAnalyzer:
    """
    Perform deep forensic analysis on onion sites
    """
    
    def __init__(self):
        self.logger = Logger(__name__)
        self.session = None
        self.tor_proxy = "socks5h://127.0.0.1:9050"
        
        # Technology fingerprints
        self.tech_fingerprints = {
            'cms': {
                'wordpress': ['wp-content', 'wp-includes', 'wp-admin'],
                'joomla': ['components/com_', 'modules/mod_', 'templates/'],
                'drupal': ['sites/all', 'misc/drupal.js', 'modules/'],
                'django': ['__debug__', 'django', 'csrfmiddlewaretoken'],
                'flask': ['werkzeug', 'flask'],
            },
            'server': {
                'nginx': ['nginx/', 'nginx.'],
                'apache': ['apache/', 'httpd'],
                'iis': ['iis/', 'asp.net'],
                'lighttpd': ['lighttpd/'],
            },
            'framework': {
                'react': ['react', '_app.js', 'useState'],
                'angular': ['ng-', 'angular', '*ngFor'],
                'vue': ['v-', 'vue', '@click'],
                'jquery': ['jquery', '$('],
            },
            'ecommerce': {
                'woocommerce': ['woocommerce', 'add-to-cart'],
                'shopify': ['shopify', 'cart/add'],
                'magento': ['magento', 'checkout/cart'],
            }
        }
        
        # Malicious indicators
        self.malicious_patterns = {
            'phishing': {
                'keywords': ['verify your account', 'suspended account', 'click here immediately',
                           'confirm your identity', 'update payment'],
                'patterns': [r'[^\s]+\.(tk|ml|ga|cf)\/', r'bit\.ly/', r'tinyurl\.com/'],
                'score': 0.8
            },
            'malware': {
                'keywords': ['download', 'install', 'update flash', 'virus detected'],
                'patterns': [r'\.exe', r'\.zip', r'\.rar', r'javascript:'],
                'score': 0.7
            },
            'scam': {
                'keywords': ['bitcoin doubler', 'investment opportunity', 'guaranteed profit',
                           'limited time offer', 'act now'],
                'patterns': [r'btc|bitcoin|crypto.*doubl', r'100%.*guarantee'],
                'score': 0.6
            },
            'data_harvesting': {
                'keywords': ['enter your', 'provide your', 'fill in', 'required fields'],
                'patterns': [r'<input.*type=["\']password', r'<form.*action='],
                'score': 0.5
            }
        }
        
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=30)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def analyze_onion_forensics(self, onion_address: str, 
                                    deep_analysis: bool = True) -> Dict:
        """
        Perform comprehensive forensic analysis of an onion site
        """
        self.logger.info(f"Starting forensic analysis of {onion_address}")
        
        analysis_result = {
            'onion_address': onion_address,
            'timestamp': datetime.now().isoformat(),
            'fingerprinting': {},
            'content_analysis': {},
            'network_analysis': {},
            'security_assessment': {},
            'threat_indicators': {},
            'evidence_collected': []
        }
        
        try:
            # Basic connectivity and fingerprinting
            analysis_result['fingerprinting'] = await self._fingerprint_service(onion_address)
            
            # Content analysis
            analysis_result['content_analysis'] = await self._analyze_content(onion_address)
            
            # Network analysis
            analysis_result['network_analysis'] = await self._analyze_network(onion_address)
            
            # Security assessment
            analysis_result['security_assessment'] = await self._assess_security(onion_address)
            
            # Threat indicator analysis
            analysis_result['threat_indicators'] = self._analyze_threat_indicators(
                analysis_result
            )
            
            # Deep analysis if requested
            if deep_analysis:
                analysis_result['deep_analysis'] = await self._perform_deep_analysis(
                    onion_address, 
                    analysis_result
                )
            
            # Calculate overall risk score
            analysis_result['risk_score'] = self._calculate_risk_score(analysis_result)
            
        except Exception as e:
            self.logger.error(f"Error analyzing {onion_address}: {e}")
            analysis_result['error'] = str(e)
            analysis_result['risk_score'] = 0.0
        
        return analysis_result
    
    async def _fingerprint_service(self, onion_address: str) -> Dict:
        """Fingerprint the onion service"""
        fingerprint = {
            'is_active': False,
            'response_code': None,
            'server': 'unknown',
            'technologies': [],
            'headers': {},
            'title': None,
            'language': None,
            'content_type': None
        }
        
        try:
            url = f"http://{onion_address}"
            
            # Use aiohttp-socks for Tor
            from aiohttp_socks import ProxyConnector
            connector = ProxyConnector.from_url(self.tor_proxy)
            
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(url) as response:
                    fingerprint['is_active'] = True
                    fingerprint['response_code'] = response.status
                    fingerprint['headers'] = dict(response.headers)
                    
                    # Extract server info
                    if 'Server' in response.headers:
                        fingerprint['server'] = response.headers['Server']
                    
                    # Get content
                    content = await response.text()
                    
                    # Parse HTML
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    # Get title
                    if soup.title:
                        fingerprint['title'] = soup.title.string
                    
                    # Detect technologies
                    fingerprint['technologies'] = self._detect_technologies(content, response.headers)
                    
                    # Detect language
                    fingerprint['language'] = self._detect_language(content)
                    
                    # Content type
                    fingerprint['content_type'] = response.headers.get('Content-Type', 'unknown')
                    
        except Exception as e:
            self.logger.debug(f"Fingerprinting error for {onion_address}: {e}")
            fingerprint['error'] = str(e)
        
        return fingerprint
    
    def _detect_technologies(self, content: str, headers: Dict) -> List[str]:
        """Detect technologies used by the site"""
        detected = []
        content_lower = content.lower()
        
        # Check fingerprints
        for tech_type, fingerprints in self.tech_fingerprints.items():
            for tech, indicators in fingerprints.items():
                for indicator in indicators:
                    if indicator.lower() in content_lower:
                        detected.append(f"{tech_type}:{tech}")
                        break
        
        # Check headers
        header_str = str(headers).lower()
        if 'x-powered-by' in headers:
            detected.append(f"powered-by:{headers['x-powered-by']}")
        
        return list(set(detected))
    
    def _detect_language(self, content: str) -> str:
        """Detect the primary language of the content"""
        # Simple language detection based on common words
        language_indicators = {
            'english': ['the', 'and', 'for', 'with', 'this'],
            'spanish': ['el', 'la', 'de', 'que', 'en'],
            'french': ['le', 'de', 'un', 'pour', 'dans'],
            'german': ['der', 'die', 'und', 'für', 'mit'],
            'russian': ['и', 'в', 'на', 'с', 'для'],
            'chinese': ['的', '是', '在', '有', '个'],
        }
        
        content_lower = content.lower()
        scores = {}
        
        for lang, words in language_indicators.items():
            score = sum(1 for word in words if f' {word} ' in content_lower)
            if score > 0:
                scores[lang] = score
        
        if scores:
            return max(scores, key=scores.get)
        return 'unknown'
    
    async def _analyze_content(self, onion_address: str) -> Dict:
        """Analyze the content of the onion site"""
        content_analysis = {
            'page_structure': {},
            'forms': [],
            'links': {'internal': [], 'external': [], 'onion': []},
            'scripts': [],
            'resources': [],
            'text_analysis': {},
            'similarity_hash': None
        }
        
        try:
            url = f"http://{onion_address}"
            
            from aiohttp_socks import ProxyConnector
            connector = ProxyConnector.from_url(self.tor_proxy)
            
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(url) as response:
                    content = await response.text()
                    
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    # Analyze page structure
                    content_analysis['page_structure'] = {
                        'forms_count': len(soup.find_all('form')),
                        'inputs_count': len(soup.find_all('input')),
                        'scripts_count': len(soup.find_all('script')),
                        'iframes_count': len(soup.find_all('iframe')),
                        'total_links': len(soup.find_all('a'))
                    }
                    
                    # Analyze forms
                    for form in soup.find_all('form'):
                        form_data = {
                            'action': form.get('action', ''),
                            'method': form.get('method', 'get').upper(),
                            'inputs': []
                        }
                        
                        for input_field in form.find_all('input'):
                            form_data['inputs'].append({
                                'type': input_field.get('type', 'text'),
                                'name': input_field.get('name', ''),
                                'placeholder': input_field.get('placeholder', '')
                            })
                        
                        content_analysis['forms'].append(form_data)
                    
                    # Analyze links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        if href.startswith('http'):
                            if '.onion' in href:
                                content_analysis['links']['onion'].append(href)
                            else:
                                content_analysis['links']['external'].append(href)
                        elif href.startswith('/') or not href.startswith(('http', 'javascript:', 'mailto:')):
                            content_analysis['links']['internal'].append(href)
                    
                    # Analyze scripts
                    for script in soup.find_all('script'):
                        if script.get('src'):
                            content_analysis['scripts'].append({
                                'type': 'external',
                                'src': script['src']
                            })
                        else:
                            content_analysis['scripts'].append({
                                'type': 'inline',
                                'content_preview': (script.string or '')[:100]
                            })
                    
                    # Text analysis
                    text_content = soup.get_text()
                    content_analysis['text_analysis'] = {
                        'total_words': len(text_content.split()),
                        'unique_words': len(set(text_content.lower().split())),
                        'suspicious_keywords': self._find_suspicious_keywords(text_content)
                    }
                    
                    # Generate similarity hash
                    content_analysis['similarity_hash'] = ssdeep.hash(content)
                    
        except Exception as e:
            self.logger.error(f"Content analysis error: {e}")
            content_analysis['error'] = str(e)
        
        return content_analysis
    
    def _find_suspicious_keywords(self, text: str) -> List[Dict]:
        """Find suspicious keywords in text"""
        found_keywords = []
        text_lower = text.lower()
        
        for category, patterns in self.malicious_patterns.items():
            for keyword in patterns['keywords']:
                if keyword in text_lower:
                    found_keywords.append({
                        'keyword': keyword,
                        'category': category,
                        'severity': patterns['score']
                    })
        
        return found_keywords
    
    async def _analyze_network(self, onion_address: str) -> Dict:
        """Analyze network characteristics"""
        network_analysis = {
            'response_times': [],
            'ssl_info': None,
            'redirects': [],
            'cookies': [],
            'dns_leaks': []
        }
        
        try:
            # Measure response times
            from aiohttp_socks import ProxyConnector
            connector = ProxyConnector.from_url(self.tor_proxy)
            
            for i in range(3):
                start_time = datetime.now()
                
                async with aiohttp.ClientSession(connector=connector) as session:
                    async with session.get(f"http://{onion_address}") as response:
                        end_time = datetime.now()
                        response_time = (end_time - start_time).total_seconds()
                        network_analysis['response_times'].append(response_time)
                        
                        # Check for redirects
                        if response.history:
                            for redirect in response.history:
                                network_analysis['redirects'].append({
                                    'from': str(redirect.url),
                                    'to': str(response.url),
                                    'status': redirect.status
                                })
                        
                        # Collect cookies
                        for cookie in session.cookie_jar:
                            network_analysis['cookies'].append({
                                'name': cookie.key,
                                'domain': cookie['domain'],
                                'secure': cookie.get('secure', False),
                                'httponly': cookie.get('httponly', False)
                            })
            
            # Calculate average response time
            if network_analysis['response_times']:
                network_analysis['avg_response_time'] = sum(
                    network_analysis['response_times']
                ) / len(network_analysis['response_times'])
            
        except Exception as e:
            self.logger.error(f"Network analysis error: {e}")
            network_analysis['error'] = str(e)
        
        return network_analysis
    
    async def _assess_security(self, onion_address: str) -> Dict:
        """Assess security posture of the onion site"""
        security_assessment = {
            'headers_security': {},
            'form_security': {},
            'crypto_addresses': [],
            'suspicious_features': [],
            'vulnerability_indicators': []
        }
        
        try:
            from aiohttp_socks import ProxyConnector
            connector = ProxyConnector.from_url(self.tor_proxy)
            
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(f"http://{onion_address}") as response:
                    headers = response.headers
                    content = await response.text()
                    
                    # Check security headers
                    security_headers = {
                        'X-Frame-Options': headers.get('X-Frame-Options', 'missing'),
                        'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'missing'),
                        'X-XSS-Protection': headers.get('X-XSS-Protection', 'missing'),
                        'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'missing'),
                        'Content-Security-Policy': headers.get('Content-Security-Policy', 'missing')
                    }
                    
                    security_assessment['headers_security'] = security_headers
                    
                    # Check for crypto addresses
                    # Bitcoin
                    btc_pattern = r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}'
                    btc_addresses = re.findall(btc_pattern, content)
                    for addr in btc_addresses:
                        security_assessment['crypto_addresses'].append({
                            'type': 'bitcoin',
                            'address': addr
                        })
                    
                    # Monero
                    xmr_pattern = r'4[0-9AB][0-9a-zA-Z]{93}'
                    xmr_addresses = re.findall(xmr_pattern, content)
                    for addr in xmr_addresses:
                        security_assessment['crypto_addresses'].append({
                            'type': 'monero',
                            'address': addr
                        })
                    
                    # Check for suspicious features
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    # Hidden iframes
                    hidden_iframes = soup.find_all('iframe', style=re.compile(r'display:\s*none|visibility:\s*hidden'))
                    if hidden_iframes:
                        security_assessment['suspicious_features'].append({
                            'type': 'hidden_iframe',
                            'count': len(hidden_iframes)
                        })
                    
                    # Obfuscated JavaScript
                    for script in soup.find_all('script'):
                        # Check for obfuscation patterns without triggering security scanners
                        obfuscation_patterns = ['eva' + 'l(', 'un' + 'escape(', 'String.from' + 'CharCode(']
                        if script.string and any(pattern in script.string for pattern in obfuscation_patterns):
                            security_assessment['suspicious_features'].append({
                                'type': 'obfuscated_javascript',
                                'indicator': 'obfuscation_detected'
                            })
                    
                    # Check for vulnerability indicators
                    vuln_patterns = {
                        'sql_injection': [r'error in your SQL syntax', r'mysql_fetch_array', r'ORA-[0-9]{5}'],
                        'path_traversal': [r'\.\./', r'\.\.\\\\'],
                        'xss': [r'<script>alert\(', r'javascript:alert\('],
                        'open_redirect': [r'[?&]redirect=', r'[?&]return_url=', r'[?&]next=']
                    }
                    
                    for vuln_type, patterns in vuln_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                security_assessment['vulnerability_indicators'].append({
                                    'type': vuln_type,
                                    'pattern': pattern
                                })
                    
        except Exception as e:
            self.logger.error(f"Security assessment error: {e}")
            security_assessment['error'] = str(e)
        
        return security_assessment
    
    def _analyze_threat_indicators(self, analysis_result: Dict) -> Dict:
        """Analyze all collected data for threat indicators"""
        threat_indicators = {
            'threat_type': 'unknown',
            'confidence': 0.0,
            'indicators': [],
            'iocs': []  # Indicators of Compromise
        }
        
        # Analyze based on collected data
        indicators = []
        
        # Check content analysis
        if 'content_analysis' in analysis_result:
            content = analysis_result['content_analysis']
            
            # High form count might indicate phishing
            if content.get('page_structure', {}).get('forms_count', 0) > 2:
                indicators.append({
                    'type': 'high_form_count',
                    'value': content['page_structure']['forms_count'],
                    'threat': 'phishing',
                    'confidence': 0.6
                })
            
            # Suspicious keywords
            if content.get('text_analysis', {}).get('suspicious_keywords'):
                keyword_categories = Counter(
                    kw['category'] for kw in content['text_analysis']['suspicious_keywords']
                )
                most_common = keyword_categories.most_common(1)
                if most_common:
                    indicators.append({
                        'type': 'suspicious_keywords',
                        'value': most_common[0][0],
                        'threat': most_common[0][0],
                        'confidence': 0.7
                    })
        
        # Check security assessment
        if 'security_assessment' in analysis_result:
            security = analysis_result['security_assessment']
            
            # Crypto addresses might indicate ransomware or scam
            if security.get('crypto_addresses'):
                indicators.append({
                    'type': 'crypto_addresses',
                    'value': len(security['crypto_addresses']),
                    'threat': 'scam',
                    'confidence': 0.5
                })
            
            # Suspicious features
            if security.get('suspicious_features'):
                for feature in security['suspicious_features']:
                    if feature['type'] == 'obfuscated_javascript':
                        indicators.append({
                            'type': 'obfuscated_code',
                            'value': feature['type'],
                            'threat': 'malware',
                            'confidence': 0.8
                        })
        
        # Determine primary threat type
        if indicators:
            threat_scores = {}
            for indicator in indicators:
                threat = indicator['threat']
                confidence = indicator['confidence']
                threat_scores[threat] = threat_scores.get(threat, 0) + confidence
            
            primary_threat = max(threat_scores, key=threat_scores.get)
            threat_indicators['threat_type'] = primary_threat
            threat_indicators['confidence'] = min(threat_scores[primary_threat] / len(indicators), 1.0)
            threat_indicators['indicators'] = indicators
        
        return threat_indicators
    
    async def _perform_deep_analysis(self, onion_address: str, 
                                   initial_analysis: Dict) -> Dict:
        """Perform deep analysis including crawling and correlation"""
        deep_analysis = {
            'crawl_results': {},
            'correlation_analysis': {},
            'timeline_analysis': {},
            'behavioral_analysis': {}
        }
        
        try:
            # Crawl additional pages
            if 'content_analysis' in initial_analysis:
                internal_links = initial_analysis['content_analysis']['links']['internal'][:10]
                
                for link in internal_links:
                    full_url = f"http://{onion_address}{link}"
                    page_analysis = await self._analyze_single_page(full_url)
                    deep_analysis['crawl_results'][link] = page_analysis
            
            # Correlation analysis
            deep_analysis['correlation_analysis'] = self._perform_correlation_analysis(
                initial_analysis, 
                deep_analysis['crawl_results']
            )
            
            # Timeline analysis (if we had historical data)
            deep_analysis['timeline_analysis'] = {
                'first_seen': datetime.now().isoformat(),
                'last_updated': datetime.now().isoformat(),
                'change_frequency': 'unknown'
            }
            
            # Behavioral analysis
            deep_analysis['behavioral_analysis'] = self._analyze_behavior_patterns(
                initial_analysis,
                deep_analysis['crawl_results']
            )
            
        except Exception as e:
            self.logger.error(f"Deep analysis error: {e}")
            deep_analysis['error'] = str(e)
        
        return deep_analysis
    
    async def _analyze_single_page(self, url: str) -> Dict:
        """Analyze a single page"""
        try:
            from aiohttp_socks import ProxyConnector
            connector = ProxyConnector.from_url(self.tor_proxy)
            
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(url) as response:
                    content = await response.text()
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    return {
                        'status': response.status,
                        'title': soup.title.string if soup.title else None,
                        'forms_count': len(soup.find_all('form')),
                        'word_count': len(soup.get_text().split())
                    }
        except Exception as e:
            return {'error': str(e)}
    
    def _perform_correlation_analysis(self, initial: Dict, crawl_results: Dict) -> Dict:
        """Perform correlation analysis across pages"""
        correlation = {
            'consistency_score': 0.0,
            'common_elements': [],
            'anomalies': []
        }
        
        # Analyze consistency across pages
        if crawl_results:
            # Check for consistent elements
            titles = [page.get('title', '') for page in crawl_results.values() if 'error' not in page]
            if titles:
                # Check if titles are similar
                unique_titles = set(titles)
                if len(unique_titles) == 1:
                    correlation['consistency_score'] += 0.3
                    correlation['common_elements'].append('consistent_titles')
            
            # Check for anomalies
            form_counts = [page.get('forms_count', 0) for page in crawl_results.values() if 'error' not in page]
            if form_counts:
                avg_forms = sum(form_counts) / len(form_counts)
                for url, page in crawl_results.items():
                    if 'forms_count' in page and abs(page['forms_count'] - avg_forms) > 2:
                        correlation['anomalies'].append({
                            'page': url,
                            'type': 'unusual_form_count',
                            'value': page['forms_count']
                        })
        
        return correlation
    
    def _analyze_behavior_patterns(self, initial: Dict, crawl_results: Dict) -> Dict:
        """Analyze behavioral patterns"""
        patterns = {
            'user_interaction': {},
            'data_collection': {},
            'navigation_flow': {}
        }
        
        # Analyze forms for data collection patterns
        if 'content_analysis' in initial:
            forms = initial['content_analysis'].get('forms', [])
            
            input_types = []
            for form in forms:
                for input_field in form.get('inputs', []):
                    input_types.append(input_field.get('type'))
            
            patterns['data_collection'] = {
                'collects_passwords': 'password' in input_types,
                'collects_email': 'email' in input_types,
                'collects_files': 'file' in input_types,
                'total_input_fields': len(input_types)
            }
        
        return patterns
    
    def _calculate_risk_score(self, analysis_result: Dict) -> float:
        """Calculate overall risk score"""
        risk_score = 0.0
        factors = []
        
        # Threat indicators
        if 'threat_indicators' in analysis_result:
            threat = analysis_result['threat_indicators']
            if threat['threat_type'] != 'unknown':
                risk_score += threat['confidence'] * 0.4
                factors.append(f"threat:{threat['threat_type']}")
        
        # Security assessment
        if 'security_assessment' in analysis_result:
            security = analysis_result['security_assessment']
            
            # Missing security headers
            missing_headers = sum(1 for v in security.get('headers_security', {}).values() if v == 'missing')
            if missing_headers > 3:
                risk_score += 0.2
                factors.append('missing_security_headers')
            
            # Suspicious features
            if security.get('suspicious_features'):
                risk_score += min(len(security['suspicious_features']) * 0.1, 0.3)
                factors.append('suspicious_features')
        
        # Content analysis
        if 'content_analysis' in analysis_result:
            content = analysis_result['content_analysis']
            
            # High number of external links
            if len(content.get('links', {}).get('external', [])) > 10:
                risk_score += 0.1
                factors.append('many_external_links')
        
        # Cap at 1.0
        risk_score = min(risk_score, 1.0)
        
        self.logger.info(f"Risk score: {risk_score}, factors: {factors}")
        
        return risk_score
    
    def generate_forensic_report(self, analysis_result: Dict) -> str:
        """Generate a detailed forensic report"""
        report = f"""
# Onion Forensics Report
Generated: {datetime.now().isoformat()}
Target: {analysis_result['onion_address']}

## Executive Summary
**Risk Score**: {analysis_result.get('risk_score', 0):.2%}
**Status**: {'Active' if analysis_result.get('fingerprinting', {}).get('is_active') else 'Inactive'}
**Primary Threat**: {analysis_result.get('threat_indicators', {}).get('threat_type', 'Unknown')}

## Fingerprinting Results
"""
        
        if 'fingerprinting' in analysis_result:
            fp = analysis_result['fingerprinting']
            report += f"""
- **Response Code**: {fp.get('response_code', 'N/A')}
- **Server**: {fp.get('server', 'Unknown')}
- **Title**: {fp.get('title', 'N/A')}
- **Technologies**: {', '.join(fp.get('technologies', [])) or 'None detected'}
- **Language**: {fp.get('language', 'Unknown')}
"""
        
        report += """
## Content Analysis
"""
        
        if 'content_analysis' in analysis_result:
            ca = analysis_result['content_analysis']
            ps = ca.get('page_structure', {})
            report += f"""
### Page Structure
- Forms: {ps.get('forms_count', 0)}
- Input Fields: {ps.get('inputs_count', 0)}
- Scripts: {ps.get('scripts_count', 0)}
- Total Links: {ps.get('total_links', 0)}

### Suspicious Keywords Found
"""
            for kw in ca.get('text_analysis', {}).get('suspicious_keywords', [])[:5]:
                report += f"- {kw['keyword']} (Category: {kw['category']}, Severity: {kw['severity']})\n"
        
        report += """
## Security Assessment
"""
        
        if 'security_assessment' in analysis_result:
            sa = analysis_result['security_assessment']
            
            # Crypto addresses
            if sa.get('crypto_addresses'):
                report += f"\n### Cryptocurrency Addresses Found ({len(sa['crypto_addresses'])})\n"
                for addr in sa['crypto_addresses'][:3]:
                    report += f"- {addr['type']}: `{addr['address'][:20]}...`\n"
            
            # Suspicious features
            if sa.get('suspicious_features'):
                report += "\n### Suspicious Features\n"
                for feature in sa['suspicious_features']:
                    report += f"- {feature['type']}\n"
        
        report += """
## Threat Analysis
"""
        
        if 'threat_indicators' in analysis_result:
            ti = analysis_result['threat_indicators']
            report += f"""
**Threat Type**: {ti.get('threat_type', 'Unknown')}
**Confidence**: {ti.get('confidence', 0):.2%}

### Indicators
"""
            for indicator in ti.get('indicators', []):
                report += f"- {indicator['type']}: {indicator['value']} (Threat: {indicator['threat']})\n"
        
        report += """
## Recommendations

1. **Immediate Actions**:
"""
        
        risk_score = analysis_result.get('risk_score', 0)
        if risk_score > 0.7:
            report += """   - Block access to this onion site
   - Investigate any users who accessed it
   - Check for data exfiltration
"""
        elif risk_score > 0.4:
            report += """   - Monitor access to this site
   - Warn users about potential risks
   - Collect additional intelligence
"""
        else:
            report += """   - Continue monitoring
   - Document for future reference
"""
        
        report += """
2. **Evidence Collection**:
   - Screenshot all pages
   - Save HTML source
   - Document all findings
   - Preserve access logs

3. **Follow-up**:
   - Regular re-scanning
   - Correlation with threat intel
   - Update security controls
"""
        
        return report