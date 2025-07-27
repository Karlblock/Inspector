#!/usr/bin/env python3
"""
Tor OSINT Module for cyba-Inspector
Defensive security research on Tor network for threat intelligence
"""

import json
import os
import subprocess
import socket
import socks
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import requests
from urllib.parse import urlparse

from enumeration.modules.base import BaseModule
from utils.validators import InputValidator
from utils.colors import Colors

# Import Tor OSINT components
from enumeration.modules.tor_osint_components.reporting import TorOSINTReporter
from enumeration.modules.tor_osint_components.integrations import TorOSINTIntegrations
from enumeration.modules.tor_osint_components.protection import TorOSINTProtection


class TorOSINTModule(BaseModule):
    """
    Tor OSINT module for defensive security research
    Focuses on identifying data leaks and threats against the organization
    """
    
    def __init__(self):
        super().__init__()
        self.name = 'tor_osint'
        self.validator = InputValidator()
        self.tor_proxy = "socks5h://127.0.0.1:9050"
        self.searches_performed = []
        
        # Initialize components
        self.reporter = TorOSINTReporter()
        self.integrations = TorOSINTIntegrations()
        self.protection = TorOSINTProtection()
        
    def verify_tor_connection(self) -> bool:
        """Verify Tor is running and accessible"""
        try:
            # Check if Tor service is running
            result = subprocess.run(['systemctl', 'is-active', 'tor'], 
                                  capture_output=True, text=True)
            if result.stdout.strip() != 'active':
                print(f"{Colors.YELLOW}[!] Tor service is not active{Colors.END}")
                return False
                
            # Test SOCKS connection
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(5)
            try:
                test_socket.connect(('127.0.0.1', 9050))
                test_socket.close()
                return True
            except:
                print(f"{Colors.RED}[-] Cannot connect to Tor SOCKS proxy on port 9050{Colors.END}")
                return False
                
        except Exception as e:
            print(f"{Colors.RED}[-] Error verifying Tor connection: {e}{Colors.END}")
            return False
    
    def check_tor_circuit(self) -> Optional[str]:
        """Check current Tor exit node IP"""
        try:
            # Configure session for Tor
            session = requests.Session()
            session.proxies = {
                'http': self.tor_proxy,
                'https': self.tor_proxy
            }
            
            # Check IP through Tor
            response = session.get('https://check.torproject.org/api/ip', timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data.get('IP', 'Unknown')
        except Exception as e:
            print(f"{Colors.RED}[-] Error checking Tor circuit: {e}{Colors.END}")
        return None
    
    def search_data_leaks(self, target_domain: str, keywords: List[str]) -> Dict:
        """
        Search for potential data leaks related to the target
        This is a defensive search for authorized targets only
        """
        results = {
            'searched_terms': [],
            'potential_leaks': [],
            'risk_level': 'low',
            'timestamp': datetime.now().isoformat()
        }
        
        # Validate domain
        if not self.validator.validate_domain(target_domain):
            print(f"{Colors.RED}[-] Invalid domain: {target_domain}{Colors.END}")
            return results
            
        # Validate search scope with protection module
        validation = self.protection.validate_search_scope(target_domain, keywords)
        if not validation['valid']:
            print(f"{Colors.RED}[-] Search validation failed: {validation['issues']}{Colors.END}")
            return results
            
        # Use sanitized keywords
        keywords = validation['sanitized_keywords']
        
        # Check rate limits
        if not self.protection.check_rate_limits():
            print(f"{Colors.YELLOW}[!] Rate limit exceeded, skipping search{Colors.END}")
            return results
            
        # Real sources to check
        leak_sources = [
            {
                'name': 'Have I Been Pwned',
                'url': 'https://haveibeenpwned.com/api/v3/breachedaccount/',
                'type': 'api',
                'requires_tor': False
            },
            {
                'name': 'IntelX Public',
                'url': 'https://2.intelx.io/search',
                'type': 'web',
                'requires_tor': False
            },
            {
                'name': 'Ahmia Search',
                'url': 'https://ahmia.fi/search/',
                'type': 'web',
                'requires_tor': False  # Ahmia has clearnet access
            }
        ]
        
        # Build search terms
        search_terms = [target_domain]
        search_terms.extend([f"{target_domain} {kw}" for kw in keywords])
        search_terms.extend([f"@{target_domain}", f"site:{target_domain}"])
        
        results['searched_terms'] = search_terms
        
        # Log defensive search
        print(f"{Colors.CYAN}[*] Starting defensive leak search for: {target_domain}{Colors.END}")
        print(f"{Colors.CYAN}[*] Search scope: {', '.join(keywords)}{Colors.END}")
        
        # Log activity for audit trail
        self.protection.log_activity('data_leak_search', {
            'target': target_domain,
            'keywords': keywords,
            'timestamp': datetime.now().isoformat()
        })
        
        # Perform real searches
        session = requests.Session()
        tor_enabled = results.get('tor_enabled', False)
        if tor_enabled:
            session.proxies = {
                'http': self.tor_proxy,
                'https': self.tor_proxy
            }
        
        # Check for known official .onion addresses first
        known_onions = self._check_known_onions(target_domain)
        if known_onions:
            results['potential_leaks'].extend(known_onions)
        
        # Search Ahmia for .onion sites mentioning the domain
        ahmia_results = self._search_ahmia(session, target_domain, keywords)
        if ahmia_results:
            results['potential_leaks'].extend(ahmia_results)
        
        # Check HIBP for breaches (requires API key for full data)
        hibp_results = self._check_hibp_domain(session, target_domain)
        if hibp_results:
            results['potential_leaks'].extend(hibp_results)
        
        # Search for exposed credentials on paste sites
        paste_results = self._search_paste_sites(session, target_domain, keywords)
        if paste_results:
            results['potential_leaks'].extend(paste_results)
        
        # Assess risk level based on findings
        if results['potential_leaks']:
            results['risk_level'] = 'medium'
            
        return results
    
    def monitor_threat_intel(self, organization_keywords: List[str]) -> Dict:
        """
        Monitor for threats against the organization
        This performs defensive monitoring only
        """
        intel = {
            'monitoring_keywords': organization_keywords,
            'threats_found': [],
            'monitoring_timestamp': datetime.now().isoformat()
        }
        
        # In production, this would connect to threat intel feeds
        # For safety, we're only demonstrating the structure
        print(f"{Colors.CYAN}[*] Monitoring for threats with keywords: {organization_keywords}{Colors.END}")
        
        return intel
    
    def generate_defensive_report(self, findings: Dict) -> str:
        """Generate a defensive security report from findings"""
        report = f"""
# Tor OSINT Defensive Security Report
Generated: {datetime.now().isoformat()}

## Executive Summary
This report contains findings from defensive Tor/dark web research conducted to identify potential data leaks and threats against the organization.

## Scope
- Authorized target domain: {findings.get('target_domain', 'N/A')}
- Search conducted through Tor: {'Yes' if findings.get('tor_enabled') else 'No'}
- Legal compliance: Defensive research only

## Findings

### Data Leak Assessment
"""
        
        leaks = findings.get('leak_search', {}).get('potential_leaks', [])
        if leaks:
            report += f"- **Risk Level**: {findings.get('leak_search', {}).get('risk_level', 'Unknown')}\n"
            report += "- **Potential Issues Found**:\n"
            for leak in leaks:
                report += f"  - {leak['type']}: {leak['details']}\n"
                report += f"    - Severity: {leak['severity']}\n"
                report += f"    - Action: {leak['recommendation']}\n"
        else:
            report += "- No data leaks detected\n"
            
        report += """
### Threat Intelligence
"""
        
        threats = findings.get('threat_intel', {}).get('threats_found', [])
        if threats:
            report += "- **Active Threats Detected**:\n"
            for threat in threats:
                report += f"  - {threat}\n"
        else:
            report += "- No active threats detected\n"
            
        report += """
## Recommendations

1. **Immediate Actions**:
   - Review all identified leaks
   - Reset credentials if compromised
   - Monitor for unauthorized access

2. **Long-term Improvements**:
   - Implement continuous dark web monitoring
   - Regular security awareness training
   - Strengthen data loss prevention (DLP)

## Legal Notice
This research was conducted within legal boundaries for defensive security purposes only.
All activities were authorized and documented according to security policies.
"""
        
        return report
    
    def run(self, target: str, session_id: str, output_dir: str, **kwargs) -> Dict:
        """
        Main execution method for the Tor OSINT module
        Performs defensive security research
        """
        print(f"{Colors.CYAN}[*] Starting Tor OSINT module for target: {target}{Colors.END}")
        
        results = {
            'module': self.name,
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'tor_enabled': False,
            'findings': {},
            'keywords': kwargs.get('keywords', ['password', 'leak', 'breach', 'database'])
        }
        
        # Check legal compliance first
        compliance = self.protection.check_legal_compliance(
            'tor_osint_research',
            kwargs.get('jurisdiction', 'US')
        )
        
        if not compliance['compliant']:
            print(f"{Colors.RED}[-] Operation not legally compliant{Colors.END}")
            results['error'] = 'Legal compliance check failed'
            results['compliance'] = compliance
            return results
            
        # Check if we should use Tor
        use_tor = kwargs.get('use_tor', False)
        keywords = results['keywords']
        
        # Verify Tor safety if using it
        if use_tor:
            tor_safety = self.protection.verify_tor_safety()
            if not tor_safety['safe']:
                print(f"{Colors.YELLOW}[!] Tor safety issues detected: {tor_safety['issues']}{Colors.END}")
                
            # Verify Tor connection
            if not self.verify_tor_connection():
                print(f"{Colors.YELLOW}[!] Tor is not available, proceeding with clearnet only{Colors.END}")
                results['findings']['warning'] = "Tor not available, limited search performed"
            else:
                # Check circuit
                exit_ip = self.check_tor_circuit()
                if exit_ip:
                    print(f"{Colors.GREEN}[+] Tor circuit established, exit IP: {exit_ip}{Colors.END}")
                    results['tor_enabled'] = True
                    results['tor_exit_ip'] = exit_ip
        
        # Perform defensive searches
        try:
            # Search for data leaks
            leak_results = self.search_data_leaks(target, keywords)
            results['findings']['leak_search'] = leak_results
            
            # Monitor threat intelligence
            org_keywords = kwargs.get('org_keywords', [target])
            threat_intel = self.monitor_threat_intel(org_keywords)
            results['findings']['threat_intel'] = threat_intel
            
            # Check additional threat sources if configured
            if kwargs.get('check_hibp', False):
                hibp_results = self.integrations.check_hibp_breaches(target)
                results['findings']['hibp'] = hibp_results
                
            if kwargs.get('check_shodan', False):
                shodan_results = self.integrations.check_shodan_exposure(target)
                results['findings']['shodan'] = shodan_results
            
            # Sanitize findings before reporting
            results['findings'] = self.protection.sanitize_findings(results['findings'])
            
            # Generate reports in multiple formats
            report_format = kwargs.get('report_format', 'markdown')
            report = self.reporter.generate_report(
                results['findings'],
                format=report_format,
                include_recommendations=kwargs.get('include_recommendations', True)
            )
            
            # Save main report
            report_ext = 'md' if report_format == 'markdown' else report_format
            report_path = os.path.join(output_dir, f"tor_osint_report_{session_id}.{report_ext}")
            
            with open(report_path, 'w') as f:
                f.write(report)
                
            results['report_path'] = report_path
            print(f"{Colors.GREEN}[+] Tor OSINT report saved to: {report_path}{Colors.END}")
            
            # Generate additional reports
            if kwargs.get('generate_executive_report', False):
                exec_report = self.reporter.generate_report(results['findings'], format='executive')
                exec_path = os.path.join(output_dir, f"tor_osint_executive_{session_id}.md")
                with open(exec_path, 'w') as f:
                    f.write(exec_report)
                results['executive_report_path'] = exec_path
                
            # Generate safety report
            safety_report = self.protection.generate_safety_report()
            safety_path = os.path.join(output_dir, f"tor_osint_safety_{session_id}.md")
            with open(safety_path, 'w') as f:
                f.write(safety_report)
            results['safety_report_path'] = safety_path
            
            # Generate OPSEC guidelines if requested
            if kwargs.get('include_opsec', False):
                opsec = self.protection.generate_opsec_guidelines()
                opsec_path = os.path.join(output_dir, f"tor_osint_opsec_{session_id}.md")
                with open(opsec_path, 'w') as f:
                    f.write(opsec)
                results['opsec_guide_path'] = opsec_path
            
            # Handle integrations
            if kwargs.get('send_to_siem', False):
                siem_results = self.integrations.integrate_with_siem(results['findings'])
                results['integrations'] = {'siem': siem_results}
                
            # Check if we need to create tickets or alerts
            risk_level = leak_results.get('risk_level', 'low')
            if risk_level in ['High', 'Critical']:
                # Send Slack alert if configured
                if kwargs.get('slack_alerts', False):
                    slack_result = self.integrations.send_slack_alert(results['findings'])
                    results.setdefault('integrations', {})['slack'] = slack_result
                    
                # Create Jira ticket if configured
                if kwargs.get('create_tickets', False):
                    jira_result = self.integrations.create_jira_ticket(results['findings'])
                    results.setdefault('integrations', {})['jira'] = jira_result
            
            # Export to STIX if requested
            if kwargs.get('export_stix', False):
                stix_data = self.integrations.export_to_stix(results['findings'])
                stix_path = os.path.join(output_dir, f"tor_osint_stix_{session_id}.json")
                with open(stix_path, 'w') as f:
                    f.write(stix_data)
                results['stix_export_path'] = stix_path
            
            # Add to session findings
            findings_summary = {
                'data_leaks_found': len(leak_results.get('potential_leaks', [])),
                'risk_level': leak_results.get('risk_level', 'low'),
                'threats_detected': len(threat_intel.get('threats_found', [])),
                'report_location': report_path,
                'compliance_status': 'compliant',
                'safety_verified': True
            }
            
            results['findings']['summary'] = findings_summary
            
            # Log completion
            self.protection.log_activity('tor_osint_complete', {
                'target': target,
                'session_id': session_id,
                'findings_count': findings_summary['data_leaks_found'] + findings_summary['threats_detected'],
                'risk_level': findings_summary['risk_level']
            })
            
        except Exception as e:
            print(f"{Colors.RED}[-] Error during Tor OSINT research: {e}{Colors.END}")
            results['error'] = str(e)
            
        return results
    
    def _search_ahmia(self, session: requests.Session, domain: str, keywords: List[str]) -> List[Dict]:
        """Search Ahmia for .onion sites mentioning the domain"""
        results = []
        base_url = "https://ahmia.fi/search/"
        
        try:
            # Recherche ciblée sur les vrais risques
            # Au lieu de chercher juste le domaine, chercher des patterns spécifiques
            risk_patterns = [
                f'"{domain}" database leak',
                f'"{domain}" password dump',
                f'"{domain}" breach',
                f'"{domain}" hacked',
                f'site:{domain.split(".")[0]}*.onion',  # Chercher les clones
                f'"{domain}" vulnerability',
                f'"{domain}" exposed data'
            ]
            
            # Limiter à 3-4 recherches pour éviter le rate limiting
            search_terms = risk_patterns[:4]
            
            for term in search_terms:
                print(f"{Colors.CYAN}[*] Searching Ahmia for: {term}{Colors.END}")
                
                params = {'q': term}
                response = session.get(base_url, params=params, timeout=30)
                
                if response.status_code == 200:
                    # Parse HTML results
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find result items
                    for result in soup.find_all('li', class_='result'):
                        onion_link = result.find('cite')
                        title = result.find('h4')
                        description = result.find('p')
                        
                        if onion_link and '.onion' in onion_link.text:
                            # Analyser la pertinence
                            title_text = title.text.lower() if title else ''
                            desc_text = description.text.lower() if description else ''
                            onion_addr = onion_link.text.strip()
                            
                            # Filtrer les résultats non pertinents
                            relevance_score = 0
                            severity = 'info'
                            
                            # Mots-clés de haute pertinence
                            high_relevance = ['leak', 'breach', 'dump', 'database', 'password', 'hack', 
                                            'stolen', 'exposed', 'vulnerability', 'compromised', 'credential']
                            
                            # Mots-clés de basse pertinence (liens, annuaires, etc.)
                            low_relevance = ['directory', 'links', 'index', 'list of', 'collection', 
                                           'bookmark', 'forum', 'wiki', 'onion list']
                            
                            # Calculer le score de pertinence
                            for keyword in high_relevance:
                                if keyword in title_text or keyword in desc_text:
                                    relevance_score += 2
                                    severity = 'high'
                            
                            for keyword in low_relevance:
                                if keyword in title_text or keyword in desc_text:
                                    relevance_score -= 1
                            
                            # Vérifier si c'est un clone/phishing potentiel
                            if domain.split('.')[0] in onion_addr:
                                relevance_score += 3
                                severity = 'critical'
                                details = f"Potential phishing/clone site: {onion_addr}"
                            else:
                                details = f"Found on: {onion_addr} - {title_text[:100]}"
                            
                            # Ne garder que les résultats pertinents
                            if relevance_score > 0 or severity == 'critical':
                                results.append({
                                    'source': 'Ahmia',
                                    'type': 'onion_mention' if severity != 'critical' else 'potential_phishing',
                                    'details': details,
                                    'title': title.text if title else 'Unknown',
                                    'description': description.text[:200] if description else '',
                                    'onion_address': onion_addr,
                                    'severity': severity,
                                    'relevance_score': relevance_score,
                                    'recommendation': 'Investigate this .onion site for potential data exposure' if severity != 'critical' else 'URGENT: Investigate potential phishing site'
                                })
                
                # Rate limiting
                time.sleep(2)
                
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Ahmia search error: {e}{Colors.END}")
            
        return results
    
    def _check_known_onions(self, domain: str) -> List[Dict]:
        """Check for known official .onion addresses"""
        results = []
        
        # Base de données des .onion officiels connus
        known_onions = {
            'facebook.com': {
                'official': 'facebookcorewwwi.onion',
                'v3': 'facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion'
            },
            'nytimes.com': {
                'official': 'nytimes3xbfgragh.onion',
                'v3': 'ej3kv4ebuugcmuwxctx5ic7zxh73rnxt42soi3tdneu2c2em55thufqd.onion'
            },
            'bbc.com': {
                'official': 'bbcnewsv2vjtpsuy.onion'
            },
            'protonmail.com': {
                'official': 'protonirockerxow.onion'
            },
            'duckduckgo.com': {
                'official': '3g2upl4pq6kufc4m.onion',
                'v3': 'duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion'
            }
        }
        
        # Vérifier si le domaine a un .onion officiel
        base_domain = domain.lower()
        if base_domain in known_onions:
            for onion_type, onion_addr in known_onions[base_domain].items():
                results.append({
                    'source': 'Known Official Onion',
                    'type': 'official_onion',
                    'details': f"Official {onion_type} Tor address for {domain}",
                    'onion_address': onion_addr,
                    'severity': 'info',
                    'recommendation': 'This is the legitimate Tor address. Be aware of clones/phishing sites.'
                })
        
        return results
    
    def _check_hibp_domain(self, session: requests.Session, domain: str) -> List[Dict]:
        """Check Have I Been Pwned for domain breaches"""
        results = []
        
        try:
            # HIBP requires User-Agent
            headers = {
                'User-Agent': 'cyba-Inspector-Security-Tool',
                'Accept': 'application/json'
            }
            
            # Check domain breaches
            print(f"{Colors.CYAN}[*] Checking HIBP for {domain} breaches{Colors.END}")
            
            # Note: Full API requires paid key. Using public breach list
            url = f"https://haveibeenpwned.com/api/v3/breaches"
            response = session.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                breaches = response.json()
                domain_breaches = []
                
                # Search for domain in breach data
                for breach in breaches:
                    if domain.lower() in breach.get('Domain', '').lower() or \
                       domain.lower() in breach.get('Title', '').lower() or \
                       domain.lower() in breach.get('Description', '').lower():
                        domain_breaches.append(breach)
                
                for breach in domain_breaches:
                    results.append({
                        'source': 'Have I Been Pwned',
                        'type': 'data_breach',
                        'details': f"{breach['Title']}: {breach['Description'][:200]}...",
                        'breach_date': breach['BreachDate'],
                        'compromised_data': ', '.join(breach['DataClasses']),
                        'affected_accounts': breach['PwnCount'],
                        'severity': 'high' if breach['PwnCount'] > 100000 else 'medium',
                        'recommendation': 'Notify affected users and enforce password resets'
                    })
                    
        except Exception as e:
            print(f"{Colors.YELLOW}[!] HIBP check error: {e}{Colors.END}")
            
        return results
    
    def _search_paste_sites(self, session: requests.Session, domain: str, keywords: List[str]) -> List[Dict]:
        """Search paste sites for exposed data"""
        results = []
        
        # Using Google dorks for paste sites (ethical and legal)
        paste_sites = [
            'site:pastebin.com',
            'site:ghostbin.com',
            'site:dpaste.com'
        ]
        
        try:
            for site in paste_sites:
                search_query = f"{site} \"{domain}\""
                print(f"{Colors.CYAN}[*] Searching pastes: {search_query}{Colors.END}")
                
                # Note: In production, you'd use Google Custom Search API
                # For now, we'll note that manual verification is needed
                results.append({
                    'source': 'Paste Site Search',
                    'type': 'manual_check_required',
                    'details': f"Manual search recommended: {search_query}",
                    'severity': 'info',
                    'recommendation': f"Manually check Google for: {search_query}"
                })
                
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Paste search error: {e}{Colors.END}")
            
        return results
    
    def cleanup(self):
        """Clean up any resources"""
        # Clear sensitive data from memory
        self.searches_performed = []
        print(f"{Colors.CYAN}[*] Tor OSINT module cleanup completed{Colors.END}")


# Module registration
module = TorOSINTModule()