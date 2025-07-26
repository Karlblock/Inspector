#!/usr/bin/env python3
"""
Tor OSINT Integrations Component
Integrates with threat intelligence platforms and security tools
"""

import json
import os
import requests
from datetime import datetime
from typing import Dict, List, Optional, Any
import hashlib
import hmac
from urllib.parse import urlencode

from ....utils.logger import Logger
from ....utils.config import Config


class TorOSINTIntegrations:
    """Handle integrations with external threat intelligence and security platforms"""
    
    def __init__(self):
        self.logger = Logger(__name__)
        self.config = Config()
        self.session = requests.Session()
        
        # Configure session for potential Tor usage
        if self.config.get('TOR_PROXY_ENABLED', False):
            self.session.proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }
            
    def check_hibp_breaches(self, domain: str) -> Dict:
        """
        Check Have I Been Pwned for breaches affecting the domain
        Note: Requires API key for domain searches
        """
        results = {
            'source': 'HaveIBeenPwned',
            'breaches_found': [],
            'checked_at': datetime.now().isoformat()
        }
        
        api_key = self.config.get('HIBP_API_KEY')
        if not api_key:
            self.logger.warning("HIBP API key not configured")
            return results
            
        try:
            headers = {
                'hibp-api-key': api_key,
                'User-Agent': 'cyba-Inspector-Security-Tool'
            }
            
            # Check domain breaches
            url = f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}"
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                breaches = response.json()
                for breach in breaches:
                    results['breaches_found'].append({
                        'name': breach.get('Name'),
                        'date': breach.get('BreachDate'),
                        'impacted': breach.get('PwnCount', 0),
                        'data_types': breach.get('DataClasses', []),
                        'verified': breach.get('IsVerified', False)
                    })
                    
        except Exception as e:
            self.logger.error(f"Error checking HIBP: {e}")
            results['error'] = str(e)
            
        return results
        
    def check_shodan_exposure(self, target: str) -> Dict:
        """
        Check Shodan for exposed services
        Note: Requires Shodan API key
        """
        results = {
            'source': 'Shodan',
            'exposed_services': [],
            'total_results': 0
        }
        
        api_key = self.config.get('SHODAN_API_KEY')
        if not api_key:
            self.logger.warning("Shodan API key not configured")
            return results
            
        try:
            # Search for the target
            url = f"https://api.shodan.io/shodan/host/search"
            params = {
                'key': api_key,
                'query': f"hostname:{target}",
                'minify': True
            }
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                results['total_results'] = data.get('total', 0)
                
                for match in data.get('matches', [])[:10]:  # Limit to 10 results
                    results['exposed_services'].append({
                        'ip': match.get('ip_str'),
                        'port': match.get('port'),
                        'service': match.get('product', 'Unknown'),
                        'version': match.get('version', ''),
                        'last_seen': match.get('timestamp')
                    })
                    
        except Exception as e:
            self.logger.error(f"Error checking Shodan: {e}")
            results['error'] = str(e)
            
        return results
        
    def check_phishtank(self, domain: str) -> Dict:
        """Check PhishTank for phishing sites targeting the domain"""
        results = {
            'source': 'PhishTank',
            'phishing_sites': [],
            'checked_at': datetime.now().isoformat()
        }
        
        api_key = self.config.get('PHISHTANK_API_KEY')
        if not api_key:
            self.logger.info("PhishTank API key not configured, using public endpoint")
            
        try:
            # Check if domain is being targeted by phishing
            # Note: PhishTank requires specific API implementation
            # This is a simplified example
            
            # In production, you would check their database
            # For now, return empty results
            self.logger.info(f"Checking PhishTank for domain: {domain}")
            
        except Exception as e:
            self.logger.error(f"Error checking PhishTank: {e}")
            results['error'] = str(e)
            
        return results
        
    def submit_to_misp(self, findings: Dict) -> Dict:
        """
        Submit findings to MISP (Malware Information Sharing Platform)
        Note: Requires MISP instance and API key
        """
        results = {
            'platform': 'MISP',
            'submitted': False,
            'event_id': None
        }
        
        misp_url = self.config.get('MISP_URL')
        misp_key = self.config.get('MISP_API_KEY')
        
        if not misp_url or not misp_key:
            self.logger.info("MISP integration not configured")
            return results
            
        try:
            # Create MISP event from findings
            event_data = {
                'Event': {
                    'info': f"Tor OSINT findings for {findings.get('target', 'unknown')}",
                    'distribution': 0,  # Organization only
                    'threat_level_id': self._get_misp_threat_level(findings),
                    'analysis': 2,  # Completed
                    'date': datetime.now().strftime('%Y-%m-%d'),
                    'Attribute': self._convert_findings_to_misp_attributes(findings)
                }
            }
            
            headers = {
                'Authorization': misp_key,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            response = requests.post(
                f"{misp_url}/events",
                json=event_data,
                headers=headers,
                timeout=30,
                verify=self.config.get('VERIFY_SSL', True)
            )
            
            if response.status_code in [200, 201]:
                event = response.json()
                results['submitted'] = True
                results['event_id'] = event.get('Event', {}).get('id')
                self.logger.info(f"Successfully submitted to MISP: Event ID {results['event_id']}")
            else:
                self.logger.error(f"MISP submission failed: {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Error submitting to MISP: {e}")
            results['error'] = str(e)
            
        return results
        
    def export_to_stix(self, findings: Dict) -> str:
        """Export findings in STIX 2.1 format"""
        try:
            # STIX bundle structure
            stix_bundle = {
                "type": "bundle",
                "id": f"bundle--{self._generate_uuid()}",
                "objects": []
            }
            
            # Create threat actor if threats found
            threats = findings.get('threat_intel', {}).get('threats_found', [])
            if threats:
                threat_actor = {
                    "type": "threat-actor",
                    "id": f"threat-actor--{self._generate_uuid()}",
                    "created": datetime.now().isoformat() + "Z",
                    "modified": datetime.now().isoformat() + "Z",
                    "name": "Unknown Threat Actor",
                    "description": f"Threat actor targeting {findings.get('target', 'organization')}",
                    "threat_actor_types": ["unknown"],
                    "spec_version": "2.1"
                }
                stix_bundle["objects"].append(threat_actor)
                
            # Create indicators for data leaks
            leaks = findings.get('leak_search', {}).get('potential_leaks', [])
            for leak in leaks:
                indicator = {
                    "type": "indicator",
                    "id": f"indicator--{self._generate_uuid()}",
                    "created": datetime.now().isoformat() + "Z",
                    "modified": datetime.now().isoformat() + "Z",
                    "name": leak.get('type', 'Data Leak'),
                    "description": leak.get('details', ''),
                    "pattern": f"[file:hashes.MD5 = '{self._generate_hash(leak.get('details', ''))}']",
                    "pattern_type": "stix",
                    "valid_from": datetime.now().isoformat() + "Z",
                    "spec_version": "2.1"
                }
                stix_bundle["objects"].append(indicator)
                
            return json.dumps(stix_bundle, indent=2)
            
        except Exception as e:
            self.logger.error(f"Error generating STIX export: {e}")
            return "{}"
            
    def integrate_with_siem(self, findings: Dict) -> Dict:
        """
        Send findings to SIEM system (Splunk, ELK, etc.)
        This is a generic implementation that can be adapted
        """
        results = {
            'siem': 'generic',
            'sent': False,
            'events_count': 0
        }
        
        siem_endpoint = self.config.get('SIEM_ENDPOINT')
        siem_token = self.config.get('SIEM_TOKEN')
        
        if not siem_endpoint:
            self.logger.info("SIEM integration not configured")
            return results
            
        try:
            # Convert findings to SIEM events
            events = []
            
            # Create events for data leaks
            for leak in findings.get('leak_search', {}).get('potential_leaks', []):
                event = {
                    'timestamp': datetime.now().isoformat(),
                    'source': 'tor_osint',
                    'severity': leak.get('severity', 'medium'),
                    'type': 'data_leak',
                    'description': leak.get('details', ''),
                    'target': findings.get('target', ''),
                    'metadata': {
                        'leak_type': leak.get('type', ''),
                        'source_location': leak.get('source', '')
                    }
                }
                events.append(event)
                
            # Send to SIEM
            headers = {
                'Content-Type': 'application/json'
            }
            
            if siem_token:
                headers['Authorization'] = f"Bearer {siem_token}"
                
            for event in events:
                response = requests.post(
                    siem_endpoint,
                    json=event,
                    headers=headers,
                    timeout=10
                )
                if response.status_code in [200, 201, 202]:
                    results['events_count'] += 1
                    
            results['sent'] = results['events_count'] > 0
            
        except Exception as e:
            self.logger.error(f"Error sending to SIEM: {e}")
            results['error'] = str(e)
            
        return results
        
    def create_jira_ticket(self, findings: Dict) -> Dict:
        """Create Jira ticket for high-priority findings"""
        results = {
            'platform': 'Jira',
            'ticket_created': False,
            'ticket_key': None
        }
        
        jira_url = self.config.get('JIRA_URL')
        jira_user = self.config.get('JIRA_USER')
        jira_token = self.config.get('JIRA_API_TOKEN')
        jira_project = self.config.get('JIRA_PROJECT', 'SEC')
        
        if not all([jira_url, jira_user, jira_token]):
            self.logger.info("Jira integration not configured")
            return results
            
        try:
            # Calculate risk level
            risk_level = self._calculate_risk_level(findings)
            
            if risk_level not in ['High', 'Critical']:
                self.logger.info(f"Risk level {risk_level} does not require Jira ticket")
                return results
                
            # Create ticket
            auth = (jira_user, jira_token)
            headers = {'Content-Type': 'application/json'}
            
            issue_data = {
                'fields': {
                    'project': {'key': jira_project},
                    'summary': f"Tor OSINT Alert: {findings.get('target', 'Unknown')} - {risk_level} Risk",
                    'description': self._generate_jira_description(findings),
                    'issuetype': {'name': 'Security Alert'},
                    'priority': {'name': 'High' if risk_level == 'Critical' else 'Medium'},
                    'labels': ['tor_osint', 'security', 'automated']
                }
            }
            
            response = requests.post(
                f"{jira_url}/rest/api/2/issue",
                json=issue_data,
                auth=auth,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 201:
                ticket = response.json()
                results['ticket_created'] = True
                results['ticket_key'] = ticket.get('key')
                self.logger.info(f"Created Jira ticket: {results['ticket_key']}")
            else:
                self.logger.error(f"Failed to create Jira ticket: {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Error creating Jira ticket: {e}")
            results['error'] = str(e)
            
        return results
        
    def send_slack_alert(self, findings: Dict) -> Dict:
        """Send Slack alert for critical findings"""
        results = {
            'platform': 'Slack',
            'alert_sent': False
        }
        
        webhook_url = self.config.get('SLACK_WEBHOOK_URL')
        if not webhook_url:
            self.logger.info("Slack integration not configured")
            return results
            
        try:
            risk_level = self._calculate_risk_level(findings)
            
            # Only alert on high/critical findings
            if risk_level not in ['High', 'Critical']:
                return results
                
            # Build Slack message
            message = {
                'text': f"🚨 Tor OSINT Security Alert - {risk_level} Risk",
                'attachments': [{
                    'color': 'danger' if risk_level == 'Critical' else 'warning',
                    'fields': [
                        {
                            'title': 'Target',
                            'value': findings.get('target', 'Unknown'),
                            'short': True
                        },
                        {
                            'title': 'Risk Level',
                            'value': risk_level,
                            'short': True
                        },
                        {
                            'title': 'Findings',
                            'value': self._summarize_findings(findings),
                            'short': False
                        }
                    ],
                    'footer': 'Tor OSINT Module',
                    'ts': int(datetime.now().timestamp())
                }]
            }
            
            response = requests.post(webhook_url, json=message, timeout=10)
            
            if response.status_code == 200:
                results['alert_sent'] = True
                self.logger.info("Slack alert sent successfully")
            else:
                self.logger.error(f"Failed to send Slack alert: {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Error sending Slack alert: {e}")
            results['error'] = str(e)
            
        return results
        
    def _get_misp_threat_level(self, findings: Dict) -> int:
        """Convert risk level to MISP threat level"""
        risk_level = self._calculate_risk_level(findings)
        mapping = {
            'Critical': 1,  # High
            'High': 2,      # Medium
            'Medium': 3,    # Low
            'Low': 4        # Undefined
        }
        return mapping.get(risk_level, 4)
        
    def _convert_findings_to_misp_attributes(self, findings: Dict) -> List[Dict]:
        """Convert findings to MISP attribute format"""
        attributes = []
        
        # Convert data leaks
        for leak in findings.get('leak_search', {}).get('potential_leaks', []):
            attributes.append({
                'type': 'text',
                'category': 'Other',
                'value': leak.get('details', ''),
                'comment': f"Data leak: {leak.get('type', 'Unknown')}",
                'to_ids': False
            })
            
        return attributes
        
    def _calculate_risk_level(self, findings: Dict) -> str:
        """Calculate overall risk level"""
        # Simplified risk calculation
        leak_count = len(findings.get('leak_search', {}).get('potential_leaks', []))
        threat_count = len(findings.get('threat_intel', {}).get('threats_found', []))
        
        total_issues = leak_count + threat_count
        
        if total_issues >= 5:
            return 'Critical'
        elif total_issues >= 3:
            return 'High'
        elif total_issues >= 1:
            return 'Medium'
        else:
            return 'Low'
            
    def _generate_uuid(self) -> str:
        """Generate UUID for STIX objects"""
        import uuid
        return str(uuid.uuid4())
        
    def _generate_hash(self, data: str) -> str:
        """Generate hash for STIX patterns"""
        return hashlib.md5(data.encode()).hexdigest()
        
    def _generate_jira_description(self, findings: Dict) -> str:
        """Generate Jira ticket description"""
        desc = f"h2. Tor OSINT Security Alert\n\n"
        desc += f"*Target:* {findings.get('target', 'Unknown')}\n"
        desc += f"*Scan Date:* {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
        
        desc += "h3. Summary\n"
        leak_count = len(findings.get('leak_search', {}).get('potential_leaks', []))
        threat_count = len(findings.get('threat_intel', {}).get('threats_found', []))
        
        desc += f"* Data leaks found: {leak_count}\n"
        desc += f"* Threats detected: {threat_count}\n\n"
        
        if leak_count > 0:
            desc += "h3. Data Leaks\n"
            for i, leak in enumerate(findings.get('leak_search', {}).get('potential_leaks', [])[:5], 1):
                desc += f"{i}. *{leak.get('type', 'Unknown')}* - {leak.get('details', 'No details')}\n"
                
        desc += "\nh3. Required Actions\n"
        desc += "# Review all identified findings\n"
        desc += "# Assess impact and scope\n"
        desc += "# Implement remediation measures\n"
        desc += "# Update security controls\n"
        
        return desc
        
    def _summarize_findings(self, findings: Dict) -> str:
        """Create brief summary of findings for alerts"""
        leak_count = len(findings.get('leak_search', {}).get('potential_leaks', []))
        threat_count = len(findings.get('threat_intel', {}).get('threats_found', []))
        
        summary = f"Found {leak_count} potential data leak(s) and {threat_count} threat(s). "
        
        if leak_count > 0:
            leak_types = [leak.get('type', 'unknown') for leak in 
                         findings.get('leak_search', {}).get('potential_leaks', [])]
            summary += f"Leak types: {', '.join(set(leak_types)[:3])}. "
            
        summary += "Immediate investigation recommended."
        
        return summary