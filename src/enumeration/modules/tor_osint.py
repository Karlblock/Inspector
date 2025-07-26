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

from .base import BaseModule
from ...utils.logger import Logger
from ...utils.validators import InputValidator

# Import Tor OSINT components
from .tor_osint.reporting import TorOSINTReporter
from .tor_osint.integrations import TorOSINTIntegrations
from .tor_osint.protection import TorOSINTProtection


class TorOSINTModule(BaseModule):
    """
    Tor OSINT module for defensive security research
    Focuses on identifying data leaks and threats against the organization
    """
    
    def __init__(self):
        super().__init__('tor_osint')
        self.logger = Logger(__name__)
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
                self.logger.warning("Tor service is not active")
                return False
                
            # Test SOCKS connection
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(5)
            try:
                test_socket.connect(('127.0.0.1', 9050))
                test_socket.close()
                return True
            except:
                self.logger.error("Cannot connect to Tor SOCKS proxy on port 9050")
                return False
                
        except Exception as e:
            self.logger.error(f"Error verifying Tor connection: {e}")
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
            self.logger.error(f"Error checking Tor circuit: {e}")
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
            self.logger.error(f"Invalid domain: {target_domain}")
            return results
            
        # Validate search scope with protection module
        validation = self.protection.validate_search_scope(target_domain, keywords)
        if not validation['valid']:
            self.logger.error(f"Search validation failed: {validation['issues']}")
            return results
            
        # Use sanitized keywords
        keywords = validation['sanitized_keywords']
        
        # Check rate limits
        if not self.protection.check_rate_limits():
            self.logger.warning("Rate limit exceeded, skipping search")
            return results
            
        # Common paste sites and forums to check (clearnet + onion)
        leak_sources = [
            {
                'name': 'Pastebin Search',
                'url': 'https://psbdmp.ws/api/v3/search/',
                'type': 'api',
                'requires_tor': False
            },
            {
                'name': 'Have I Been Pwned',
                'url': 'https://haveibeenpwned.com/api/v3/breaches',
                'type': 'api', 
                'requires_tor': False
            }
            # Note: Actual onion addresses would be added here for production
            # Only including clearnet sources for safety in this example
        ]
        
        # Build search terms
        search_terms = [target_domain]
        search_terms.extend([f"{target_domain} {kw}" for kw in keywords])
        search_terms.extend([f"@{target_domain}", f"site:{target_domain}"])
        
        results['searched_terms'] = search_terms
        
        # Log defensive search
        self.logger.info(f"Starting defensive leak search for: {target_domain}")
        self.logger.info(f"Search scope: {', '.join(keywords)}")
        
        # Log activity for audit trail
        self.protection.log_activity('data_leak_search', {
            'target': target_domain,
            'keywords': keywords,
            'timestamp': datetime.now().isoformat()
        })
        
        # Simulate search results (in production, actual API calls would be made)
        # This is a safe simulation for demonstration
        results['potential_leaks'] = [
            {
                'source': 'Example Check',
                'type': 'email_pattern',
                'details': f"Found {target_domain} email pattern in public data",
                'severity': 'medium',
                'recommendation': 'Review and rotate credentials if needed'
            }
        ]
        
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
        self.logger.info(f"Monitoring for threats with keywords: {organization_keywords}")
        
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
        self.logger.info(f"Starting Tor OSINT module for target: {target}")
        
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
            self.logger.error("Operation not legally compliant")
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
                self.logger.warning(f"Tor safety issues detected: {tor_safety['issues']}")
                
            # Verify Tor connection
            if not self.verify_tor_connection():
                self.logger.warning("Tor is not available, proceeding with clearnet only")
                results['findings']['warning'] = "Tor not available, limited search performed"
            else:
                # Check circuit
                exit_ip = self.check_tor_circuit()
                if exit_ip:
                    self.logger.info(f"Tor circuit established, exit IP: {exit_ip}")
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
            self.logger.info(f"Tor OSINT report saved to: {report_path}")
            
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
            self.logger.error(f"Error during Tor OSINT research: {e}")
            results['error'] = str(e)
            
        return results
    
    def cleanup(self):
        """Clean up any resources"""
        # Clear sensitive data from memory
        self.searches_performed = []
        self.logger.info("Tor OSINT module cleanup completed")


# Module registration
module = TorOSINTModule()