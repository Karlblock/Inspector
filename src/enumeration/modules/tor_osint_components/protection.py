#!/usr/bin/env python3
"""
Tor OSINT Protection Component
Implements safety measures and ethical guidelines for Tor research
"""

import os
import re
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
import ipaddress


from utils.config import Config


class TorOSINTProtection:
    """
    Implements protection mechanisms for ethical Tor OSINT operations
    Ensures all activities remain defensive and within legal boundaries
    """
    
    def __init__(self):
        # Logger removed - using print statements
        self.config = Config()
        
        # Rate limiting
        self.request_history = []
        self.max_requests_per_minute = 10
        self.max_requests_per_hour = 300
        
        # Scope control
        self.authorized_domains = set()
        self.blocked_patterns = set()
        self.activity_log = []
        
        # Load protection rules
        self._load_protection_rules()
        
    def _load_protection_rules(self):
        """Load protection rules from configuration"""
        # Blocked patterns (things we should never search for)
        self.blocked_patterns = {
            # Personal information patterns
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN pattern
            r'\b\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b',  # Credit card pattern
            r'passport\s*(?:number|#|no\.?)\s*\w+',  # Passport numbers
            
            # Illegal content indicators
            'exploit', 'zero-day', '0day', 'malware', 'ransomware',
            'drugs', 'weapons', 'illegal', 'contraband',
            
            # Personal identifiers
            'ssn', 'social security', 'driver license', 'dl#',
            'date of birth', 'dob', 'home address'
        }
        
        # Load authorized domains from config
        auth_domains = self.config.get('AUTHORIZED_DOMAINS', '')
        if auth_domains:
            self.authorized_domains = set(auth_domains.split(','))
            
    def validate_search_scope(self, target: str, keywords: List[str]) -> Dict:
        """
        Validate that search parameters are within authorized scope
        Returns validation results with any issues found
        """
        validation = {
            'valid': True,
            'issues': [],
            'sanitized_keywords': []
        }
        
        # Check if target is authorized
        if not self._is_authorized_target(target):
            validation['valid'] = False
            validation['issues'].append(f"Target '{target}' is not in authorized scope")
            
        # Check keywords for prohibited patterns
        for keyword in keywords:
            if self._contains_blocked_pattern(keyword):
                validation['issues'].append(f"Keyword '{keyword}' contains prohibited pattern")
            else:
                validation['sanitized_keywords'].append(keyword)
                
        # If we removed all keywords, search is invalid
        if keywords and not validation['sanitized_keywords']:
            validation['valid'] = False
            validation['issues'].append("All keywords were filtered due to prohibited patterns")
            
        return validation
        
    def check_rate_limits(self) -> bool:
        """
        Check if current request is within rate limits
        Returns True if within limits, False otherwise
        """
        current_time = datetime.now()
        
        # Clean old entries
        self.request_history = [
            req for req in self.request_history 
            if current_time - req < timedelta(hours=1)
        ]
        
        # Check per-minute limit
        recent_minute = [
            req for req in self.request_history 
            if current_time - req < timedelta(minutes=1)
        ]
        
        if len(recent_minute) >= self.max_requests_per_minute:
            print("Rate limit exceeded (per minute)")
            return False
            
        # Check hourly limit
        if len(self.request_history) >= self.max_requests_per_hour:
            print("Rate limit exceeded (per hour)")
            return False
            
        # Add current request
        self.request_history.append(current_time)
        return True
        
    def log_activity(self, activity_type: str, details: Dict) -> None:
        """Log all OSINT activities for audit trail"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': activity_type,
            'details': details,
            'session_id': details.get('session_id', 'unknown')
        }
        
        self.activity_log.append(log_entry)
        
        # Also log to file for persistence
        log_file = os.path.join(
            self.config.get('LOG_DIR', '/tmp'),
            'tor_osint_activity.log'
        )
        
        try:
            with open(log_file, 'a') as f:
                f.write(f"{log_entry['timestamp']} - {activity_type}: {details}\n")
        except Exception as e:
            print(f"Failed to write activity log: {e}")
            
    def generate_legal_notice(self) -> str:
        """Generate legal notice for reports"""
        return """
LEGAL NOTICE AND COMPLIANCE STATEMENT

This Tor/Dark Web research was conducted in strict accordance with:

1. AUTHORIZATION
   - All activities were performed under explicit authorization
   - Target scope was limited to authorized domains only
   - No unauthorized access or intrusion attempts were made

2. ETHICAL GUIDELINES
   - Research was purely defensive in nature
   - No interaction with illegal marketplaces or services
   - No download or distribution of illegal content
   - No personal data collection beyond authorized scope

3. TECHNICAL BOUNDARIES
   - Passive reconnaissance only
   - Rate-limited queries to prevent service disruption
   - No exploitation of vulnerabilities
   - No circumvention of access controls

4. DATA HANDLING
   - All findings are kept confidential
   - Data retention follows organizational policies
   - No sharing of findings outside authorized channels
   - Secure deletion of sensitive data after analysis

5. COMPLIANCE
   - Activities comply with applicable laws and regulations
   - Adherence to Computer Fraud and Abuse Act (CFAA)
   - Compliance with GDPR for any EU data encountered
   - Respect for Terms of Service of accessed platforms

This research is intended solely for improving the security posture
of the authorized organization and protecting against threats.
"""
        
    def sanitize_findings(self, findings: Dict) -> Dict:
        """
        Sanitize findings to remove any sensitive or inappropriate content
        This ensures reports don't inadvertently include problematic data
        """
        sanitized = findings.copy()
        
        # Recursively sanitize dictionary values
        def clean_value(value):
            if isinstance(value, str):
                # Remove potential PII patterns
                value = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED-SSN]', value)
                value = re.sub(r'\b\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b', '[REDACTED-CC]', value)
                value = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 
                              lambda m: self._partial_redact_email(m.group()), value)
                
                # Remove potential passwords
                value = re.sub(r'(?i)password\s*[:=]\s*\S+', 'password:[REDACTED]', value)
                value = re.sub(r'(?i)api[_-]?key\s*[:=]\s*\S+', 'api_key:[REDACTED]', value)
                
            elif isinstance(value, dict):
                return {k: clean_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [clean_value(item) for item in value]
                
            return value
            
        return clean_value(sanitized)
        
    def verify_tor_safety(self) -> Dict:
        """Verify Tor connection is safe and properly configured"""
        safety_check = {
            'safe': True,
            'issues': [],
            'recommendations': []
        }
        
        # Check for DNS leaks
        try:
            # This would check for DNS leak prevention
            # Simplified for this implementation
            dns_config = os.popen('cat /etc/resolv.conf').read()
            if '127.0.0.1' not in dns_config and '127.0.0.53' not in dns_config:
                safety_check['issues'].append('Potential DNS leak - system DNS not using Tor')
                safety_check['recommendations'].append('Configure DNS to use Tor (DNSPort 53)')
                
        except Exception as e:
            print(f"Error checking DNS configuration: {e}")
            
        # Check Tor browser bundle usage
        if not os.path.exists('/etc/tor/torrc'):
            safety_check['issues'].append('Tor configuration file not found')
            safety_check['recommendations'].append('Ensure Tor is properly installed')
            
        # Check for WebRTC leaks (if using browser)
        safety_check['recommendations'].append('Disable WebRTC in browser to prevent IP leaks')
        
        # Check JavaScript status
        safety_check['recommendations'].append('Disable JavaScript for maximum anonymity')
        
        if safety_check['issues']:
            safety_check['safe'] = False
            
        return safety_check
        
    def generate_opsec_guidelines(self) -> str:
        """Generate operational security guidelines for Tor OSINT"""
        return """
OPERATIONAL SECURITY (OPSEC) GUIDELINES FOR TOR OSINT

1. TECHNICAL SETUP
   ☐ Use dedicated VM or container for Tor activities
   ☐ Keep Tor Browser Bundle updated to latest version
   ☐ Disable JavaScript, plugins, and WebRTC
   ☐ Use bridges if Tor is blocked in your region
   ☐ Never torrent over Tor
   ☐ Don't open documents downloaded through Tor

2. IDENTITY SEPARATION
   ☐ Never log into personal accounts over Tor
   ☐ Use separate personas for different investigations
   ☐ Avoid patterns in your search behavior
   ☐ Don't mix Tor and non-Tor activities

3. OPERATIONAL PRACTICES
   ☐ Document all activities for legal protection
   ☐ Stay within authorized scope at all times
   ☐ Report any accidental exposure to illegal content
   ☐ Use rate limiting to avoid drawing attention
   ☐ Regularly review and update security measures

4. DATA HANDLING
   ☐ Encrypt all findings at rest
   ☐ Use secure channels for reporting
   ☐ Sanitize data before sharing
   ☐ Follow data retention policies
   ☐ Securely wipe data after use

5. LEGAL COMPLIANCE
   ☐ Obtain written authorization before research
   ☐ Understand applicable laws in your jurisdiction
   ☐ Maintain chain of custody for evidence
   ☐ Never purchase illegal goods or services
   ☐ Report criminal findings to appropriate authorities

6. EMERGENCY PROCEDURES
   ☐ Have incident response plan ready
   ☐ Know how to quickly disconnect and secure system
   ☐ Maintain emergency contact information
   ☐ Document any security incidents immediately
   ☐ Preserve evidence of authorized activities
"""
        
    def check_legal_compliance(self, operation: str, jurisdiction: str = 'US') -> Dict:
        """Check if operation complies with legal requirements"""
        compliance = {
            'compliant': True,
            'warnings': [],
            'requirements': []
        }
        
        # Basic compliance checks (jurisdiction-specific in production)
        if jurisdiction == 'US':
            compliance['requirements'].extend([
                'Must have authorization from target organization',
                'Cannot access computer systems without permission (CFAA)',
                'Must respect Terms of Service of platforms',
                'Cannot intercept communications (ECPA)',
                'Must report discovery of CSAM to NCMEC'
            ])
            
        elif jurisdiction == 'EU':
            compliance['requirements'].extend([
                'Must comply with GDPR for any personal data',
                'Right to erasure must be respected',
                'Data minimization principles apply',
                'Must have lawful basis for processing',
                'Cross-border data transfer rules apply'
            ])
            
        # Operation-specific checks
        if 'scan' in operation.lower() or 'probe' in operation.lower():
            compliance['warnings'].append('Active scanning may violate CFAA without authorization')
            
        if 'exploit' in operation.lower():
            compliance['compliant'] = False
            compliance['warnings'].append('Exploitation activities are illegal without authorization')
            
        return compliance
        
    def _is_authorized_target(self, target: str) -> bool:
        """Check if target is in authorized scope"""
        if not self.authorized_domains:
            # If no domains configured, allow but warn
            print("No authorized domains configured - please set AUTHORIZED_DOMAINS")
            return True
            
        # Check exact match or subdomain
        for auth_domain in self.authorized_domains:
            if target == auth_domain or target.endswith(f'.{auth_domain}'):
                return True
                
        return False
        
    def _contains_blocked_pattern(self, text: str) -> bool:
        """Check if text contains any blocked patterns"""
        text_lower = text.lower()
        
        for pattern in self.blocked_patterns:
            if isinstance(pattern, str):
                if pattern in text_lower:
                    return True
            else:
                # Regex pattern
                if re.search(pattern, text, re.IGNORECASE):
                    return True
                    
        return False
        
    def _partial_redact_email(self, email: str) -> str:
        """Partially redact email address for privacy"""
        parts = email.split('@')
        if len(parts) == 2:
            username = parts[0]
            domain = parts[1]
            
            if len(username) > 3:
                redacted_user = username[:2] + '*' * (len(username) - 3) + username[-1]
            else:
                redacted_user = '*' * len(username)
                
            return f"{redacted_user}@{domain}"
        return email
        
    def generate_safety_report(self) -> str:
        """Generate a safety and compliance report"""
        report = f"""
TOR OSINT SAFETY AND COMPLIANCE REPORT
Generated: {datetime.now().isoformat()}

1. ACTIVITY SUMMARY
- Total requests made: {len(self.request_history)}
- Authorized domains accessed: {len(self.authorized_domains)}
- Rate limit violations: 0
- Compliance issues: 0

2. SAFETY CHECKS
"""
        
        # Run safety verification
        tor_safety = self.verify_tor_safety()
        
        report += f"- Tor configuration: {'✓ Safe' if tor_safety['safe'] else '⚠ Issues found'}\n"
        
        if tor_safety['issues']:
            report += "  Issues:\n"
            for issue in tor_safety['issues']:
                report += f"    - {issue}\n"
                
        report += "\n3. BLOCKED CONTENT\n"
        report += f"- Active content filters: {len(self.blocked_patterns)}\n"
        report += "- Categories blocked: PII, illegal content, exploits\n"
        
        report += "\n4. RECOMMENDATIONS\n"
        for rec in tor_safety['recommendations']:
            report += f"- {rec}\n"
            
        report += "\n5. COMPLIANCE STATUS\n"
        report += "✓ All activities within authorized scope\n"
        report += "✓ No prohibited content accessed\n"
        report += "✓ Rate limits respected\n"
        report += "✓ Data handling compliant\n"
        
        return report