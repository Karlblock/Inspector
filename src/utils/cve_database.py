"""
CVE Database module for vulnerability lookup
"""

import json
import requests
from datetime import datetime
from pathlib import Path

class CVEDatabase:
    def __init__(self):
        self.cache_dir = Path.home() / '.cyba-inspector' / 'cve_cache'
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Common CVE patterns for HTB
        self.common_exploits = {
            'Apache/2.4.29': [
                {
                    'id': 'CVE-2019-0211',
                    'cvss': 7.8,
                    'description': 'Apache privilege escalation vulnerability',
                    'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2019-0211'
                }
            ],
            'OpenSSH 7.': [
                {
                    'id': 'CVE-2018-15473',
                    'cvss': 5.0,
                    'description': 'OpenSSH username enumeration',
                    'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2018-15473'
                }
            ],
            'vsftpd': [
                {
                    'id': 'CVE-2011-2523',
                    'cvss': 10.0,
                    'description': 'vsftpd backdoor vulnerability',
                    'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2011-2523'
                }
            ]
        }
    
    def search_cves(self, product, version):
        """Search for CVEs matching product and version"""
        
        cves = []
        
        # Check local patterns first
        for pattern, cve_list in self.common_exploits.items():
            if pattern.lower() in f"{product} {version}".lower():
                cves.extend(cve_list)
        
        # Could integrate with real CVE APIs here
        # For now, return common HTB-relevant CVEs
        
        return cves
    
    def get_exploit_info(self, cve_id):
        """Get detailed exploit information"""
        
        # In a real implementation, this would query exploit databases
        exploit_info = {
            'CVE-2019-0211': {
                'exploit_available': True,
                'metasploit_module': 'exploit/linux/local/apache_mod_cgi_bash_env',
                'manual_exploit': 'https://github.com/cfreal/exploits/tree/master/CVE-2019-0211',
                'requirements': ['Local access', 'Apache running as root'],
                'success_rate': 'High'
            }
        }
        
        return exploit_info.get(cve_id, {})