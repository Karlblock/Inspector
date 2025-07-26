"""
Web enumeration module
"""

from enumeration.modules.base import BaseModule
from utils.colors import Colors
import re

class WebModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "web"
        self.web_ports = ['80', '443', '8080', '8443', '8000', '3000', '5000']
        
    def run(self, target, session_id, output_dir, ports=None, quick=False, **kwargs):
        """Run web enumeration"""
        results = {}
        
        # Determine which ports to scan
        if ports:
            # If specific ports are provided, use them
            provided_ports = [p.strip() for p in str(ports).split(',')]
            scan_ports = [p for p in provided_ports if p in self.web_ports or p in ['80', '443', '8080', '8443']]
        else:
            # Check which web ports are open
            print(f"{Colors.CYAN}[*] Detecting web ports...{Colors.END}")
            scan_ports = self._detect_web_ports(target)
            
            # If detection fails, try common web ports from nmap results
            if not scan_ports:
                # Check for port 80 and 443 specifically
                for port in ['80', '443']:
                    cmd = f"nc -zv -w 2 {target} {port} 2>&1"
                    result = self.execute_command(cmd, timeout=5)
                    if 'succeeded' in result.get('stdout', '') or 'succeeded' in result.get('stderr', ''):
                        scan_ports.append(port)
                        print(f"{Colors.GREEN}[+] Found web port: {port}{Colors.END}")
        
        if not scan_ports:
            print(f"{Colors.YELLOW}[!] No web ports detected{Colors.END}")
            return results
        
        for port in scan_ports:
            print(f"\n{Colors.CYAN}[*] Enumerating web service on port {port}...{Colors.END}")
            
            # Determine protocol
            protocol = 'https' if port in ['443', '8443'] else 'http'
            base_url = f"{protocol}://{target}:{port}"
            
            # Basic information gathering
            print(f"{Colors.CYAN}[*] Gathering basic information...{Colors.END}")
            
            # WhatWeb
            cmd = f"whatweb -a 3 {base_url}"
            result = self.execute_command(cmd, timeout=60)
            if result['returncode'] == 0:
                self.save_output(output_dir, f"whatweb_port_{port}.txt", result['stdout'])
                results[f'whatweb_{port}'] = result
            
            # Nikto (skip in quick mode)
            if not quick:
                print(f"{Colors.CYAN}[*] Running Nikto scan...{Colors.END}")
                cmd = f"nikto -h {base_url} -o {output_dir}/nikto_port_{port}.txt -Format txt"
                result = self.execute_command(cmd, timeout=300)
                if result['returncode'] == 0:
                    results[f'nikto_{port}'] = result
            
            # Directory enumeration
            print(f"{Colors.CYAN}[*] Running directory enumeration...{Colors.END}")
            
            # Gobuster with common wordlist
            wordlist = "/usr/share/wordlists/dirb/common.txt"
            cmd = f"gobuster dir -u {base_url} -w {wordlist} -o {output_dir}/gobuster_common_port_{port}.txt"
            
            if quick:
                cmd += " -t 50"  # More threads for quick scan
            else:
                cmd += " -t 30 -x php,html,txt,asp,aspx,jsp"
            
            result = self.execute_command(cmd, timeout=300 if quick else 600)
            if result['returncode'] == 0:
                results[f'gobuster_common_{port}'] = result
            
            # Additional enumeration for non-quick mode
            if not quick:
                # Larger wordlist
                print(f"{Colors.CYAN}[*] Running extended directory enumeration...{Colors.END}")
                wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
                cmd = f"gobuster dir -u {base_url} -w {wordlist} -t 30 -x php,html,txt -o {output_dir}/gobuster_medium_port_{port}.txt"
                result = self.execute_command(cmd, timeout=900)
                if result['returncode'] == 0:
                    results[f'gobuster_medium_{port}'] = result
                
                # Subdomain enumeration if port 80/443
                if port in ['80', '443'] and self._is_domain(target):
                    print(f"{Colors.CYAN}[*] Running subdomain enumeration...{Colors.END}")
                    cmd = f"gobuster dns -d {target} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -o {output_dir}/gobuster_subdomains.txt"
                    result = self.execute_command(cmd, timeout=300)
                    if result['returncode'] == 0:
                        results['subdomain_enum'] = result
            
            # SSL/TLS enumeration for HTTPS
            if protocol == 'https':
                print(f"{Colors.CYAN}[*] Running SSL/TLS enumeration...{Colors.END}")
                cmd = f"sslscan {target}:{port}"
                result = self.execute_command(cmd, timeout=60)
                if result['returncode'] == 0:
                    self.save_output(output_dir, f"sslscan_port_{port}.txt", result['stdout'])
                    results[f'sslscan_{port}'] = result
        
        return results
    
    def _detect_web_ports(self, target):
        """Detect open web ports"""
        open_ports = []
        
        # Quick check for common web ports
        for port in self.web_ports:
            cmd = f"nc -zv -w 2 {target} {port} 2>&1"
            result = self.execute_command(cmd, timeout=5)
            
            if 'succeeded' in result.get('stdout', '') or 'connected' in result.get('stderr', ''):
                open_ports.append(port)
        
        return open_ports
    
    def _is_domain(self, target):
        """Check if target is a domain name"""
        # Simple check - if it's not an IP, assume it's a domain
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        return not ip_pattern.match(target)