"""
HTB Wiki integration for cyba-Inspector
"""

import requests
import json
from datetime import datetime
from ..utils.colors import Colors

class WikiSync:
    def __init__(self, wiki_url="http://localhost:5000"):
        self.wiki_url = wiki_url
        self.api_endpoint = f"{wiki_url}/api/sync"
        
    def sync_findings(self, session_data, module, findings):
        """Sync findings to HTB Wiki"""
        
        machine_name = session_data.get('name', 'Unknown')
        target_ip = session_data.get('target', 'Unknown')
        
        # Format findings for wiki
        content = self._format_findings(module, findings)
        commands = self._extract_commands(findings)
        
        # Create wiki entry
        entry_data = {
            'machine_name': machine_name,
            'ip': target_ip,
            'type': 'enumeration',
            'title': f"{module.upper()} Scan Results",
            'content': content,
            'commands': commands
        }
        
        try:
            response = requests.post(self.api_endpoint, json=entry_data, timeout=5)
            if response.status_code == 200:
                print(f"{Colors.GREEN}[+] Findings synced to wiki{Colors.END}")
            else:
                print(f"{Colors.WARNING}[!] Wiki sync failed: {response.status_code}{Colors.END}")
        except Exception as e:
            print(f"{Colors.WARNING}[!] Wiki not available: {str(e)}{Colors.END}")
    
    def _format_findings(self, module, findings):
        """Format findings for wiki display"""
        
        content = f"## {module.upper()} Enumeration Results\n\n"
        content += f"Scan performed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        if module == 'nmap':
            content += self._format_nmap_findings(findings)
        elif module == 'web':
            content += self._format_web_findings(findings)
        elif module == 'smb':
            content += self._format_smb_findings(findings)
        else:
            content += "### Raw Findings\n\n"
            for finding in findings:
                if isinstance(finding, dict) and 'data' in finding:
                    data = finding['data']
                    if 'stdout' in data:
                        content += f"```\n{data['stdout'][:1000]}...\n```\n\n"
        
        return content
    
    def _format_nmap_findings(self, findings):
        """Format nmap findings"""
        content = "### Port Scan Results\n\n"
        
        for finding in findings:
            if isinstance(finding, dict) and 'data' in finding:
                data = finding['data']
                if 'stdout' in data and 'open' in data['stdout']:
                    # Extract open ports
                    lines = data['stdout'].split('\n')
                    ports = []
                    for line in lines:
                        if '/tcp' in line and 'open' in line:
                            ports.append(line.strip())
                    
                    if ports:
                        content += "| Port | State | Service | Version |\n"
                        content += "|------|-------|---------|--------|\n"
                        for port in ports[:10]:  # Limit to first 10
                            parts = port.split()
                            if len(parts) >= 3:
                                content += f"| {parts[0]} | {parts[1]} | {parts[2]} | {' '.join(parts[3:])} |\n"
                        content += "\n"
        
        return content
    
    def _format_web_findings(self, findings):
        """Format web findings"""
        content = "### Web Enumeration Results\n\n"
        
        for finding in findings:
            if isinstance(finding, dict):
                data = finding.get('data', {})
                command = data.get('command', '')
                
                if 'gobuster' in command:
                    content += "#### Directory Enumeration\n\n"
                    if 'stdout' in data:
                        # Extract found directories
                        lines = data['stdout'].split('\n')
                        dirs = [line for line in lines if 'Status:' in line][:10]
                        if dirs:
                            content += "```\n" + '\n'.join(dirs) + "\n```\n\n"
                
                elif 'nikto' in command:
                    content += "#### Nikto Scan\n\n"
                    content += "Vulnerability scan performed.\n\n"
        
        return content
    
    def _format_smb_findings(self, findings):
        """Format SMB findings"""
        content = "### SMB Enumeration Results\n\n"
        
        for finding in findings:
            if isinstance(finding, dict):
                data = finding.get('data', {})
                command = data.get('command', '')
                
                if 'smbclient' in command and '-L' in command:
                    content += "#### SMB Shares\n\n"
                    if 'stdout' in data:
                        # Extract shares
                        lines = data['stdout'].split('\n')
                        shares = []
                        in_shares = False
                        for line in lines:
                            if 'Sharename' in line:
                                in_shares = True
                                continue
                            elif in_shares and line.strip() and not line.startswith('-'):
                                shares.append(line.strip())
                            elif in_shares and line.startswith('-'):
                                break
                        
                        if shares:
                            content += "| Share | Type | Comment |\n"
                            content += "|-------|------|--------|\n"
                            for share in shares[:10]:
                                parts = share.split(None, 2)
                                if parts:
                                    content += f"| {parts[0]} | {parts[1] if len(parts) > 1 else ''} | {parts[2] if len(parts) > 2 else ''} |\n"
                            content += "\n"
        
        return content
    
    def _extract_commands(self, findings):
        """Extract all commands from findings"""
        commands = []
        
        for finding in findings:
            if isinstance(finding, dict) and 'data' in finding:
                data = finding['data']
                if 'command' in data:
                    commands.append(data['command'])
        
        return '\n'.join(commands)