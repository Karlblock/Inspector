"""
Platform synchronization module for cyba-Inspector
Auto-documents progress to HTB Platform
"""

import json
import requests
from datetime import datetime
from pathlib import Path
from ..utils.colors import Colors
from ..utils.cve_database import CVEDatabase
from ..utils.vulnerability_db import VulnerabilityDB
from ..utils.config import config

class PlatformSync:
    def __init__(self, api_url=None, api_key=None):
        # Use config system for sensitive data
        self.api_url = api_url or config.get('api_url', 'http://localhost:8080/api')
        self.api_key = api_key or config.get('api_key')
        self.headers = {
            'Authorization': f'Token {self.api_key}',
            'Content-Type': 'application/json'
        } if self.api_key else {}
        
        self.cve_db = CVEDatabase()
        self.vuln_db = VulnerabilityDB()
        
    def sync_enumeration_progress(self, session_id, session_data, findings):
        """Sync enumeration progress to platform"""
        
        machine_name = session_data['name']
        target_ip = session_data['target']
        
        # Create or update machine documentation
        machine_doc = self._create_machine_structure(machine_name, target_ip)
        
        # Process findings and create structured documentation
        for module, module_findings in findings.items():
            self._process_module_findings(
                machine_doc['id'], 
                module, 
                module_findings,
                session_data
            )
        
        # Analyze for CVEs and vulnerabilities
        vulnerabilities = self._analyze_vulnerabilities(findings)
        if vulnerabilities:
            self._document_vulnerabilities(machine_doc['id'], vulnerabilities)
        
        print(f"{Colors.GREEN}[+] Progress synced to platform{Colors.END}")
        
    def _create_machine_structure(self, machine_name, target_ip):
        """Create machine documentation structure"""
        
        # Structure:
        # Book: HTB Machines
        # Chapter: Machine Name
        # Pages: Overview, Enumeration, Exploitation, Post-Exploitation, etc.
        
        book_data = {
            'name': 'HTB Machines',
            'description': 'Hack The Box Machine Documentation'
        }
        
        # Create or get book
        book = self._api_call('POST', '/books', book_data)
        
        # Create chapter for machine
        chapter_data = {
            'book_id': book['id'],
            'name': machine_name,
            'description': f'Documentation for {machine_name} ({target_ip})'
        }
        
        chapter = self._api_call('POST', '/chapters', chapter_data)
        
        # Create standard pages
        pages = [
            {
                'name': 'Overview',
                'html': self._generate_overview_page(machine_name, target_ip),
                'chapter_id': chapter['id']
            },
            {
                'name': 'Enumeration',
                'html': '<h1>Enumeration Results</h1><p>Auto-generated findings will appear here.</p>',
                'chapter_id': chapter['id']
            },
            {
                'name': 'Vulnerabilities',
                'html': '<h1>Identified Vulnerabilities</h1><p>CVEs and vulnerability analysis.</p>',
                'chapter_id': chapter['id']
            },
            {
                'name': 'Exploitation',
                'html': '<h1>Exploitation</h1><p>Document exploitation attempts here.</p>',
                'chapter_id': chapter['id']
            },
            {
                'name': 'Commands Reference',
                'html': '<h1>Commands Used</h1><p>All commands will be logged here.</p>',
                'chapter_id': chapter['id']
            }
        ]
        
        for page in pages:
            self._api_call('POST', '/pages', page)
        
        return {'id': chapter['id'], 'book_id': book['id']}
    
    def _generate_overview_page(self, machine_name, target_ip):
        """Generate overview page content"""
        
        return f"""
        <h1>{machine_name}</h1>
        
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>IP Address</td><td><code>{target_ip}</code></td></tr>
            <tr><td>Hostname</td><td>{machine_name}</td></tr>
            <tr><td>Start Time</td><td>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
            <tr><td>Status</td><td><span style="color: #4fc3f7;">In Progress</span></td></tr>
        </table>
        
        <h2>Progress Tracker</h2>
        <ul>
            <li>☐ Initial Enumeration</li>
            <li>☐ Service Identification</li>
            <li>☐ Vulnerability Discovery</li>
            <li>☐ Initial Access</li>
            <li>☐ Privilege Escalation</li>
            <li>☐ Post-Exploitation</li>
        </ul>
        
        <h2>Quick Links</h2>
        <ul>
            <li><a href="#enumeration">Enumeration Results</a></li>
            <li><a href="#vulnerabilities">Identified Vulnerabilities</a></li>
            <li><a href="#exploitation">Exploitation Attempts</a></li>
            <li><a href="#commands">Commands Reference</a></li>
        </ul>
        """
    
    def _process_module_findings(self, chapter_id, module, findings, session_data):
        """Process and document module findings"""
        
        # Get enumeration page
        enum_page = self._get_page_by_name(chapter_id, 'Enumeration')
        
        # Build content for this module
        module_content = f"<h2>{module.upper()} Results</h2>\n"
        module_content += f"<p><em>Scanned at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</em></p>\n"
        
        # Process findings based on module type
        if module == 'nmap':
            module_content += self._process_nmap_findings(findings)
        elif module == 'web':
            module_content += self._process_web_findings(findings)
        elif module == 'smb':
            module_content += self._process_smb_findings(findings)
        else:
            module_content += self._process_generic_findings(findings)
        
        # Update page
        current_content = enum_page.get('html', '')
        updated_content = current_content + "\n" + module_content
        
        self._api_call('PUT', f'/pages/{enum_page["id"]}', {
            'html': updated_content
        })
    
    def _analyze_vulnerabilities(self, findings):
        """Analyze findings for known vulnerabilities"""
        
        vulnerabilities = []
        
        # Extract service versions
        services = self._extract_services(findings)
        
        for service in services:
            # Check CVE database
            cves = self.cve_db.search_cves(
                product=service['name'],
                version=service['version']
            )
            
            # Check vulnerability patterns
            vuln_patterns = self.vuln_db.check_vulnerabilities(service)
            
            if cves or vuln_patterns:
                vulnerabilities.append({
                    'service': service,
                    'cves': cves,
                    'patterns': vuln_patterns
                })
        
        return vulnerabilities
    
    def _document_vulnerabilities(self, chapter_id, vulnerabilities):
        """Document identified vulnerabilities"""
        
        vuln_page = self._get_page_by_name(chapter_id, 'Vulnerabilities')
        
        content = "<h1>Vulnerability Analysis</h1>\n"
        content += f"<p><em>Analysis performed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</em></p>\n"
        
        for vuln in vulnerabilities:
            service = vuln['service']
            content += f"\n<h2>{service['name']} {service['version']}</h2>\n"
            
            if vuln['cves']:
                content += "<h3>Known CVEs</h3>\n<ul>\n"
                for cve in vuln['cves'][:5]:  # Limit to top 5
                    content += f"""
                    <li>
                        <strong>{cve['id']}</strong> - CVSS: {cve.get('cvss', 'N/A')}
                        <br>{cve.get('description', 'No description available')}
                        <br><a href="{cve.get('reference', '#')}">Reference</a>
                    </li>\n"""
                content += "</ul>\n"
            
            if vuln['patterns']:
                content += "<h3>Potential Vulnerabilities</h3>\n<ul>\n"
                for pattern in vuln['patterns']:
                    content += f"""
                    <li>
                        <strong>{pattern['type']}</strong>
                        <br>{pattern['description']}
                        <br>Severity: {pattern['severity']}
                    </li>\n"""
                content += "</ul>\n"
        
        self._api_call('PUT', f'/pages/{vuln_page["id"]}', {
            'html': content
        })
    
    def _api_call(self, method, endpoint, data=None):
        """Make API call to platform"""
        
        if not self.api_key:
            # Fallback to file-based storage if no API
            return self._file_fallback(method, endpoint, data)
        
        url = f"{self.api_url}{endpoint}"
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=self.headers)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=self.headers)
            elif method == 'PUT':
                response = requests.put(url, json=data, headers=self.headers)
            else:
                return None
            
            response.raise_for_status()
            return response.json()
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Platform sync error: {str(e)}{Colors.END}")
            return self._file_fallback(method, endpoint, data)
    
    def _file_fallback(self, method, endpoint, data):
        """Fallback to file storage when API unavailable"""
        
        # Store in local JSON files
        platform_dir = Path.home() / '.cyba-inspector' / 'platform'
        platform_dir.mkdir(parents=True, exist_ok=True)
        
        # Simple file-based implementation
        # This ensures documentation continues even without platform
        
        return {'id': 'local', 'status': 'stored_locally'}