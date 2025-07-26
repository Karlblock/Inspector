"""
Report generator for cyba-HTB
"""

import json
from datetime import datetime
from pathlib import Path
from utils.session import SessionManager

class ReportGenerator:
    def __init__(self):
        self.session_manager = SessionManager()
        
    def generate_report(self, session_id, format='markdown', output_file=None):
        """Generate report in specified format"""
        session = self.session_manager.get_session(session_id)
        if not session:
            return False
        
        if format == 'markdown':
            content = self._generate_markdown_report(session)
        elif format == 'json':
            content = self._generate_json_report(session)
        elif format == 'html':
            content = self._generate_html_report(session)
        else:
            return False
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(content)
            
            # Update GitBook documentation
            self._update_gitbook_docs(session, output_file)
        else:
            print(content)
        
        return True
    
    def _generate_markdown_report(self, session):
        """Generate Markdown report"""
        report = f"""# Enumeration Report - {session['name']}

**Target**: `{session['target']}`  
**Date**: {session['created'][:10]}  
**Time**: {session['created'][11:19]}  
**Profile**: {session['profile']}  
**Session ID**: `{session['id']}`

---

## Executive Summary

- **Total modules executed**: {len(session['completed_modules'])}
- **Status**: {'✅ Completed' if len(session['pending_modules']) == 0 else '⚠️  Partial - ' + str(len(session['pending_modules'])) + ' modules pending'}
- **Output directory**: `{session.get('output_dir', 'N/A')}`

## Scan Results Overview

"""
        
        # Add quick overview of findings
        open_ports = []
        services = []
        
        # Extract key findings for overview
        findings = session.get('findings', {})
        if 'nmap' in findings:
            for finding in findings['nmap']:
                data = finding['data']
                if isinstance(data, dict) and 'stdout' in data:
                    ports = self._extract_ports_from_nmap(data['stdout'])
                    open_ports.extend(ports)
        
        if open_ports:
            report += f"### 🔍 Open Ports Discovered\n\n"
            report += "| Port | Service | Version |\n"
            report += "|------|---------|--------|\n"
            for port in list(set(open_ports)):
                report += f"| {port} | - | - |\n"
            report += "\n"
        
        report += "## Detailed Findings\n\n"""
        
        # Add findings by module
        for module, findings in session.get('findings', {}).items():
            report += f"### {module.upper()}\n\n"
            
            for finding in findings:
                timestamp = finding['timestamp'][:19]
                data = finding['data']
                
                if isinstance(data, dict):
                    if 'command' in data:
                        report += f"**Command**: `{data['command']}`\n"
                        report += f"**Timestamp**: {timestamp}\n\n"
                        
                        if 'error' in data:
                            report += f"**Error**: {data['error']}\n\n"
                        elif data.get('returncode') == 0:
                            report += "**Status**: Success\n\n"
                            
                            # Add key findings from output
                            if module == 'nmap' and 'stdout' in data:
                                ports = self._extract_ports_from_nmap(data['stdout'])
                                if ports:
                                    report += "**Open Ports**:\n"
                                    for port in ports:
                                        report += f"- {port}\n"
                                    report += "\n"
                            
                            elif module == 'smb' and 'stdout' in data:
                                shares = self._extract_smb_shares(data['stdout'])
                                if shares:
                                    report += "**SMB Shares**:\n"
                                    for share in shares:
                                        report += f"- {share}\n"
                                    report += "\n"
                        else:
                            report += f"**Status**: Failed (return code: {data.get('returncode')})\n\n"
                else:
                    report += f"{data}\n\n"
            
            report += "---\n\n"
        
        # Add notes
        if session.get('notes'):
            report += "## Notes\n\n"
            for note_entry in session['notes']:
                timestamp = note_entry['timestamp'][:19]
                note = note_entry['note']
                report += f"- **[{timestamp}]** {note}\n"
            report += "\n"
        
        # Add recommendations
        report += self._generate_recommendations(session)
        
        # Add next steps
        report += "\n## Next Steps\n\n"
        report += "1. Review all findings and identify potential attack vectors\n"
        report += "2. Research vulnerabilities for discovered services\n"
        report += "3. Attempt exploitation of identified weaknesses\n"
        report += "4. Document successful exploitation methods\n\n"
        
        # Add commands reference
        report += "## Quick Commands Reference\n\n"
        report += "```bash\n"
        report += f"# Resume this session\n"
        report += f"cyba-htb resume {session['id']}\n\n"
        report += f"# Generate updated report\n"
        report += f"cyba-htb report {session['id']} -f markdown -o {session['name']}_enum_updated.md\n"
        report += "```\n"
        
        return report
    
    def _generate_json_report(self, session):
        """Generate JSON report"""
        return json.dumps(session, indent=2)
    
    def _generate_html_report(self, session):
        """Generate HTML report"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Enumeration Report - {session['name']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1, h2, h3 {{ color: #333; }}
        .info {{ background: #f0f0f0; padding: 10px; border-radius: 5px; }}
        .finding {{ margin: 20px 0; padding: 15px; border-left: 3px solid #4CAF50; }}
        .error {{ border-left-color: #f44336; }}
        code {{ background: #f5f5f5; padding: 2px 5px; border-radius: 3px; }}
        pre {{ background: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>Enumeration Report - {session['name']}</h1>
    
    <div class="info">
        <p><strong>Target:</strong> {session['target']}</p>
        <p><strong>Date:</strong> {session['created'][:10]}</p>
        <p><strong>Profile:</strong> {session['profile']}</p>
        <p><strong>Session ID:</strong> {session['id']}</p>
    </div>
    
    <h2>Summary</h2>
    <p>Total modules executed: {len(session['completed_modules'])}</p>
    <p>Pending modules: {len(session['pending_modules'])}</p>
    
    <h2>Findings</h2>
"""
        
        # Add findings
        for module, findings in session.get('findings', {}).items():
            html += f"<h3>{module.upper()}</h3>\n"
            
            for finding in findings:
                data = finding['data']
                if isinstance(data, dict) and 'command' in data:
                    css_class = "finding error" if 'error' in data else "finding"
                    html += f'<div class="{css_class}">\n'
                    html += f'<p><strong>Command:</strong> <code>{data["command"]}</code></p>\n'
                    
                    if 'error' in data:
                        html += f'<p><strong>Error:</strong> {data["error"]}</p>\n'
                    elif data.get('returncode') == 0:
                        html += '<p><strong>Status:</strong> Success</p>\n'
                    
                    html += '</div>\n'
        
        html += """
</body>
</html>"""
        
        return html
    
    def _extract_ports_from_nmap(self, output):
        """Extract open ports from nmap output"""
        ports = []
        for line in output.split('\n'):
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if parts:
                    ports.append(parts[0])
        return ports
    
    def _extract_smb_shares(self, output):
        """Extract SMB shares from output"""
        shares = []
        in_shares = False
        
        for line in output.split('\n'):
            if 'Sharename' in line:
                in_shares = True
                continue
            elif in_shares and line.strip() and not line.startswith('-'):
                parts = line.split()
                if parts:
                    shares.append(parts[0])
            elif in_shares and line.startswith('-'):
                break
        
        return shares
    
    def _generate_recommendations(self, session):
        """Generate recommendations based on findings"""
        recommendations = "\n## Recommendations\n\n"
        
        findings = session.get('findings', {})
        
        # Check for web findings
        if 'web' in findings:
            recommendations += "- Web services detected. Consider:\n"
            recommendations += "  - Manual browsing and functionality mapping\n"
            recommendations += "  - Checking for default credentials\n"
            recommendations += "  - Testing for common vulnerabilities (SQLi, XSS, etc.)\n\n"
        
        # Check for SMB findings
        if 'smb' in findings:
            recommendations += "- SMB services detected. Consider:\n"
            recommendations += "  - Testing for null/guest authentication\n"
            recommendations += "  - Enumerating users and groups\n"
            recommendations += "  - Checking for sensitive files in shares\n\n"
        
        # Check for SSH findings
        if 'ssh' in findings:
            recommendations += "- SSH service detected. Consider:\n"
            recommendations += "  - Brute-forcing with common credentials\n"
            recommendations += "  - Checking for SSH key reuse\n"
            recommendations += "  - Testing for username enumeration\n\n"
        
        return recommendations
    
    def _update_gitbook_docs(self, session, output_file):
        """Update GitBook documentation with scan results"""
        try:
            gitbook_dir = Path.home() / "HTB" / "htb-docs"
            if not gitbook_dir.exists():
                return
                
            machine_name = session.get('name', 'Unknown')
            target_ip = session.get('target', 'Unknown')
            
            # Determine category based on current directory
            current_dir = Path.cwd()
            category = "machines"
            if "StartingPoint" in str(current_dir):
                category = "starting-point"
            
            # Create/update machine writeup
            machine_dir = gitbook_dir / category
            machine_dir.mkdir(exist_ok=True)
            
            writeup_file = machine_dir / f"{machine_name.lower()}.md"
            
            # Read existing content or create new
            if writeup_file.exists():
                with open(writeup_file, 'r') as f:
                    content = f.read()
                
                # Update enumeration section
                if "## Enumeration Results" in content:
                    # Find the section and update
                    lines = content.split('\n')
                    enum_index = -1
                    for i, line in enumerate(lines):
                        if line.strip() == "## Enumeration Results":
                            enum_index = i
                            break
                    
                    if enum_index >= 0:
                        # Insert new scan link after the header
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
                        scan_link = f"\n**Latest scan** ({timestamp}): [View Report](./{Path(output_file).name})\n"
                        lines.insert(enum_index + 1, scan_link)
                        content = '\n'.join(lines)
                else:
                    # Add enumeration section
                    content += f"\n\n## Enumeration Results\n\n"
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
                    content += f"**Latest scan** ({timestamp}): [View Report](./{Path(output_file).name})\n"
                
                with open(writeup_file, 'w') as f:
                    f.write(content)
            else:
                # Create new writeup
                with open(writeup_file, 'w') as f:
                    f.write(f"# {machine_name}\n\n")
                    f.write("## Machine Information\n\n")
                    f.write("| Property | Value |\n")
                    f.write("|----------|-------|\n")
                    f.write(f"| **Name** | {machine_name} |\n")
                    f.write(f"| **IP** | {target_ip} |\n")
                    f.write(f"| **Category** | {category.replace('-', ' ').title()} |\n\n")
                    f.write("## Enumeration Results\n\n")
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
                    f.write(f"**Latest scan** ({timestamp}): [View Report](./{Path(output_file).name})\n\n")
                    f.write("## Initial Access\n\n")
                    f.write("*[To be documented...]*\n\n")
                    f.write("## Privilege Escalation\n\n")
                    f.write("*[To be documented...]*\n\n")
                    f.write("## Lessons Learned\n\n")
                    f.write("*[To be documented...]*\n")
                
                # Update SUMMARY.md
                summary_file = gitbook_dir / "SUMMARY.md"
                if summary_file.exists():
                    with open(summary_file, 'r') as f:
                        summary_content = f.read()
                    
                    if machine_name.lower() not in summary_content.lower():
                        lines = summary_content.split('\n')
                        
                        # Find the right section
                        section_header = "## Starting Point" if category == "starting-point" else "## Machines"
                        insert_index = -1
                        
                        for i, line in enumerate(lines):
                            if line.strip() == section_header:
                                # Find next empty line or section
                                j = i + 1
                                while j < len(lines) and lines[j].strip() and not lines[j].startswith('##'):
                                    j += 1
                                insert_index = j
                                break
                        
                        if insert_index > 0:
                            lines.insert(insert_index, f"* [{machine_name}]({category}/{machine_name.lower()}.md)")
                            
                            with open(summary_file, 'w') as f:
                                f.write('\n'.join(lines))
            
            print(f"\n[+] Updated GitBook documentation for {machine_name}")
            
        except Exception as e:
            # Silently fail - GitBook update is optional
            pass