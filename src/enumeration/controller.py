"""
Enumeration controller - manages enumeration workflows
"""

import os
import json
from pathlib import Path
from datetime import datetime
from utils.colors import Colors
from utils.session import SessionManager
from enumeration.profiles import EnumerationProfiles
from enumeration.modules import nmap, web, smb, ssh, ftp

class EnumerationController:
    def __init__(self):
        self.session_manager = SessionManager()
        self.profiles = EnumerationProfiles()
        self.modules = {
            'nmap': nmap.NmapModule(),
            'web': web.WebModule(),
            'smb': smb.SMBModule(),
            'ssh': ssh.SSHModule(),
            'ftp': ftp.FTPModule()
        }
        
    def start_enumeration(self, session_id, target, name, profile='auto', 
                         ports=None, auto_detect=False, output_dir=None):
        """Start enumeration process"""
        # Set output directory
        if not output_dir:
            output_dir = Path.home() / 'HTB' / 'Machines' / name
        else:
            output_dir = Path(output_dir)
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Get profile
        if profile == 'auto' or auto_detect:
            print(f"{Colors.BLUE}[*] Running initial port scan for service detection...{Colors.END}")
            detected_services = self._detect_services(target, ports)
            profile_data = self._select_profile_for_services(detected_services)
        else:
            profile_data = self.profiles.get_profile(profile)
        
        if not profile_data:
            print(f"{Colors.RED}[-] Invalid profile: {profile}{Colors.END}")
            return
        
        print(f"{Colors.GREEN}[+] Using profile: {profile_data['name']}{Colors.END}")
        
        # Update session with modules
        self.session_manager.update_session(session_id, {
            'pending_modules': profile_data['modules'],
            'output_dir': str(output_dir)
        })
        
        # Run enumeration modules
        for module_name in profile_data['modules']:
            if module_name in self.modules:
                print(f"\n{Colors.CYAN}[*] Running {module_name} enumeration...{Colors.END}")
                
                try:
                    results = self.modules[module_name].run(
                        target=target,
                        session_id=session_id,
                        output_dir=output_dir,
                        ports=ports
                    )
                    
                    # Save results
                    self.session_manager.add_finding(session_id, module_name, results)
                    self.session_manager.mark_module_complete(session_id, module_name)
                    
                    print(f"{Colors.GREEN}[+] {module_name} enumeration completed{Colors.END}")
                    
                    # Sync to wiki if available
                    try:
                        from integrations.wiki_sync import WikiSync
                        wiki = WikiSync()
                        session_data = self.session_manager.get_session(session_id)
                        wiki.sync_findings(session_data, module_name, [results])
                    except:
                        pass
                    
                except Exception as e:
                    print(f"{Colors.RED}[-] Error in {module_name}: {str(e)}{Colors.END}")
        
        # Update session status
        self.session_manager.update_session(session_id, {'status': 'completed'})
        print(f"\n{Colors.GREEN}[+] Enumeration completed! Results saved in: {output_dir}{Colors.END}")
        
        # Sync with platform if available
        try:
            from integrations.platform_sync import PlatformSync
            sync = PlatformSync()
            session_data = self.session_manager.get_session(session_id)
            if session_data:
                sync.sync_enumeration_progress(session_id, session_data, session_data.get('findings', {}))
        except:
            pass
    
    def quick_enumeration(self, session_id, target, top_ports=1000):
        """Quick enumeration for CTF"""
        print(f"{Colors.BLUE}[*] Running quick enumeration...{Colors.END}")
        
        # Quick nmap scan
        output_dir = Path.home() / 'HTB' / 'quick_scans' / target
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Run only essential modules
        quick_modules = ['nmap', 'web']
        
        for module_name in quick_modules:
            if module_name in self.modules:
                print(f"{Colors.CYAN}[*] Running {module_name}...{Colors.END}")
                
                try:
                    results = self.modules[module_name].run(
                        target=target,
                        session_id=session_id,
                        output_dir=output_dir,
                        quick=True,
                        top_ports=top_ports
                    )
                    
                    self.session_manager.add_finding(session_id, module_name, results)
                    
                except Exception as e:
                    print(f"{Colors.RED}[-] Error in {module_name}: {str(e)}{Colors.END}")
        
        print(f"{Colors.GREEN}[+] Quick scan completed!{Colors.END}")
    
    def resume_enumeration(self, session_id):
        """Resume a previous enumeration session"""
        session = self.session_manager.get_session(session_id)
        if not session:
            return
        
        print(f"{Colors.BLUE}[*] Resuming enumeration for {session['name']} ({session['target']}){Colors.END}")
        print(f"{Colors.INFO}[*] Pending modules: {', '.join(session['pending_modules'])}{Colors.END}")
        
        output_dir = Path(session.get('output_dir', Path.home() / 'HTB' / 'Machines' / session['name']))
        
        # Run pending modules
        for module_name in session['pending_modules']:
            if module_name in self.modules:
                print(f"\n{Colors.CYAN}[*] Running {module_name} enumeration...{Colors.END}")
                
                try:
                    results = self.modules[module_name].run(
                        target=session['target'],
                        session_id=session_id,
                        output_dir=output_dir
                    )
                    
                    self.session_manager.add_finding(session_id, module_name, results)
                    self.session_manager.mark_module_complete(session_id, module_name)
                    
                    print(f"{Colors.GREEN}[+] {module_name} enumeration completed{Colors.END}")
                    
                except Exception as e:
                    print(f"{Colors.RED}[-] Error in {module_name}: {str(e)}{Colors.END}")
    
    def _detect_services(self, target, ports=None):
        """Detect services on target"""
        # Run quick nmap scan to detect services
        import subprocess
        
        if ports:
            port_arg = f"-p{ports}"
        else:
            port_arg = "--top-ports 100"
        
        cmd = f"nmap -sV -sC {port_arg} {target} -oG -"
        
        try:
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=60)
            services = self._parse_nmap_output(result.stdout)
            return services
        except Exception as e:
            print(f"{Colors.WARNING}[!] Service detection failed: {str(e)}{Colors.END}")
            return []
    
    def _parse_nmap_output(self, output):
        """Parse nmap output to detect services"""
        services = []
        
        for line in output.split('\n'):
            if '/open/' in line:
                parts = line.split()
                for part in parts:
                    if '/open/' in part:
                        port_info = part.split('/')
                        if len(port_info) >= 5:
                            services.append({
                                'port': port_info[0],
                                'protocol': port_info[1],
                                'service': port_info[4]
                            })
        
        return services
    
    def _select_profile_for_services(self, services):
        """Select appropriate profile based on detected services"""
        service_names = [s['service'] for s in services]
        
        # Also check ports
        ports = [s['port'] for s in services]
        
        # Check for specific service combinations
        if any('http' in s for s in service_names) or '80' in ports or '443' in ports:
            if any('smb' in s or 'netbios' in s for s in service_names):
                return self.profiles.get_profile('windows-basic')
            else:
                return self.profiles.get_profile('web-app')
        elif any('smb' in s or 'netbios' in s or 'ldap' in s for s in service_names):
            return self.profiles.get_profile('windows-ad')
        elif any('ssh' in s for s in service_names):
            return self.profiles.get_profile('linux-basic')
        else:
            return self.profiles.get_profile('basic')
    
    def get_available_profiles(self):
        """Get list of available profiles"""
        return self.profiles.list_profiles()
    
    def get_profile_details(self, profile_name):
        """Get details of a specific profile"""
        return self.profiles.get_profile(profile_name)