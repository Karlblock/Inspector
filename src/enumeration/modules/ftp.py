"""
FTP enumeration module
"""

from enumeration.modules.base import BaseModule
from utils.colors import Colors

class FTPModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "ftp"
        
    def run(self, target, session_id, output_dir, **kwargs):
        """Run FTP enumeration"""
        results = {}
        
        print(f"{Colors.CYAN}[*] Starting FTP enumeration...{Colors.END}")
        
        # Check if FTP is running
        cmd = f"nc -zv -w 2 {target} 21 2>&1"
        result = self.execute_command(cmd, timeout=5)
        
        if not ('succeeded' in result.get('stdout', '') or 'connected' in result.get('stderr', '')):
            print(f"{Colors.YELLOW}[!] FTP port not detected{Colors.END}")
            return results
        
        # Get FTP banner
        print(f"{Colors.CYAN}[*] Getting FTP banner...{Colors.END}")
        cmd = f"nc -nv {target} 21"
        result = self.execute_command(cmd, timeout=5)
        
        if result.get('stdout'):
            self.save_output(output_dir, "ftp_banner.txt", result['stdout'])
            results['ftp_banner'] = result
        
        # Check anonymous access
        print(f"{Colors.CYAN}[*] Checking anonymous FTP access...{Colors.END}")
        cmd = f"ftp -n {target} <<EOF\nuser anonymous anonymous\nls\nquit\nEOF"
        result = self.execute_command(cmd, timeout=30)
        
        if result['returncode'] == 0 and '230' in result.get('stdout', ''):
            print(f"{Colors.GREEN}[+] Anonymous FTP access allowed!{Colors.END}")
            self.save_output(output_dir, "ftp_anonymous.txt", result['stdout'])
            results['anonymous_access'] = result
            
            # Try to download files if anonymous access
            print(f"{Colors.CYAN}[*] Attempting to list and download files...{Colors.END}")
            cmd = f"wget -r --no-passive-ftp ftp://anonymous:anonymous@{target}/ -P {output_dir}/ftp_downloads/ 2>&1"
            result = self.execute_command(cmd, timeout=120)
            
            if result['returncode'] == 0:
                results['ftp_download'] = result
        
        # Nmap FTP scripts
        print(f"{Colors.CYAN}[*] Running nmap FTP scripts...{Colors.END}")
        cmd = f"nmap -p21 --script ftp-* {target}"
        result = self.execute_command(cmd, timeout=120)
        
        if result['returncode'] == 0:
            self.save_output(output_dir, "nmap_ftp_scripts.txt", result['stdout'])
            results['nmap_ftp'] = result
        
        # Check for FTP bounce
        print(f"{Colors.CYAN}[*] Checking FTP bounce attack...{Colors.END}")
        cmd = f"nmap -p21 --script ftp-bounce {target}"
        result = self.execute_command(cmd, timeout=60)
        
        if result['returncode'] == 0:
            self.save_output(output_dir, "ftp_bounce.txt", result['stdout'])
            results['ftp_bounce'] = result
        
        return results