"""
SMB enumeration module
"""

from enumeration.modules.base import BaseModule
from utils.colors import Colors

class SMBModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "smb"
        self.smb_ports = ['139', '445']
        
    def run(self, target, session_id, output_dir, **kwargs):
        """Run SMB enumeration"""
        results = {}
        
        print(f"{Colors.CYAN}[*] Starting SMB enumeration...{Colors.END}")
        
        # Check if SMB ports are open
        open_ports = self._check_smb_ports(target)
        if not open_ports:
            print(f"{Colors.YELLOW}[!] No SMB ports detected{Colors.END}")
            return results
        
        # SMBClient - List shares
        print(f"{Colors.CYAN}[*] Listing SMB shares...{Colors.END}")
        cmd = f"smbclient -L //{target} -N"
        result = self.execute_command(cmd, timeout=30)
        
        if result['returncode'] == 0:
            self.save_output(output_dir, "smbclient_list.txt", result['stdout'])
            results['smbclient_list'] = result
        
        # Enum4linux
        print(f"{Colors.CYAN}[*] Running enum4linux...{Colors.END}")
        cmd = f"enum4linux -a {target}"
        result = self.execute_command(cmd, timeout=300)
        
        if result['returncode'] == 0:
            self.save_output(output_dir, "enum4linux.txt", result['stdout'])
            results['enum4linux'] = result
            print(f"{Colors.GREEN}[+] enum4linux completed{Colors.END}")
        
        # SMBMap
        print(f"{Colors.CYAN}[*] Running smbmap...{Colors.END}")
        cmd = f"smbmap -H {target}"
        result = self.execute_command(cmd, timeout=60)
        
        if result['returncode'] == 0:
            self.save_output(output_dir, "smbmap.txt", result['stdout'])
            results['smbmap'] = result
        
        # CrackMapExec
        print(f"{Colors.CYAN}[*] Running crackmapexec...{Colors.END}")
        cmd = f"crackmapexec smb {target}"
        result = self.execute_command(cmd, timeout=30)
        
        if result['returncode'] == 0:
            self.save_output(output_dir, "crackmapexec_info.txt", result['stdout'])
            results['crackmapexec_info'] = result
        
        # Check for anonymous access
        print(f"{Colors.CYAN}[*] Checking anonymous access...{Colors.END}")
        cmd = f"smbmap -H {target} -u '' -p ''"
        result = self.execute_command(cmd, timeout=60)
        
        if result['returncode'] == 0:
            self.save_output(output_dir, "smbmap_anonymous.txt", result['stdout'])
            results['anonymous_access'] = result
            
            # If anonymous access, try to list files
            if 'READ' in result.get('stdout', ''):
                print(f"{Colors.GREEN}[+] Anonymous access detected, listing files...{Colors.END}")
                cmd = f"smbmap -H {target} -u '' -p '' -R"
                result = self.execute_command(cmd, timeout=120)
                if result['returncode'] == 0:
                    self.save_output(output_dir, "smbmap_anonymous_files.txt", result['stdout'])
                    results['anonymous_files'] = result
        
        # RPC enumeration
        print(f"{Colors.CYAN}[*] Attempting RPC enumeration...{Colors.END}")
        cmd = f"rpcclient -U '' -N {target} -c 'enumdomusers'"
        result = self.execute_command(cmd, timeout=30)
        
        if result['returncode'] == 0 and 'user:' in result.get('stdout', ''):
            self.save_output(output_dir, "rpcclient_users.txt", result['stdout'])
            results['rpc_users'] = result
            
            # Try more RPC commands
            rpc_commands = ['enumdomgroups', 'enumdomains', 'querydominfo']
            for rpc_cmd in rpc_commands:
                cmd = f"rpcclient -U '' -N {target} -c '{rpc_cmd}'"
                result = self.execute_command(cmd, timeout=30)
                if result['returncode'] == 0:
                    self.save_output(output_dir, f"rpcclient_{rpc_cmd}.txt", result['stdout'])
                    results[f'rpc_{rpc_cmd}'] = result
        
        return results
    
    def _check_smb_ports(self, target):
        """Check if SMB ports are open"""
        open_ports = []
        
        for port in self.smb_ports:
            cmd = f"nc -zv -w 2 {target} {port} 2>&1"
            result = self.execute_command(cmd, timeout=5)
            
            if 'succeeded' in result.get('stdout', '') or 'connected' in result.get('stderr', ''):
                open_ports.append(port)
        
        return open_ports