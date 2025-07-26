"""
SSH enumeration module
"""

from enumeration.modules.base import BaseModule
from utils.colors import Colors

class SSHModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "ssh"
        
    def run(self, target, session_id, output_dir, **kwargs):
        """Run SSH enumeration"""
        results = {}
        
        print(f"{Colors.CYAN}[*] Starting SSH enumeration...{Colors.END}")
        
        # Check if SSH is running
        cmd = f"nc -zv -w 2 {target} 22 2>&1"
        result = self.execute_command(cmd, timeout=5)
        
        if not ('succeeded' in result.get('stdout', '') or 'connected' in result.get('stderr', '')):
            print(f"{Colors.YELLOW}[!] SSH port not detected{Colors.END}")
            return results
        
        # Get SSH version
        print(f"{Colors.CYAN}[*] Getting SSH version...{Colors.END}")
        cmd = f"nmap -p22 -sV {target}"
        result = self.execute_command(cmd, timeout=30)
        
        if result['returncode'] == 0:
            self.save_output(output_dir, "ssh_version.txt", result['stdout'])
            results['ssh_version'] = result
        
        # SSH audit
        print(f"{Colors.CYAN}[*] Running SSH audit...{Colors.END}")
        cmd = f"nmap -p22 --script ssh-auth-methods,ssh-hostkey,ssh2-enum-algos {target}"
        result = self.execute_command(cmd, timeout=60)
        
        if result['returncode'] == 0:
            self.save_output(output_dir, "ssh_audit.txt", result['stdout'])
            results['ssh_audit'] = result
        
        # Check for weak SSH configurations
        print(f"{Colors.CYAN}[*] Checking SSH configuration...{Colors.END}")
        cmd = f"nmap -p22 --script ssh-* {target}"
        result = self.execute_command(cmd, timeout=120)
        
        if result['returncode'] == 0:
            self.save_output(output_dir, "ssh_scripts.txt", result['stdout'])
            results['ssh_scripts'] = result
        
        # Username enumeration (if applicable)
        print(f"{Colors.CYAN}[*] Checking for username enumeration...{Colors.END}")
        
        # Test with common usernames
        common_users = ['root', 'admin', 'user', 'test', 'guest', 'oracle', 'postgres']
        valid_users = []
        
        for username in common_users:
            # This is a timing-based check, may not always work
            cmd = f"ssh -o BatchMode=yes -o ConnectTimeout=3 {username}@{target} 2>&1"
            result = self.execute_command(cmd, timeout=5)
            
            # Different error messages might indicate valid vs invalid users
            output = result.get('stderr', '') + result.get('stdout', '')
            if 'Permission denied' in output:
                valid_users.append(username)
        
        if valid_users:
            print(f"{Colors.GREEN}[+] Potential valid users found: {', '.join(valid_users)}{Colors.END}")
            self.save_output(output_dir, "ssh_valid_users.txt", '\n'.join(valid_users))
            results['valid_users'] = valid_users
        
        return results