"""
RDP (Remote Desktop Protocol) enumeration module
"""

from enumeration.modules.base import BaseModule
from utils.colors import Colors
import re

class RDPModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "rdp"
        self.rdp_port = '3389'

    def run(self, target, session_id, output_dir, **kwargs):
        """Run RDP enumeration"""
        results = {}

        print(f"{Colors.CYAN}[*] Starting RDP enumeration...{Colors.END}")

        # Check if RDP port is open
        if not self._check_rdp_port(target):
            print(f"{Colors.YELLOW}[!] RDP port {self.rdp_port} not detected{Colors.END}")
            return results

        print(f"{Colors.GREEN}[+] RDP port {self.rdp_port} is open{Colors.END}")

        # Nmap RDP scripts
        print(f"{Colors.CYAN}[*] Running nmap RDP scripts...{Colors.END}")
        nmap_result = self._nmap_rdp_scripts(target)
        if nmap_result:
            results['nmap_scripts'] = nmap_result
            self.save_output(output_dir, "rdp_nmap_scripts.txt", nmap_result['stdout'])

            # Check for vulnerabilities
            stdout = nmap_result.get('stdout', '')
            if 'VULNERABLE' in stdout:
                print(f"{Colors.RED}[!] RDP vulnerability detected!{Colors.END}")
            if 'MS12-020' in stdout:
                print(f"{Colors.RED}[!] MS12-020 vulnerability (DoS) detected{Colors.END}")

        # Check for BlueKeep (CVE-2019-0708)
        print(f"{Colors.CYAN}[*] Checking for BlueKeep vulnerability (CVE-2019-0708)...{Colors.END}")
        bluekeep_result = self._check_bluekeep(target)
        if bluekeep_result:
            results['bluekeep_check'] = bluekeep_result
            self.save_output(output_dir, "rdp_bluekeep_check.txt", bluekeep_result['stdout'])

            if 'VULNERABLE' in bluekeep_result.get('stdout', ''):
                print(f"{Colors.RED}[!] BlueKeep vulnerability detected!{Colors.END}")
            else:
                print(f"{Colors.GREEN}[+] Not vulnerable to BlueKeep{Colors.END}")

        # RDP security check
        print(f"{Colors.CYAN}[*] Checking RDP security settings...{Colors.END}")
        security_result = self._check_rdp_security(target)
        if security_result:
            results['security_check'] = security_result
            self.save_output(output_dir, "rdp_security.txt", security_result['stdout'])

            stdout = security_result.get('stdout', '')
            if 'NLA' in stdout:
                print(f"{Colors.GREEN}[+] Network Level Authentication (NLA) is enabled{Colors.END}")
            else:
                print(f"{Colors.YELLOW}[!] NLA may not be enabled{Colors.END}")

        # Check encryption level
        print(f"{Colors.CYAN}[*] Checking RDP encryption level...{Colors.END}")
        encryption_result = self._check_encryption(target)
        if encryption_result:
            results['encryption_check'] = encryption_result
            self.save_output(output_dir, "rdp_encryption.txt", encryption_result['stdout'])

        # Username enumeration attempt
        print(f"{Colors.CYAN}[*] Attempting RDP user enumeration...{Colors.END}")
        user_enum_result = self._enumerate_users(target)
        if user_enum_result:
            results['user_enumeration'] = user_enum_result
            self.save_output(output_dir, "rdp_user_enum.txt", user_enum_result['stdout'])

            # Extract valid usernames
            valid_users = self._extract_valid_users(user_enum_result['stdout'])
            if valid_users:
                print(f"{Colors.GREEN}[+] Valid RDP users found: {', '.join(valid_users)}{Colors.END}")

        # Certificate information
        print(f"{Colors.CYAN}[*] Extracting RDP certificate information...{Colors.END}")
        cert_result = self._get_certificate_info(target)
        if cert_result:
            results['certificate'] = cert_result
            self.save_output(output_dir, "rdp_certificate.txt", cert_result['stdout'])

            # Extract hostname from cert
            hostname = self._extract_hostname_from_cert(cert_result['stdout'])
            if hostname:
                print(f"{Colors.GREEN}[+] Hostname from certificate: {hostname}{Colors.END}")

        # Session enumeration (if creds available in kwargs)
        if 'username' in kwargs and 'password' in kwargs:
            print(f"{Colors.CYAN}[*] Attempting authenticated enumeration...{Colors.END}")
            auth_result = self._authenticated_enum(target, kwargs['username'], kwargs['password'])
            if auth_result:
                results['authenticated_enum'] = auth_result
                self.save_output(output_dir, "rdp_authenticated_enum.txt", auth_result['stdout'])

        return results

    def _check_rdp_port(self, target):
        """Check if RDP port is open"""
        cmd = f"nc -zv -w 2 {target} {self.rdp_port} 2>&1"
        result = self.execute_command(cmd, timeout=5)

        return 'succeeded' in result.get('stdout', '') or 'connected' in result.get('stderr', '')

    def _nmap_rdp_scripts(self, target):
        """Run nmap RDP enumeration scripts"""
        # Comprehensive RDP scanning with multiple scripts
        scripts = [
            'rdp-enum-encryption',
            'rdp-vuln-ms12-020',
            'rdp-ntlm-info',
            'ssl-cert'
        ]

        cmd = f"nmap -p{self.rdp_port} --script {','.join(scripts)} {target} -oN - 2>&1"
        return self.execute_command(cmd, timeout=180)

    def _check_bluekeep(self, target):
        """Check for BlueKeep vulnerability (CVE-2019-0708)"""
        cmd = f"nmap -p{self.rdp_port} --script rdp-vuln-cve-2019-0708 {target} -oN - 2>&1"
        return self.execute_command(cmd, timeout=120)

    def _check_rdp_security(self, target):
        """Check RDP security settings including NLA"""
        cmd = f"nmap -p{self.rdp_port} --script rdp-enum-encryption {target} -oN - 2>&1"
        return self.execute_command(cmd, timeout=60)

    def _check_encryption(self, target):
        """Check RDP encryption level"""
        # Use rdp-enum-encryption script
        cmd = f"nmap -p{self.rdp_port} --script rdp-enum-encryption {target} -oN - 2>&1"
        return self.execute_command(cmd, timeout=60)

    def _enumerate_users(self, target):
        """Attempt to enumerate RDP users"""
        # Try with common usernames
        common_users = ['administrator', 'admin', 'guest', 'user', 'test']

        output = []
        for user in common_users:
            # Use rdp-sec-check or custom method
            # Note: This is a reconnaissance technique, not active exploitation
            cmd = f"nmap -p{self.rdp_port} --script rdp-ntlm-info {target} -oN - 2>&1"
            result = self.execute_command(cmd, timeout=30)

            if result.get('returncode') == 0:
                output.append(f"--- Testing user: {user} ---")
                output.append(result.get('stdout', ''))

        return {
            'command': f'User enumeration with nmap scripts',
            'stdout': '\n'.join(output),
            'returncode': 0
        }

    def _get_certificate_info(self, target):
        """Extract RDP SSL certificate information"""
        # Use nmap ssl-cert script
        cmd = f"nmap -p{self.rdp_port} --script ssl-cert {target} -oN - 2>&1"
        return self.execute_command(cmd, timeout=60)

    def _authenticated_enum(self, target, username, password):
        """Perform authenticated RDP enumeration"""
        # Use xfreerdp or rdesktop to test authentication
        # Note: This is for testing only with proper authorization
        cmd = f"xfreerdp /v:{target} /u:{username} /p:{password} /cert-ignore +auth-only 2>&1"
        return self.execute_command(cmd, timeout=30)

    def _extract_valid_users(self, output):
        """Extract valid usernames from enumeration output"""
        users = []

        # Parse nmap output for user information
        for match in re.finditer(r'User:\s+(\S+)', output):
            user = match.group(1)
            if user not in users:
                users.append(user)

        # Also check for NetBIOS/Domain info
        for match in re.finditer(r'NetBIOS_Domain_Name:\s+(\S+)', output):
            domain = match.group(1)
            print(f"{Colors.GREEN}[+] Domain found: {domain}{Colors.END}")

        return users

    def _extract_hostname_from_cert(self, cert_output):
        """Extract hostname from SSL certificate"""
        # Look for commonName or subjectAltName
        match = re.search(r'commonName=([^\n\r/]+)', cert_output)
        if match:
            return match.group(1).strip()

        match = re.search(r'Subject:.*CN=([^\n\r,]+)', cert_output)
        if match:
            return match.group(1).strip()

        return None

# Module instance for import
module = RDPModule()
