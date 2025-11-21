"""
LDAP enumeration module for Active Directory reconnaissance
"""

from enumeration.modules.base import BaseModule
from utils.colors import Colors
import re

class LDAPModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "ldap"
        self.ldap_ports = ['389', '636', '3268', '3269']  # LDAP, LDAPS, Global Catalog

    def run(self, target, session_id, output_dir, **kwargs):
        """Run LDAP enumeration"""
        results = {}

        print(f"{Colors.CYAN}[*] Starting LDAP enumeration...{Colors.END}")

        # Check if LDAP ports are open
        open_ports = self._check_ldap_ports(target)
        if not open_ports:
            print(f"{Colors.YELLOW}[!] No LDAP ports detected{Colors.END}")
            return results

        print(f"{Colors.GREEN}[+] LDAP ports detected: {', '.join(open_ports)}{Colors.END}")

        # Determine domain context
        domain_context = self._get_domain_context(target)

        # Anonymous bind test
        print(f"{Colors.CYAN}[*] Testing anonymous LDAP bind...{Colors.END}")
        anon_result = self._test_anonymous_bind(target, domain_context)
        if anon_result:
            results['anonymous_bind'] = anon_result
            self.save_output(output_dir, "ldap_anonymous_bind.txt", anon_result['stdout'])

        # LDAP search - Base naming context
        print(f"{Colors.CYAN}[*] Enumerating LDAP naming contexts...{Colors.END}")
        naming_result = self._enumerate_naming_contexts(target)
        if naming_result:
            results['naming_contexts'] = naming_result
            self.save_output(output_dir, "ldap_naming_contexts.txt", naming_result['stdout'])

        # Domain enumeration
        if domain_context:
            print(f"{Colors.CYAN}[*] Enumerating domain objects...{Colors.END}")

            # Users enumeration
            users_result = self._enumerate_users(target, domain_context)
            if users_result:
                results['users'] = users_result
                self.save_output(output_dir, "ldap_users.txt", users_result['stdout'])

                # Extract and display key users
                key_users = self._extract_key_users(users_result['stdout'])
                if key_users:
                    print(f"{Colors.GREEN}[+] Found {len(key_users)} user accounts{Colors.END}")

            # Groups enumeration
            groups_result = self._enumerate_groups(target, domain_context)
            if groups_result:
                results['groups'] = groups_result
                self.save_output(output_dir, "ldap_groups.txt", groups_result['stdout'])

            # Computers enumeration
            computers_result = self._enumerate_computers(target, domain_context)
            if computers_result:
                results['computers'] = computers_result
                self.save_output(output_dir, "ldap_computers.txt", computers_result['stdout'])

            # Domain admins
            print(f"{Colors.CYAN}[*] Enumerating Domain Admins...{Colors.END}")
            admins_result = self._enumerate_domain_admins(target, domain_context)
            if admins_result:
                results['domain_admins'] = admins_result
                self.save_output(output_dir, "ldap_domain_admins.txt", admins_result['stdout'])
                print(f"{Colors.GREEN}[+] Domain Admins enumeration completed{Colors.END}")

            # Service Principal Names (SPNs)
            print(f"{Colors.CYAN}[*] Enumerating SPNs (Kerberoasting targets)...{Colors.END}")
            spn_result = self._enumerate_spns(target, domain_context)
            if spn_result:
                results['spns'] = spn_result
                self.save_output(output_dir, "ldap_spns.txt", spn_result['stdout'])

                # Check for Kerberoastable accounts
                if 'servicePrincipalName:' in spn_result.get('stdout', ''):
                    print(f"{Colors.YELLOW}[!] Potential Kerberoasting targets found!{Colors.END}")

            # AS-REP Roastable accounts
            print(f"{Colors.CYAN}[*] Checking for AS-REP Roastable accounts...{Colors.END}")
            asrep_result = self._enumerate_asrep_roastable(target, domain_context)
            if asrep_result:
                results['asrep_roastable'] = asrep_result
                self.save_output(output_dir, "ldap_asrep_roastable.txt", asrep_result['stdout'])

                if 'DONT_REQ_PREAUTH' in asrep_result.get('stdout', ''):
                    print(f"{Colors.YELLOW}[!] AS-REP Roastable accounts found!{Colors.END}")

        # LDAP null session with ldapsearch
        print(f"{Colors.CYAN}[*] Attempting LDAP null session enumeration...{Colors.END}")
        null_result = self._ldapsearch_null_session(target)
        if null_result:
            results['null_session'] = null_result
            self.save_output(output_dir, "ldap_null_session.txt", null_result['stdout'])

        # Try nmap LDAP scripts
        print(f"{Colors.CYAN}[*] Running nmap LDAP scripts...{Colors.END}")
        nmap_result = self._nmap_ldap_scripts(target)
        if nmap_result:
            results['nmap_scripts'] = nmap_result
            self.save_output(output_dir, "nmap_ldap_scripts.txt", nmap_result['stdout'])

        return results

    def _check_ldap_ports(self, target):
        """Check if LDAP ports are open"""
        open_ports = []

        for port in self.ldap_ports:
            cmd = f"nc -zv -w 2 {target} {port} 2>&1"
            result = self.execute_command(cmd, timeout=5)

            if 'succeeded' in result.get('stdout', '') or 'connected' in result.get('stderr', ''):
                open_ports.append(port)

        return open_ports

    def _get_domain_context(self, target):
        """Try to determine domain DN context"""
        # Try to get naming context from rootDSE
        cmd = f"ldapsearch -x -h {target} -s base namingContexts 2>&1"
        result = self.execute_command(cmd, timeout=10)

        if result.get('returncode') == 0:
            stdout = result.get('stdout', '')
            # Look for DC= pattern
            match = re.search(r'(DC=\w+(?:,DC=\w+)+)', stdout)
            if match:
                return match.group(1)

        # Fallback: try to reverse lookup DNS
        cmd = f"host {target} 2>&1"
        result = self.execute_command(cmd, timeout=5)

        if result.get('returncode') == 0:
            stdout = result.get('stdout', '')
            # Extract domain from PTR record
            match = re.search(r'domain name pointer (\S+)', stdout)
            if match:
                hostname = match.group(1).rstrip('.')
                # Convert hostname to DN
                parts = hostname.split('.')
                if len(parts) >= 2:
                    return ','.join([f'DC={part}' for part in parts[-2:]])

        return None

    def _test_anonymous_bind(self, target, domain_context):
        """Test anonymous LDAP bind"""
        if domain_context:
            cmd = f"ldapsearch -x -h {target} -b '{domain_context}' '(objectClass=*)' -LLL 2>&1"
        else:
            cmd = f"ldapsearch -x -h {target} -b '' '(objectClass=*)' -LLL 2>&1"

        return self.execute_command(cmd, timeout=30)

    def _enumerate_naming_contexts(self, target):
        """Enumerate LDAP naming contexts"""
        cmd = f"ldapsearch -x -h {target} -s base namingContexts -LLL 2>&1"
        return self.execute_command(cmd, timeout=10)

    def _enumerate_users(self, target, domain_context):
        """Enumerate domain users"""
        cmd = f"ldapsearch -x -h {target} -b '{domain_context}' '(objectClass=user)' sAMAccountName userPrincipalName memberOf description -LLL 2>&1"
        return self.execute_command(cmd, timeout=120)

    def _enumerate_groups(self, target, domain_context):
        """Enumerate domain groups"""
        cmd = f"ldapsearch -x -h {target} -b '{domain_context}' '(objectClass=group)' sAMAccountName member description -LLL 2>&1"
        return self.execute_command(cmd, timeout=120)

    def _enumerate_computers(self, target, domain_context):
        """Enumerate domain computers"""
        cmd = f"ldapsearch -x -h {target} -b '{domain_context}' '(objectClass=computer)' dNSHostName operatingSystem -LLL 2>&1"
        return self.execute_command(cmd, timeout=120)

    def _enumerate_domain_admins(self, target, domain_context):
        """Enumerate Domain Admins group members"""
        # Try both CN formats
        cmd = f"ldapsearch -x -h {target} -b '{domain_context}' '(memberOf=CN=Domain Admins,CN=Users,{domain_context})' sAMAccountName -LLL 2>&1"
        result = self.execute_command(cmd, timeout=60)

        # If first attempt fails, try alternative group search
        if not result.get('stdout') or 'result: 0' not in result.get('stdout', ''):
            cmd = f"ldapsearch -x -h {target} -b '{domain_context}' '(&(objectClass=group)(cn=Domain Admins))' member -LLL 2>&1"
            result = self.execute_command(cmd, timeout=60)

        return result

    def _enumerate_spns(self, target, domain_context):
        """Enumerate Service Principal Names for Kerberoasting"""
        cmd = f"ldapsearch -x -h {target} -b '{domain_context}' '(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))' servicePrincipalName sAMAccountName -LLL 2>&1"
        return self.execute_command(cmd, timeout=120)

    def _enumerate_asrep_roastable(self, target, domain_context):
        """Enumerate accounts with DONT_REQ_PREAUTH set (AS-REP Roasting)"""
        # UserAccountControl flag 4194304 = DONT_REQ_PREAUTH
        cmd = f"ldapsearch -x -h {target} -b '{domain_context}' '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' sAMAccountName userAccountControl -LLL 2>&1"
        return self.execute_command(cmd, timeout=120)

    def _ldapsearch_null_session(self, target):
        """Try LDAP null session enumeration"""
        cmd = f"ldapsearch -x -h {target} -b '' -s base '(objectclass=*)' -LLL 2>&1"
        return self.execute_command(cmd, timeout=30)

    def _nmap_ldap_scripts(self, target):
        """Run nmap LDAP enumeration scripts"""
        cmd = f"nmap -p389,636 --script ldap-rootdse,ldap-search,ldap-brute {target} -oN - 2>&1"
        return self.execute_command(cmd, timeout=180)

    def _extract_key_users(self, ldap_output):
        """Extract key user accounts from LDAP output"""
        users = []

        # Extract sAMAccountName
        for match in re.finditer(r'sAMAccountName:\s*(\S+)', ldap_output):
            username = match.group(1)
            if username not in users and username.endswith('$') == False:  # Exclude machine accounts
                users.append(username)

        return users

# Module instance for import
module = LDAPModule()
