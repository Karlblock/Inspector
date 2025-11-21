"""
DNS enumeration module for domain reconnaissance
"""

from enumeration.modules.base import BaseModule
from utils.colors import Colors
import re

class DNSModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "dns"
        self.dns_port = '53'

    def run(self, target, session_id, output_dir, **kwargs):
        """Run DNS enumeration"""
        results = {}

        print(f"{Colors.CYAN}[*] Starting DNS enumeration...{Colors.END}")

        # Get domain from kwargs or try to determine
        domain = kwargs.get('domain', None)
        if not domain:
            domain = self._try_get_domain(target)

        if domain:
            print(f"{Colors.GREEN}[+] Target domain: {domain}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}[!] No domain specified, using IP-based enumeration{Colors.END}")

        # Check if DNS port is open
        if self._check_dns_port(target):
            print(f"{Colors.GREEN}[+] DNS port {self.dns_port} is open{Colors.END}")
        else:
            print(f"{Colors.YELLOW}[!] DNS port {self.dns_port} not detected{Colors.END}")

        # DNS Server version detection
        print(f"{Colors.CYAN}[*] Detecting DNS server version...{Colors.END}")
        version_result = self._detect_dns_version(target)
        if version_result:
            results['version'] = version_result
            self.save_output(output_dir, "dns_version.txt", version_result['stdout'])

            if 'BIND' in version_result.get('stdout', ''):
                print(f"{Colors.GREEN}[+] BIND DNS server detected{Colors.END}")

        # Zone transfer attempt
        if domain:
            print(f"{Colors.CYAN}[*] Attempting zone transfer (AXFR)...{Colors.END}")
            axfr_result = self._attempt_zone_transfer(target, domain)
            if axfr_result:
                results['zone_transfer'] = axfr_result
                self.save_output(output_dir, "dns_zone_transfer.txt", axfr_result['stdout'])

                if 'Transfer failed' not in axfr_result.get('stdout', ''):
                    print(f"{Colors.RED}[!] Zone transfer successful! Domain data exposed{Colors.END}")
                else:
                    print(f"{Colors.GREEN}[+] Zone transfer denied (secure){Colors.END}")

        # DNS record enumeration
        if domain:
            print(f"{Colors.CYAN}[*] Enumerating DNS records...{Colors.END}")

            # A records
            a_result = self._query_record(domain, 'A', target)
            if a_result:
                results['a_records'] = a_result
                self.save_output(output_dir, "dns_a_records.txt", a_result['stdout'])

            # AAAA records
            aaaa_result = self._query_record(domain, 'AAAA', target)
            if aaaa_result:
                results['aaaa_records'] = aaaa_result
                self.save_output(output_dir, "dns_aaaa_records.txt", aaaa_result['stdout'])

            # MX records
            mx_result = self._query_record(domain, 'MX', target)
            if mx_result:
                results['mx_records'] = mx_result
                self.save_output(output_dir, "dns_mx_records.txt", mx_result['stdout'])

                # Extract mail servers
                mail_servers = self._extract_mx_servers(mx_result['stdout'])
                if mail_servers:
                    print(f"{Colors.GREEN}[+] Mail servers found: {', '.join(mail_servers)}{Colors.END}")

            # NS records
            ns_result = self._query_record(domain, 'NS', target)
            if ns_result:
                results['ns_records'] = ns_result
                self.save_output(output_dir, "dns_ns_records.txt", ns_result['stdout'])

            # TXT records
            txt_result = self._query_record(domain, 'TXT', target)
            if txt_result:
                results['txt_records'] = txt_result
                self.save_output(output_dir, "dns_txt_records.txt", txt_result['stdout'])

                # Check for SPF records
                if 'v=spf1' in txt_result.get('stdout', ''):
                    print(f"{Colors.GREEN}[+] SPF record found{Colors.END}")

                # Check for DMARC
                if 'v=DMARC1' in txt_result.get('stdout', ''):
                    print(f"{Colors.GREEN}[+] DMARC policy found{Colors.END}")

            # SOA records
            soa_result = self._query_record(domain, 'SOA', target)
            if soa_result:
                results['soa_records'] = soa_result
                self.save_output(output_dir, "dns_soa_records.txt", soa_result['stdout'])

            # SRV records (useful for AD)
            print(f"{Colors.CYAN}[*] Enumerating SRV records...{Colors.END}")
            srv_result = self._enumerate_srv_records(domain, target)
            if srv_result:
                results['srv_records'] = srv_result
                self.save_output(output_dir, "dns_srv_records.txt", srv_result['stdout'])

        # Subdomain enumeration
        if domain:
            print(f"{Colors.CYAN}[*] Enumerating subdomains...{Colors.END}")
            subdomain_result = self._enumerate_subdomains(domain, target)
            if subdomain_result:
                results['subdomains'] = subdomain_result
                self.save_output(output_dir, "dns_subdomains.txt", subdomain_result['stdout'])

                # Count discovered subdomains
                subdomains = self._extract_subdomains(subdomain_result['stdout'])
                if subdomains:
                    print(f"{Colors.GREEN}[+] Found {len(subdomains)} subdomains{Colors.END}")

        # Reverse DNS lookup
        print(f"{Colors.CYAN}[*] Performing reverse DNS lookup...{Colors.END}")
        reverse_result = self._reverse_lookup(target)
        if reverse_result:
            results['reverse_lookup'] = reverse_result
            self.save_output(output_dir, "dns_reverse_lookup.txt", reverse_result['stdout'])

            hostname = self._extract_hostname(reverse_result['stdout'])
            if hostname:
                print(f"{Colors.GREEN}[+] Reverse DNS: {hostname}{Colors.END}")

        # DNSRecon
        if domain:
            print(f"{Colors.CYAN}[*] Running DNSRecon...{Colors.END}")
            dnsrecon_result = self._run_dnsrecon(domain, target)
            if dnsrecon_result:
                results['dnsrecon'] = dnsrecon_result
                self.save_output(output_dir, "dnsrecon_output.txt", dnsrecon_result['stdout'])

        # Nmap DNS scripts
        print(f"{Colors.CYAN}[*] Running nmap DNS scripts...{Colors.END}")
        nmap_result = self._nmap_dns_scripts(target)
        if nmap_result:
            results['nmap_scripts'] = nmap_result
            self.save_output(output_dir, "nmap_dns_scripts.txt", nmap_result['stdout'])

        return results

    def _check_dns_port(self, target):
        """Check if DNS port is open"""
        cmd = f"nc -zvu -w 2 {target} {self.dns_port} 2>&1"
        result = self.execute_command(cmd, timeout=5)

        return 'succeeded' in result.get('stdout', '') or 'open' in result.get('stdout', '')

    def _try_get_domain(self, target):
        """Try to determine domain from reverse lookup"""
        cmd = f"host {target} 2>&1"
        result = self.execute_command(cmd, timeout=5)

        if result.get('returncode') == 0:
            stdout = result.get('stdout', '')
            match = re.search(r'domain name pointer (\S+)', stdout)
            if match:
                hostname = match.group(1).rstrip('.')
                # Extract domain (last two parts)
                parts = hostname.split('.')
                if len(parts) >= 2:
                    return '.'.join(parts[-2:])

        return None

    def _detect_dns_version(self, target):
        """Detect DNS server version"""
        # Try BIND version query
        cmd = f"dig @{target} version.bind chaos txt 2>&1"
        result = self.execute_command(cmd, timeout=10)

        if result.get('returncode') != 0 or not result.get('stdout'):
            # Alternative: nmap version detection
            cmd = f"nmap -sU -sV -p{self.dns_port} {target} -oN - 2>&1"
            result = self.execute_command(cmd, timeout=60)

        return result

    def _attempt_zone_transfer(self, target, domain):
        """Attempt DNS zone transfer (AXFR)"""
        cmd = f"dig @{target} {domain} AXFR 2>&1"
        result = self.execute_command(cmd, timeout=30)

        # Also try with host command
        if 'Transfer failed' in result.get('stdout', ''):
            cmd = f"host -l {domain} {target} 2>&1"
            result_alt = self.execute_command(cmd, timeout=30)
            if result_alt.get('returncode') == 0:
                result = result_alt

        return result

    def _query_record(self, domain, record_type, nameserver=None):
        """Query specific DNS record type"""
        if nameserver:
            cmd = f"dig @{nameserver} {domain} {record_type} +short 2>&1"
        else:
            cmd = f"dig {domain} {record_type} +short 2>&1"

        return self.execute_command(cmd, timeout=10)

    def _enumerate_srv_records(self, domain, nameserver):
        """Enumerate SRV records (useful for Active Directory)"""
        # Common SRV records for AD
        srv_records = [
            f'_ldap._tcp.{domain}',
            f'_kerberos._tcp.{domain}',
            f'_kpasswd._tcp.{domain}',
            f'_ldap._tcp.dc._msdcs.{domain}',
            f'_kerberos._tcp.dc._msdcs.{domain}',
            f'_gc._tcp.{domain}'  # Global Catalog
        ]

        output = []
        for srv in srv_records:
            cmd = f"dig @{nameserver} {srv} SRV +short 2>&1"
            result = self.execute_command(cmd, timeout=10)
            if result.get('stdout') and result['stdout'].strip():
                output.append(f"--- {srv} ---")
                output.append(result['stdout'])

        return {
            'command': 'SRV record enumeration',
            'stdout': '\n'.join(output),
            'returncode': 0
        }

    def _enumerate_subdomains(self, domain, nameserver):
        """Enumerate subdomains using common prefixes"""
        # Common subdomain prefixes
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'admin', 'portal', 'api', 'dev', 'staging', 'test', 'vpn', 'ssh', 'remote',
            'blog', 'shop', 'store', 'support', 'help', 'secure', 'login', 'cpanel',
            'whm', 'webdisk', 'backup', 'mysql', 'db', 'sql'
        ]

        output = []
        found_count = 0

        for sub in common_subdomains:
            fqdn = f'{sub}.{domain}'
            cmd = f"dig @{nameserver} {fqdn} A +short 2>&1"
            result = self.execute_command(cmd, timeout=5)

            if result.get('stdout') and result['stdout'].strip():
                ip = result['stdout'].strip()
                # Verify it's a valid IP response
                if re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                    output.append(f"{fqdn} -> {ip}")
                    found_count += 1

        return {
            'command': f'Subdomain enumeration for {domain}',
            'stdout': '\n'.join(output) if output else 'No subdomains found',
            'returncode': 0,
            'found_count': found_count
        }

    def _reverse_lookup(self, target):
        """Perform reverse DNS lookup"""
        cmd = f"dig -x {target} +short 2>&1"
        result = self.execute_command(cmd, timeout=10)

        # Also try with host command
        if not result.get('stdout') or not result['stdout'].strip():
            cmd = f"host {target} 2>&1"
            result = self.execute_command(cmd, timeout=10)

        return result

    def _run_dnsrecon(self, domain, nameserver):
        """Run DNSRecon for comprehensive enumeration"""
        cmd = f"dnsrecon -d {domain} -n {nameserver} 2>&1"
        return self.execute_command(cmd, timeout=180)

    def _nmap_dns_scripts(self, target):
        """Run nmap DNS enumeration scripts"""
        scripts = [
            'dns-brute',
            'dns-zone-transfer',
            'dns-nsid',
            'dns-recursion'
        ]

        cmd = f"nmap -sU -p{self.dns_port} --script {','.join(scripts)} {target} -oN - 2>&1"
        return self.execute_command(cmd, timeout=300)

    def _extract_mx_servers(self, output):
        """Extract mail server hostnames from MX records"""
        servers = []
        for match in re.finditer(r'\d+\s+(\S+\.\S+)', output):
            server = match.group(1).rstrip('.')
            if server not in servers:
                servers.append(server)
        return servers

    def _extract_subdomains(self, output):
        """Extract subdomain list from output"""
        subdomains = []
        for line in output.split('\n'):
            if '->' in line:
                subdomain = line.split('->')[0].strip()
                if subdomain not in subdomains:
                    subdomains.append(subdomain)
        return subdomains

    def _extract_hostname(self, output):
        """Extract hostname from reverse lookup output"""
        # Try to match hostname pattern
        match = re.search(r'domain name pointer (\S+)', output)
        if match:
            return match.group(1).rstrip('.')

        # Try direct match (dig +short output)
        lines = output.strip().split('\n')
        if lines and lines[0] and not lines[0].startswith(';'):
            return lines[0].strip().rstrip('.')

        return None

# Module instance for import
module = DNSModule()
