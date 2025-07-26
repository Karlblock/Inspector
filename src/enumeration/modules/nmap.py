"""
Nmap enumeration module
"""

from enumeration.modules.base import BaseModule
from utils.colors import Colors

class NmapModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "nmap"
        
    def run(self, target, session_id, output_dir, ports=None, quick=False, top_ports=1000, **kwargs):
        """Run nmap enumeration"""
        results = {}
        
        # Quick scan
        if quick:
            print(f"{Colors.CYAN}[*] Running quick nmap scan...{Colors.END}")
            cmd = f"nmap -sV -sC --top-ports {top_ports} {target}"
            result = self.execute_command(cmd, timeout=120)
            
            if result['returncode'] == 0:
                self.save_output(output_dir, "nmap_quick.txt", result['stdout'])
                results['quick_scan'] = result
            
            return results
        
        # Initial TCP scan
        print(f"{Colors.CYAN}[*] Running initial TCP scan...{Colors.END}")
        if ports:
            cmd = f"nmap -sV -sC -p{ports} -oA {output_dir}/nmap_initial {target}"
        else:
            cmd = f"nmap -sV -sC -oA {output_dir}/nmap_initial {target}"
        
        result = self.execute_command(cmd)
        if result['returncode'] == 0:
            results['initial_scan'] = result
            print(f"{Colors.GREEN}[+] Initial scan completed{Colors.END}")
        
        # Full TCP scan
        print(f"{Colors.CYAN}[*] Running full TCP port scan...{Colors.END}")
        cmd = f"nmap -p- -T4 --max-retries 1 --max-scan-delay 20 -oA {output_dir}/nmap_full_tcp {target}"
        result = self.execute_command(cmd, timeout=600)
        
        if result['returncode'] == 0:
            results['full_tcp_scan'] = result
            print(f"{Colors.GREEN}[+] Full TCP scan completed{Colors.END}")
            
            # Extract open ports for detailed scan
            open_ports = self._extract_open_ports(result['stdout'])
            if open_ports:
                print(f"{Colors.CYAN}[*] Running detailed scan on open ports: {open_ports}{Colors.END}")
                cmd = f"nmap -sV -sC -A -p{open_ports} -oA {output_dir}/nmap_detailed {target}"
                detailed_result = self.execute_command(cmd)
                
                if detailed_result['returncode'] == 0:
                    results['detailed_scan'] = detailed_result
                    print(f"{Colors.GREEN}[+] Detailed scan completed{Colors.END}")
        
        # UDP scan (top 20 ports)
        print(f"{Colors.CYAN}[*] Running UDP scan (top 20 ports)...{Colors.END}")
        cmd = f"sudo nmap -sU --top-ports 20 -oA {output_dir}/nmap_udp {target}"
        result = self.execute_command(cmd, timeout=300)
        
        if result['returncode'] == 0:
            results['udp_scan'] = result
            print(f"{Colors.GREEN}[+] UDP scan completed{Colors.END}")
        
        # Vulnerability scan
        print(f"{Colors.CYAN}[*] Running vulnerability scan...{Colors.END}")
        cmd = f"nmap --script vuln -oA {output_dir}/nmap_vuln {target}"
        result = self.execute_command(cmd, timeout=300)
        
        if result['returncode'] == 0:
            results['vuln_scan'] = result
            print(f"{Colors.GREEN}[+] Vulnerability scan completed{Colors.END}")
        
        return results
    
    def _extract_open_ports(self, nmap_output):
        """Extract open ports from nmap output"""
        ports = []
        
        for line in nmap_output.split('\n'):
            if '/tcp' in line and 'open' in line:
                port = line.split('/')[0].strip()
                if port.isdigit():
                    ports.append(port)
        
        return ','.join(ports) if ports else None