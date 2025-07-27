"""
Input validation utilities for cyba-Inspector
Provides secure input validation and sanitization
"""

import re
import ipaddress
import shlex
from pathlib import Path
import socket

class InputValidator:
    """Validate and sanitize user inputs"""
    
    @staticmethod
    def validate_ip(ip_string):
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip_string)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_port(port):
        """Validate port number or range"""
        if isinstance(port, int):
            return 1 <= port <= 65535
        
        if isinstance(port, str):
            # Single port
            if port.isdigit():
                return 1 <= int(port) <= 65535
            
            # Port range (e.g., "80-443")
            if '-' in port:
                try:
                    start, end = port.split('-')
                    start, end = int(start), int(end)
                    return 1 <= start <= end <= 65535
                except ValueError:
                    return False
            
            # Comma-separated ports (e.g., "80,443,8080")
            if ',' in port:
                try:
                    ports = [int(p.strip()) for p in port.split(',')]
                    return all(1 <= p <= 65535 for p in ports)
                except ValueError:
                    return False
        
        return False
    
    @staticmethod
    def validate_profile_name(name):
        """Validate enumeration profile name"""
        valid_profiles = [
            'basic', 'linux-basic', 'windows-basic', 
            'windows-ad', 'web-app', 'database', 
            'quick', 'full'
        ]
        return name in valid_profiles
    
    @staticmethod
    def validate_machine_name(name):
        """Validate machine name (alphanumeric, dash, underscore)"""
        pattern = r'^[a-zA-Z0-9_-]+$'
        return bool(re.match(pattern, name)) and len(name) <= 50
    
    @staticmethod
    def sanitize_command_arg(arg):
        """Safely quote command line argument"""
        return shlex.quote(str(arg))
    
    @staticmethod
    def validate_file_path(path, must_exist=False):
        """Validate file path"""
        try:
            p = Path(path)
            # Check for path traversal attempts
            if '..' in p.parts:
                return False
            
            if must_exist:
                return p.exists()
            
            return True
        except:
            return False
    
    @staticmethod
    def validate_url(url):
        """Basic URL validation"""
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return bool(url_pattern.match(url))
    
    @staticmethod
    def sanitize_output(text):
        """Remove potentially dangerous content from output"""
        # Remove ANSI escape sequences
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)
    
    @staticmethod
    def validate_domain(domain):
        """Validate domain name"""
        # Basic domain validation pattern
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
            r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        
        # Check length
        if not domain or len(domain) > 253:
            return False
            
        # Check pattern
        if not domain_pattern.match(domain):
            return False
            
        # Check each label
        labels = domain.split('.')
        for label in labels:
            if not label or len(label) > 63:
                return False
                
        return True
    
    @staticmethod
    def validate_target(target):
        """Validate target - can be IP address or domain name"""
        # First try as IP
        if InputValidator.validate_ip(target):
            return True
        # Then try as domain
        return InputValidator.validate_domain(target)
    
    @staticmethod
    def resolve_domain(domain):
        """Resolve domain to IP address"""
        try:
            # Get the first IP address
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror:
            return None
    
    @staticmethod
    def get_target_info(target):
        """Get target information - returns (ip, hostname)"""
        # Check if it's an IP
        if InputValidator.validate_ip(target):
            try:
                # Try reverse lookup
                hostname = socket.gethostbyaddr(target)[0]
                return target, hostname
            except:
                return target, None
        
        # Check if it's a domain
        elif InputValidator.validate_domain(target):
            ip = InputValidator.resolve_domain(target)
            if ip:
                return ip, target
            else:
                return None, target
        
        return None, None