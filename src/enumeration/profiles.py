"""
Enumeration profiles for different machine types
"""

class EnumerationProfiles:
    def __init__(self):
        self.profiles = {
            'basic': {
                'name': 'basic',
                'description': 'Basic enumeration for all machine types',
                'modules': ['nmap']
            },
            'linux-basic': {
                'name': 'linux-basic',
                'description': 'Standard Linux machine enumeration',
                'modules': ['nmap', 'ssh', 'web', 'ftp']
            },
            'windows-basic': {
                'name': 'windows-basic',
                'description': 'Standard Windows machine enumeration',
                'modules': ['nmap', 'smb', 'web', 'rdp']
            },
            'windows-ad': {
                'name': 'windows-ad',
                'description': 'Active Directory focused enumeration',
                'modules': ['nmap', 'smb', 'ldap', 'kerberos', 'web']
            },
            'web-app': {
                'name': 'web-app',
                'description': 'Web application focused enumeration',
                'modules': ['nmap', 'web', 'api', 'ssl']
            },
            'database': {
                'name': 'database',
                'description': 'Database server enumeration',
                'modules': ['nmap', 'mysql', 'postgres', 'mssql', 'mongodb']
            },
            'quick': {
                'name': 'quick',
                'description': 'Quick CTF enumeration',
                'modules': ['nmap', 'web']
            },
            'full': {
                'name': 'full',
                'description': 'Complete enumeration with all modules',
                'modules': ['nmap', 'web', 'smb', 'ssh', 'ftp', 'ldap', 'ssl', 'dns']
            }
        }
    
    def get_profile(self, name):
        """Get a specific profile"""
        return self.profiles.get(name)
    
    def list_profiles(self):
        """List all available profiles"""
        return [
            {
                'name': name,
                'description': profile['description']
            }
            for name, profile in self.profiles.items()
        ]
    
    def add_custom_profile(self, name, description, modules):
        """Add a custom profile"""
        self.profiles[name] = {
            'name': name,
            'description': description,
            'modules': modules
        }