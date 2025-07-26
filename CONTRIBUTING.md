# Contributing to cyba-Inspector

Thank you for your interest in contributing to cyba-Inspector! This tool is designed to help the Hack The Box community with structured enumeration and learning.

## How to Contribute

### Reporting Issues
- Use the GitHub issue tracker to report bugs
- Include detailed information about the issue
- Provide steps to reproduce the problem

### Submitting Pull Requests
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style
- Follow PEP 8 guidelines for Python code
- Use meaningful variable and function names
- Add comments for complex logic
- Keep functions focused and modular

### Adding New Modules
To add a new enumeration module:

1. Create a new file in `src/enumeration/modules/`
2. Inherit from `BaseModule`
3. Implement the `run()` method
4. Add your module to the appropriate profiles in `profiles.py`

Example:
```python
from enumeration.modules.base import BaseModule
from utils.colors import Colors

class MyModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "mymodule"
        
    def run(self, target, session_id, output_dir, **kwargs):
        """Run my enumeration module"""
        results = {}
        
        # Your enumeration logic here
        
        return results
```

### Security Considerations
- Never hardcode sensitive information
- Use the config system for API keys and secrets
- Validate all user inputs
- Use subprocess safely (prefer list arguments over shell=True)

### Testing
- Test your changes thoroughly
- Include both positive and negative test cases
- Ensure backward compatibility

## Module Status

### Implemented Modules
- ✅ nmap - Port scanning and service detection
- ✅ web - Web enumeration
- ✅ smb - SMB enumeration
- ✅ ssh - SSH enumeration  
- ✅ ftp - FTP enumeration
- ✅ version_scanner - Version detection

### Planned Modules (Contributors Welcome!)
- 🔄 ldap - LDAP enumeration
- 🔄 kerberos - Kerberos enumeration
- 🔄 dns - DNS enumeration
- 🔄 mysql - MySQL enumeration
- 🔄 postgres - PostgreSQL enumeration
- 🔄 mssql - MSSQL enumeration
- 🔄 mongodb - MongoDB enumeration
- 🔄 api - API enumeration
- 🔄 ssl - SSL/TLS analysis
- 🔄 rdp - RDP enumeration

## Community Guidelines
- Be respectful and inclusive
- Help others learn and grow
- Share knowledge and techniques
- Remember this is for educational purposes

## Questions?
Feel free to open an issue for any questions about contributing.