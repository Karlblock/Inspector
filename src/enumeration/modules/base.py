"""
Base module class for enumeration modules
"""

from abc import ABC, abstractmethod
import subprocess
import os
import shlex
from pathlib import Path
from datetime import datetime
from utils.validators import InputValidator

class BaseModule(ABC):
    def __init__(self):
        self.name = self.__class__.__name__
        
    @abstractmethod
    def run(self, target, session_id, output_dir, **kwargs):
        """Run the enumeration module"""
        pass
    
    def execute_command(self, command, timeout=300):
        """Execute a shell command and return output"""
        try:
            # If command is a list, use it directly (safer)
            if isinstance(command, list):
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
            else:
                # For string commands, use shell but with caution
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
            
            return {
                'command': command,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode,
                'timestamp': datetime.now().isoformat()
            }
        except subprocess.TimeoutExpired:
            return {
                'command': command,
                'error': 'Command timed out',
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'command': command,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def save_output(self, output_dir, filename, content):
        """Save output to file"""
        output_path = Path(output_dir) / filename
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            f.write(content)
        
        return str(output_path)
    
    def parse_ports(self, ports):
        """Parse port specification"""
        if not ports:
            return None
        
        if isinstance(ports, str):
            return ports
        elif isinstance(ports, list):
            return ','.join(map(str, ports))
        else:
            return str(ports)