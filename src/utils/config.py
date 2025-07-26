"""
Configuration management for cyba-Inspector
Handles environment variables and secure configuration
"""

import os
from pathlib import Path
import json

class Config:
    """Centralized configuration management"""
    
    def __init__(self):
        self.config_dir = Path.home() / '.cyba-inspector' / 'config'
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.config_file = self.config_dir / 'config.json'
        self._load_config()
    
    def _load_config(self):
        """Load configuration from file and environment"""
        # Default configuration
        self.config = {
            'api_url': os.getenv('CYBA_API_URL', 'http://localhost:8080/api'),
            'api_key': os.getenv('CYBA_API_KEY', None),
            'session_dir': os.getenv('CYBA_SESSION_DIR', str(Path.home() / '.cyba-inspector' / 'sessions')),
            'timeout_short': int(os.getenv('CYBA_TIMEOUT_SHORT', '120')),
            'timeout_long': int(os.getenv('CYBA_TIMEOUT_LONG', '600')),
            'max_threads': int(os.getenv('CYBA_MAX_THREADS', '5')),
        }
        
        # Load from config file if exists
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    file_config = json.load(f)
                    # File config doesn't override environment variables
                    for key, value in file_config.items():
                        if key not in os.environ and key.upper() not in os.environ:
                            self.config[key] = value
            except json.JSONDecodeError:
                pass
    
    def get(self, key, default=None):
        """Get configuration value"""
        return self.config.get(key, default)
    
    def set(self, key, value):
        """Set configuration value (runtime only)"""
        self.config[key] = value
    
    def save(self):
        """Save current configuration to file (excluding sensitive data)"""
        # Don't save API keys to file
        safe_config = {k: v for k, v in self.config.items() if 'key' not in k.lower() and 'password' not in k.lower()}
        with open(self.config_file, 'w') as f:
            json.dump(safe_config, f, indent=2)

# Global config instance
config = Config()