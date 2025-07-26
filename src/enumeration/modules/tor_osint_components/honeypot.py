"""
Tor Honeypot System - Deploy and manage .onion honeypots for threat detection
"""

import os
import json
import subprocess
import hashlib
import secrets
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import asyncio
from pathlib import Path
import shutil




class TorHoneypotSystem:
    """
    Create and manage Tor hidden service honeypots
    """
    
    def __init__(self, base_dir: str = "/var/lib/tor/honeypots"):
        # Logger removed - using print statements
        self.base_dir = Path(base_dir)
        self.honeypots = {}
        self.monitoring_data = []
        
        # Honeypot templates
        self.honeypot_templates = {
            'fake_backup': {
                'name_pattern': '{org}-backup',
                'content': self._generate_backup_page,
                'triggers': ['download_attempt', 'credential_entry'],
                'risk_score': 0.8
            },
            'fake_admin': {
                'name_pattern': '{org}-admin',
                'content': self._generate_admin_page,
                'triggers': ['login_attempt', 'brute_force', 'sql_injection'],
                'risk_score': 0.9
            },
            'fake_api': {
                'name_pattern': '{org}-api',
                'content': self._generate_api_page,
                'triggers': ['api_key_probe', 'endpoint_scan'],
                'risk_score': 0.7
            },
            'fake_leak': {
                'name_pattern': '{org}-leaks',
                'content': self._generate_leak_page,
                'triggers': ['data_access', 'scraping_attempt'],
                'risk_score': 0.6
            },
            'fake_internal': {
                'name_pattern': '{org}-internal',
                'content': self._generate_internal_page,
                'triggers': ['access_attempt', 'enumeration'],
                'risk_score': 0.7
            }
        }
        
    def create_honeypot_suite(self, organization: str, 
                            honeypot_types: List[str] = None,
                            custom_names: Dict[str, str] = None) -> Dict:
        """
        Create a suite of honeypot hidden services
        """
        print(f"Creating honeypot suite for {organization}")
        
        if honeypot_types is None:
            honeypot_types = list(self.honeypot_templates.keys())
        
        deployment = {
            'organization': organization,
            'timestamp': datetime.now().isoformat(),
            'honeypots': {},
            'deployment_status': 'initializing'
        }
        
        for hp_type in honeypot_types:
            if hp_type not in self.honeypot_templates:
                print(f"Unknown honeypot type: {hp_type}")
                continue
            
            template = self.honeypot_templates[hp_type]
            
            # Generate honeypot name
            if custom_names and hp_type in custom_names:
                hp_name = custom_names[hp_type]
            else:
                hp_name = template['name_pattern'].format(org=organization.lower())
            
            # Create honeypot
            try:
                hp_config = self._create_single_honeypot(
                    hp_name, 
                    hp_type, 
                    template, 
                    organization
                )
                deployment['honeypots'][hp_type] = hp_config
                self.honeypots[hp_config['onion_address']] = hp_config
                
            except Exception as e:
                print(f"Failed to create {hp_type} honeypot: {e}")
                deployment['honeypots'][hp_type] = {'error': str(e)}
        
        deployment['deployment_status'] = 'active'
        
        # Save deployment configuration
        self._save_deployment_config(deployment)
        
        return deployment
    
    def _create_single_honeypot(self, name: str, hp_type: str, 
                               template: Dict, organization: str) -> Dict:
        """Create a single honeypot hidden service"""
        
        # Create directory structure
        hp_dir = self.base_dir / name
        hp_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate hidden service
        hs_dir = hp_dir / 'hidden_service'
        hs_dir.mkdir(exist_ok=True)
        
        # Create torrc configuration
        torrc_content = f"""
# Honeypot: {name}
HiddenServiceDir {hs_dir}
HiddenServicePort 80 127.0.0.1:{self._get_free_port()}
HiddenServicePort 443 127.0.0.1:{self._get_free_port()}
"""
        
        torrc_path = hp_dir / 'torrc'
        torrc_path.write_text(torrc_content)
        
        # Start hidden service
        self._start_hidden_service(torrc_path)
        
        # Wait for onion address generation
        hostname_path = hs_dir / 'hostname'
        onion_address = self._wait_for_onion_address(hostname_path)
        
        # Generate honeypot content
        content = template['content'](organization)
        
        # Set up web server
        web_config = self._setup_honeypot_webserver(
            hp_dir, 
            content, 
            template['triggers']
        )
        
        # Create monitoring configuration
        monitor_config = {
            'name': name,
            'type': hp_type,
            'onion_address': onion_address,
            'created_at': datetime.now().isoformat(),
            'triggers': template['triggers'],
            'risk_score': template['risk_score'],
            'web_config': web_config,
            'log_file': str(hp_dir / 'access.log'),
            'alert_log': str(hp_dir / 'alerts.log'),
            'status': 'active'
        }
        
        # Initialize monitoring
        self._initialize_monitoring(monitor_config)
        
        return monitor_config
    
    def _generate_backup_page(self, organization: str) -> str:
        """Generate fake backup page content"""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>{organization} Backup Portal</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #1a1a1a; color: #fff; }}
        .container {{ max-width: 600px; margin: 50px auto; padding: 20px; }}
        .warning {{ color: #ff6b6b; font-weight: bold; }}
        .form-group {{ margin: 20px 0; }}
        input {{ width: 100%; padding: 10px; margin: 5px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{organization} Backup System</h1>
        <p class="warning">⚠️ INTERNAL USE ONLY - AUTHORIZED PERSONNEL ONLY</p>
        
        <div class="backup-list">
            <h3>Available Backups:</h3>
            <ul>
                <li>database_backup_2024.tar.gz.enc (2.3GB)</li>
                <li>user_data_export_2024.zip.enc (1.7GB)</li>
                <li>system_config_backup.tar.gz (423MB)</li>
            </ul>
        </div>
        
        <form id="download-form">
            <div class="form-group">
                <label>Access Code:</label>
                <input type="password" name="access_code" required>
            </div>
            <button type="submit">Download</button>
        </form>
        
        <script>
            // Honeypot tracking
            document.getElementById('download-form').addEventListener('submit', function(e) {{
                e.preventDefault();
                // Log attempt
                fetch('/log', {{
                    method: 'POST',
                    body: JSON.stringify({{
                        action: 'download_attempt',
                        timestamp: new Date().toISOString(),
                        data: new FormData(e.target)
                    }})
                }});
                alert('Access Denied - This incident has been reported');
            }});
        </script>
    </div>
</body>
</html>
"""
    
    def _generate_admin_page(self, organization: str) -> str:
        """Generate fake admin login page"""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>{organization} Admin Portal</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #0a0a0a; color: #0f0; }}
        .login-container {{ max-width: 400px; margin: 100px auto; padding: 30px; 
                          border: 1px solid #0f0; background: #111; }}
        input {{ width: 100%; padding: 10px; margin: 10px 0; background: #000; 
                color: #0f0; border: 1px solid #0f0; }}
        button {{ width: 100%; padding: 10px; background: #0f0; color: #000; 
                 border: none; cursor: pointer; font-weight: bold; }}
        .logo {{ text-align: center; font-size: 24px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">🔒 {organization} ADMIN</div>
        <h2>Secure Admin Access</h2>
        
        <form id="login-form">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="text" name="2fa" placeholder="2FA Code" required>
            <button type="submit">LOGIN</button>
        </form>
        
        <p style="text-align: center; margin-top: 20px; font-size: 12px;">
            IP: <span id="ip-address"></span> | Session: <span id="session-id"></span>
        </p>
        
        <script>
            // Generate fake session info
            document.getElementById('ip-address').textContent = 
                Math.floor(Math.random() * 255) + '.' +
                Math.floor(Math.random() * 255) + '.' +
                Math.floor(Math.random() * 255) + '.' +
                Math.floor(Math.random() * 255);
            
            document.getElementById('session-id').textContent = 
                Math.random().toString(36).substring(2, 15);
            
            // Track login attempts
            let attempts = 0;
            document.getElementById('login-form').addEventListener('submit', function(e) {{
                e.preventDefault();
                attempts++;
                
                // Log attempt
                fetch('/log', {{
                    method: 'POST',
                    body: JSON.stringify({{
                        action: 'login_attempt',
                        attempt_number: attempts,
                        timestamp: new Date().toISOString(),
                        form_data: Object.fromEntries(new FormData(e.target))
                    }})
                }});
                
                if (attempts >= 3) {{
                    alert('Too many failed attempts. This IP has been blocked.');
                    document.getElementById('login-form').style.display = 'none';
                }} else {{
                    alert('Invalid credentials');
                }}
            }});
        </script>
    </div>
</body>
</html>
"""
    
    def _generate_api_page(self, organization: str) -> str:
        """Generate fake API documentation page"""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>{organization} API v2.0</title>
    <style>
        body {{ font-family: monospace; background: #1e1e1e; color: #d4d4d4; }}
        .container {{ max-width: 800px; margin: 20px auto; padding: 20px; }}
        .endpoint {{ background: #2d2d2d; padding: 15px; margin: 10px 0; }}
        .method {{ color: #4ec9b0; font-weight: bold; }}
        .path {{ color: #dcdcaa; }}
        code {{ background: #000; padding: 2px 5px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{organization} Internal API</h1>
        <p>Base URL: <code>http://api-internal.{organization.lower()}.onion</code></p>
        
        <h2>Authentication</h2>
        <p>All requests require an API key in the header:</p>
        <code>X-API-Key: your_api_key_here</code>
        
        <h2>Endpoints</h2>
        
        <div class="endpoint">
            <span class="method">GET</span> <span class="path">/api/v2/users</span>
            <p>Retrieve all user data</p>
        </div>
        
        <div class="endpoint">
            <span class="method">POST</span> <span class="path">/api/v2/auth/token</span>
            <p>Generate access token</p>
        </div>
        
        <div class="endpoint">
            <span class="method">GET</span> <span class="path">/api/v2/data/export</span>
            <p>Export database dump</p>
        </div>
        
        <div class="endpoint">
            <span class="method">POST</span> <span class="path">/api/v2/admin/execute</span>
            <p>Execute admin commands</p>
        </div>
        
        <h2>Test Your API Key</h2>
        <form id="api-test">
            <input type="text" id="api-key" placeholder="Enter API Key" style="width: 300px;">
            <button type="submit">Test</button>
        </form>
        
        <script>
            document.getElementById('api-test').addEventListener('submit', function(e) {{
                e.preventDefault();
                const apiKey = document.getElementById('api-key').value;
                
                // Log API key probe
                fetch('/log', {{
                    method: 'POST',
                    body: JSON.stringify({{
                        action: 'api_key_probe',
                        api_key: apiKey,
                        timestamp: new Date().toISOString()
                    }})
                }});
                
                alert('Invalid API Key - This attempt has been logged');
            }});
        </script>
    </div>
</body>
</html>
"""
    
    def _generate_leak_page(self, organization: str) -> str:
        """Generate fake data leak page"""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>{organization} Data</title>
    <style>
        body {{ background: #000; color: #0f0; font-family: monospace; }}
        .container {{ padding: 20px; }}
        .file-list {{ background: #111; padding: 20px; margin: 20px 0; }}
        .file {{ color: #ff0; cursor: pointer; margin: 5px 0; }}
        .file:hover {{ text-decoration: underline; }}
        pre {{ background: #111; padding: 10px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>/// {organization.upper()} LEAKED DATA ///</h1>
        <p>Uploaded: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="file-list">
            <h3>Available Files:</h3>
            <div class="file" onclick="showFakeData('users')">users_database.sql (243MB)</div>
            <div class="file" onclick="showFakeData('passwords')">password_hashes.txt (18MB)</div>
            <div class="file" onclick="showFakeData('emails')">email_list_2024.csv (67MB)</div>
            <div class="file" onclick="showFakeData('config')">server_config.json (2.3MB)</div>
            <div class="file" onclick="showFakeData('keys')">api_keys_backup.txt (892KB)</div>
        </div>
        
        <div id="preview" style="display: none;">
            <h3>Preview:</h3>
            <pre id="preview-content"></pre>
        </div>
        
        <script>
            function showFakeData(fileType) {{
                // Log access attempt
                fetch('/log', {{
                    method: 'POST',
                    body: JSON.stringify({{
                        action: 'data_access',
                        file: fileType,
                        timestamp: new Date().toISOString()
                    }})
                }});
                
                // Show fake preview
                const fakeData = {{
                    'users': 'ERROR: Access denied - Authentication required',
                    'passwords': 'ERROR: File corrupted - Unable to read',
                    'emails': 'ERROR: Quota exceeded - Contact admin',
                    'config': 'ERROR: Permission denied',
                    'keys': 'ERROR: File moved to secure location'
                }};
                
                document.getElementById('preview').style.display = 'block';
                document.getElementById('preview-content').textContent = fakeData[fileType];
            }}
        </script>
    </div>
</body>
</html>
"""
    
    def _generate_internal_page(self, organization: str) -> str:
        """Generate fake internal portal page"""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>{organization} Internal Portal</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f0f0f0; color: #333; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; }}
        .container {{ max-width: 1000px; margin: 0 auto; padding: 20px; }}
        .section {{ background: white; padding: 20px; margin: 20px 0; 
                   box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .link {{ color: #3498db; text-decoration: none; margin: 0 10px; }}
        .warning {{ background: #e74c3c; color: white; padding: 10px; 
                   text-align: center; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{organization} Employee Portal</h1>
        <p>Internal Resources and Tools</p>
    </div>
    
    <div class="warning">
        ⚠️ AUTHORIZED PERSONNEL ONLY - All access is logged and monitored ⚠️
    </div>
    
    <div class="container">
        <div class="section">
            <h2>Quick Links</h2>
            <a href="#" class="link" onclick="logAccess('email')">Webmail</a>
            <a href="#" class="link" onclick="logAccess('hr')">HR System</a>
            <a href="#" class="link" onclick="logAccess('wiki')">Internal Wiki</a>
            <a href="#" class="link" onclick="logAccess('vpn')">VPN Access</a>
            <a href="#" class="link" onclick="logAccess('tickets')">IT Tickets</a>
        </div>
        
        <div class="section">
            <h2>Announcements</h2>
            <p>• Security Update: Please change your passwords by end of month</p>
            <p>• New VPN server: vpn2.{organization.lower()}.onion</p>
            <p>• Maintenance window: Saturday 2:00 AM - 6:00 AM UTC</p>
        </div>
        
        <div class="section">
            <h2>Resources</h2>
            <p>Employee Handbook: <a href="#" onclick="logAccess('handbook')">Download PDF</a></p>
            <p>Security Guidelines: <a href="#" onclick="logAccess('security')">View</a></p>
            <p>Contact IT Support: support@{organization.lower()}.onion</p>
        </div>
    </div>
    
    <script>
        function logAccess(resource) {{
            fetch('/log', {{
                method: 'POST',
                body: JSON.stringify({{
                    action: 'access_attempt',
                    resource: resource,
                    timestamp: new Date().toISOString(),
                    user_agent: navigator.userAgent
                }})
            }});
            
            alert('Access Denied - You do not have permission to access this resource');
            return false;
        }}
    </script>
</body>
</html>
"""
    
    def _get_free_port(self) -> int:
        """Get a free port for the honeypot service"""
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            s.listen(1)
            port = s.getsockname()[1]
        return port
    
    def _start_hidden_service(self, torrc_path: Path) -> None:
        """Start a Tor hidden service with the given configuration"""
        try:
            # Start tor with custom config
            subprocess.run([
                'tor', '-f', str(torrc_path), '--quiet'
            ], check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to start hidden service: {e}")
            raise
    
    def _wait_for_onion_address(self, hostname_path: Path, timeout: int = 60) -> str:
        """Wait for Tor to generate the onion address"""
        import time
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if hostname_path.exists():
                address = hostname_path.read_text().strip()
                if address.endswith('.onion'):
                    return address
            time.sleep(1)
        
        raise TimeoutError("Timeout waiting for onion address generation")
    
    def _setup_honeypot_webserver(self, hp_dir: Path, content: str, 
                                 triggers: List[str]) -> Dict:
        """Set up the honeypot web server"""
        # Create web root
        web_root = hp_dir / 'www'
        web_root.mkdir(exist_ok=True)
        
        # Write content
        index_path = web_root / 'index.html'
        index_path.write_text(content)
        
        # Create logging endpoint
        log_handler = self._create_log_handler(hp_dir, triggers)
        
        # Create simple Python web server script
        server_script = f"""
#!/usr/bin/env python3
import http.server
import socketserver
import json
from datetime import datetime

class HoneypotHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/log':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            # Log the data
            log_entry = {{
                'timestamp': datetime.now().isoformat(),
                'client_ip': self.client_address[0],
                'user_agent': self.headers.get('User-Agent', 'Unknown'),
                'data': json.loads(post_data)
            }}
            
            with open('{hp_dir}/access.log', 'a') as f:
                f.write(json.dumps(log_entry) + '\\n')
            
            # Check triggers
            self.check_triggers(log_entry)
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'OK')
        else:
            super().do_POST()
    
    def check_triggers(self, log_entry):
        triggers = {json.dumps(triggers)}
        action = log_entry['data'].get('action', '')
        
        if action in triggers:
            alert = {{
                'timestamp': datetime.now().isoformat(),
                'trigger': action,
                'severity': 'high',
                'details': log_entry
            }}
            
            with open('{hp_dir}/alerts.log', 'a') as f:
                f.write(json.dumps(alert) + '\\n')

if __name__ == '__main__':
    PORT = {self._get_free_port()}
    Handler = HoneypotHandler
    
    with socketserver.TCPServer(("127.0.0.1", PORT), Handler) as httpd:
        print(f"Honeypot serving at port {{PORT}}")
        httpd.serve_forever()
"""
        
        server_path = hp_dir / 'server.py'
        server_path.write_text(server_script)
        server_path.chmod(0o755)
        
        # Start the server
        subprocess.Popen(['python3', str(server_path)], 
                        cwd=str(web_root),
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
        
        return {
            'web_root': str(web_root),
            'server_script': str(server_path),
            'port': self._get_free_port()
        }
    
    def _create_log_handler(self, hp_dir: Path, triggers: List[str]) -> None:
        """Create log handling for honeypot triggers"""
        # This would be expanded to handle real-time alerting
        pass
    
    def _initialize_monitoring(self, config: Dict) -> None:
        """Initialize monitoring for the honeypot"""
        # Set up log watchers, alert systems, etc.
        print(f"Monitoring initialized for {config['name']}")
    
    def _save_deployment_config(self, deployment: Dict) -> None:
        """Save deployment configuration for persistence"""
        config_path = self.base_dir / f"{deployment['organization']}_deployment.json"
        with open(config_path, 'w') as f:
            json.dump(deployment, f, indent=2)
    
    def monitor_honeypots(self, callback=None) -> None:
        """Monitor all active honeypots for activity"""
        import time
        
        while True:
            for address, config in self.honeypots.items():
                # Check for new alerts
                alert_log = Path(config['alert_log'])
                if alert_log.exists():
                    # Process new alerts
                    with open(alert_log, 'r') as f:
                        for line in f:
                            try:
                                alert = json.loads(line)
                                print(f"ALERT: {alert['trigger']} on {address}")
                                
                                if callback:
                                    callback(alert, config)
                                    
                            except json.JSONDecodeError:
                                continue
            
            time.sleep(30)  # Check every 30 seconds
    
    def get_honeypot_statistics(self) -> Dict:
        """Get statistics from all honeypots"""
        stats = {
            'total_honeypots': len(self.honeypots),
            'active_honeypots': 0,
            'total_hits': 0,
            'total_alerts': 0,
            'top_triggers': {},
            'recent_activity': []
        }
        
        for address, config in self.honeypots.items():
            if config['status'] == 'active':
                stats['active_honeypots'] += 1
            
            # Count hits and alerts
            access_log = Path(config['log_file'])
            if access_log.exists():
                with open(access_log, 'r') as f:
                    stats['total_hits'] += sum(1 for _ in f)
            
            alert_log = Path(config['alert_log'])
            if alert_log.exists():
                with open(alert_log, 'r') as f:
                    for line in f:
                        stats['total_alerts'] += 1
                        try:
                            alert = json.loads(line)
                            trigger = alert.get('trigger', 'unknown')
                            stats['top_triggers'][trigger] = stats['top_triggers'].get(trigger, 0) + 1
                        except:
                            continue
        
        return stats