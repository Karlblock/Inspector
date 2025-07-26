"""
Tor Monitoring System - Continuous monitoring and alerting for Tor threats
"""

import json
import asyncio
import aiohttp
from typing import Dict, List, Optional, Set, Callable, Any
from datetime import datetime, timedelta
from collections import defaultdict
import re
import threading
import queue
from pathlib import Path
import hashlib


from .discovery import OnionDiscoveryEngine


class Monitor:
    """Base monitor class"""
    def __init__(self, name: str):
        self.name = name
        self.logger = Logger(f"{__name__}.{name}")
        self.is_running = False
        
    async def check(self, config: Dict) -> List[Dict]:
        """Perform monitoring check - to be implemented by subclasses"""
        raise NotImplementedError


class BrandAbuseMonitor(Monitor):
    """Monitor for brand abuse on Tor"""
    
    def __init__(self):
        super().__init__("brand_abuse")
        self.discovery_engine = OnionDiscoveryEngine()
        self.known_legitimate = set()
        self.detected_abuse = set()
        
    async def check(self, config: Dict) -> List[Dict]:
        """Check for brand abuse"""
        alerts = []
        organization = config.get('organization', '')
        keywords = config.get('keywords', [])
        
        # Discover related onions
        discoveries = self.discovery_engine.discover_related_onions(
            organization, 
            deep_search=False,
            include_variations=True
        )
        
        # Check for suspicious or malicious sites
        for category in ['suspicious', 'malicious']:
            for item in discoveries['discovered_onions'][category]:
                onion_address = item['address']
                
                if onion_address not in self.detected_abuse:
                    self.detected_abuse.add(onion_address)
                    
                    alert = {
                        'type': 'brand_abuse',
                        'severity': 'high' if category == 'malicious' else 'medium',
                        'timestamp': datetime.now().isoformat(),
                        'details': {
                            'onion_address': onion_address,
                            'category': category,
                            'similarity_score': item['classification']['similarity_score'],
                            'indicators': item['classification']['indicators']
                        },
                        'recommendation': 'Investigate for potential trademark infringement'
                    }
                    alerts.append(alert)
        
        return alerts


class DataLeakMonitor(Monitor):
    """Monitor for data leaks"""
    
    def __init__(self):
        super().__init__("data_leak")
        self.paste_sites = [
            'http://paste2vljvhmwq5zy33re2hzu4fisgqsohufgbljqomib2brzx3q4mid.onion',  # Example
        ]
        self.checked_hashes = set()
        
    async def check(self, config: Dict) -> List[Dict]:
        """Check for data leaks"""
        alerts = []
        keywords = config.get('leak_keywords', [])
        domains = config.get('domains', [])
        
        # Check paste sites
        async with aiohttp.ClientSession() as session:
            for site in self.paste_sites:
                try:
                    pastes = await self._fetch_recent_pastes(session, site)
                    
                    for paste in pastes:
                        content_hash = hashlib.sha256(paste['content'].encode()).hexdigest()
                        
                        if content_hash not in self.checked_hashes:
                            self.checked_hashes.add(content_hash)
                            
                            # Check for keywords and domains
                            content_lower = paste['content'].lower()
                            
                            for keyword in keywords:
                                if keyword.lower() in content_lower:
                                    alert = self._create_leak_alert(paste, keyword, 'keyword')
                                    alerts.append(alert)
                                    break
                            
                            for domain in domains:
                                if domain.lower() in content_lower:
                                    # Check for email patterns
                                    email_pattern = rf'[\w\.-]+@{re.escape(domain)}'
                                    emails = re.findall(email_pattern, paste['content'], re.IGNORECASE)
                                    
                                    if emails:
                                        alert = self._create_leak_alert(
                                            paste, 
                                            f"{len(emails)} {domain} emails", 
                                            'email'
                                        )
                                        alerts.append(alert)
                
                except Exception as e:
                    print(f"Error checking {site}: {e}")
        
        return alerts
    
    async def _fetch_recent_pastes(self, session: aiohttp.ClientSession, 
                                  site_url: str) -> List[Dict]:
        """Fetch recent pastes from a paste site"""
        # This is a placeholder - actual implementation would depend on the site
        return []
    
    def _create_leak_alert(self, paste: Dict, matched: str, leak_type: str) -> Dict:
        """Create a data leak alert"""
        return {
            'type': 'data_leak',
            'severity': 'critical' if leak_type == 'email' else 'high',
            'timestamp': datetime.now().isoformat(),
            'details': {
                'source': paste.get('source', 'unknown'),
                'matched': matched,
                'leak_type': leak_type,
                'paste_id': paste.get('id', 'unknown'),
                'preview': paste['content'][:200] + '...' if len(paste['content']) > 200 else paste['content']
            },
            'recommendation': 'Investigate immediately and initiate incident response if confirmed'
        }


class ThreatIntelMonitor(Monitor):
    """Monitor threat intelligence sources"""
    
    def __init__(self):
        super().__init__("threat_intel")
        self.threat_feeds = {
            'forums': [],  # List of monitored forums
            'markets': [],  # Darknet markets to monitor
            'intel_sources': []  # Threat intel feeds
        }
        self.known_threats = set()
        
    async def check(self, config: Dict) -> List[Dict]:
        """Check threat intelligence sources"""
        alerts = []
        organization = config.get('organization', '')
        assets = config.get('assets', [])
        
        # Monitor forums for mentions
        for forum in self.threat_feeds['forums']:
            try:
                threats = await self._check_forum_threats(forum, organization, assets)
                
                for threat in threats:
                    threat_hash = hashlib.sha256(
                        f"{threat['source']}{threat['content']}".encode()
                    ).hexdigest()
                    
                    if threat_hash not in self.known_threats:
                        self.known_threats.add(threat_hash)
                        
                        alert = {
                            'type': 'threat_intel',
                            'severity': self._assess_threat_severity(threat),
                            'timestamp': datetime.now().isoformat(),
                            'details': threat,
                            'recommendation': 'Assess threat credibility and implement countermeasures'
                        }
                        alerts.append(alert)
                        
            except Exception as e:
                print(f"Error checking forum {forum}: {e}")
        
        return alerts
    
    async def _check_forum_threats(self, forum: str, organization: str, 
                                  assets: List[str]) -> List[Dict]:
        """Check a forum for threats"""
        # Placeholder for actual forum monitoring
        return []
    
    def _assess_threat_severity(self, threat: Dict) -> str:
        """Assess the severity of a threat"""
        content = threat.get('content', '').lower()
        
        # Critical indicators
        if any(word in content for word in ['0day', 'zero-day', 'exploit', 'ransomware']):
            return 'critical'
        
        # High indicators
        if any(word in content for word in ['vulnerability', 'breach', 'access']):
            return 'high'
        
        # Medium indicators
        if any(word in content for word in ['target', 'plan', 'research']):
            return 'medium'
        
        return 'low'


class NewOnionMonitor(Monitor):
    """Monitor for new onion addresses"""
    
    def __init__(self):
        super().__init__("new_onion")
        self.seen_onions = set()
        self.onion_pattern = re.compile(r'[a-z2-7]{16,56}\.onion', re.IGNORECASE)
        
    async def check(self, config: Dict) -> List[Dict]:
        """Check for new onion addresses"""
        alerts = []
        organization = config.get('organization', '')
        
        # Use discovery engine to find onions
        discovery = OnionDiscoveryEngine()
        discoveries = discovery.discover_related_onions(organization, deep_search=False)
        
        all_found = set()
        for category in discoveries['discovered_onions']:
            for item in discoveries['discovered_onions'][category]:
                all_found.add(item['address'])
        
        # Check for new onions
        new_onions = all_found - self.seen_onions
        self.seen_onions.update(new_onions)
        
        for onion in new_onions:
            # Classify the new onion
            classification = discovery._classify_onion(onion, organization)
            
            if classification['similarity_score'] > 0.5:  # Similar to organization
                alert = {
                    'type': 'new_onion',
                    'severity': 'medium',
                    'timestamp': datetime.now().isoformat(),
                    'details': {
                        'onion_address': onion,
                        'similarity_score': classification['similarity_score'],
                        'category': classification['category'],
                        'indicators': classification['indicators']
                    },
                    'recommendation': 'Investigate new onion service for potential brand abuse'
                }
                alerts.append(alert)
        
        return alerts


class TorMonitoringSystem:
    """
    Main monitoring system that coordinates all monitors
    """
    
    def __init__(self):
        # Logger removed - using print statements
        self.monitors = {
            'brand_abuse': BrandAbuseMonitor(),
            'data_leaks': DataLeakMonitor(),
            'threat_intel': ThreatIntelMonitor(),
            'new_onions': NewOnionMonitor()
        }
        self.alert_queue = queue.Queue()
        self.is_running = False
        self.monitoring_tasks = []
        self.alert_handlers = []
        
    def add_alert_handler(self, handler: Callable[[Dict], None]) -> None:
        """Add a handler for alerts"""
        self.alert_handlers.append(handler)
    
    async def start_monitoring(self, config: Dict) -> None:
        """Start continuous monitoring"""
        print("Starting Tor monitoring system")
        self.is_running = True
        
        # Start alert processor
        alert_thread = threading.Thread(target=self._process_alerts)
        alert_thread.daemon = True
        alert_thread.start()
        
        # Start monitors
        tasks = []
        for monitor_name, monitor in self.monitors.items():
            if monitor_name in config.get('enabled_monitors', []):
                task = asyncio.create_task(
                    self._run_monitor(monitor, config)
                )
                tasks.append(task)
                self.monitoring_tasks.append(task)
        
        # Wait for all monitors
        await asyncio.gather(*tasks)
    
    async def _run_monitor(self, monitor: Monitor, config: Dict) -> None:
        """Run a single monitor continuously"""
        monitor_config = config.get(monitor.name, {})
        interval = monitor_config.get('interval', 3600)  # Default 1 hour
        
        while self.is_running:
            try:
                print(f"Running {monitor.name} check")
                alerts = await monitor.check(monitor_config)
                
                for alert in alerts:
                    alert['monitor'] = monitor.name
                    self.alert_queue.put(alert)
                    
            except Exception as e:
                print(f"Error in {monitor.name}: {e}")
            
            await asyncio.sleep(interval)
    
    def _process_alerts(self) -> None:
        """Process alerts from the queue"""
        while self.is_running:
            try:
                alert = self.alert_queue.get(timeout=1)
                
                # Log alert
                print(f"ALERT [{alert['severity']}]: {alert['type']}")
                
                # Call handlers
                for handler in self.alert_handlers:
                    try:
                        handler(alert)
                    except Exception as e:
                        print(f"Error in alert handler: {e}")
                        
            except queue.Empty:
                continue
    
    def stop_monitoring(self) -> None:
        """Stop monitoring"""
        print("Stopping Tor monitoring system")
        self.is_running = False
        
        # Cancel all tasks
        for task in self.monitoring_tasks:
            task.cancel()
    
    def get_monitor_status(self) -> Dict:
        """Get status of all monitors"""
        status = {
            'is_running': self.is_running,
            'monitors': {},
            'alert_queue_size': self.alert_queue.qsize()
        }
        
        for name, monitor in self.monitors.items():
            status['monitors'][name] = {
                'is_running': monitor.is_running,
                'name': monitor.name
            }
        
        return status
    
    @staticmethod
    def create_monitoring_config(organization: str, 
                               keywords: List[str],
                               domains: List[str],
                               check_interval: int = 3600) -> Dict:
        """Create a monitoring configuration"""
        return {
            'organization': organization,
            'enabled_monitors': ['brand_abuse', 'data_leaks', 'threat_intel', 'new_onions'],
            'brand_abuse': {
                'organization': organization,
                'keywords': keywords,
                'interval': check_interval
            },
            'data_leaks': {
                'leak_keywords': keywords,
                'domains': domains,
                'interval': check_interval
            },
            'threat_intel': {
                'organization': organization,
                'assets': domains,
                'interval': check_interval * 2  # Less frequent
            },
            'new_onions': {
                'organization': organization,
                'interval': check_interval
            }
        }


class AlertNotificationSystem:
    """Handle alert notifications"""
    
    def __init__(self):
        # Logger removed - using print statements
        self.notification_methods = {
            'email': self._send_email,
            'webhook': self._send_webhook,
            'siem': self._send_to_siem,
            'slack': self._send_slack
        }
        
    async def send_alert(self, alert: Dict, config: Dict) -> None:
        """Send alert through configured channels"""
        severity = alert.get('severity', 'low')
        
        # Determine which channels to use based on severity
        channels = []
        if severity == 'critical':
            channels = config.get('critical_channels', ['email', 'webhook', 'slack'])
        elif severity == 'high':
            channels = config.get('high_channels', ['email', 'webhook'])
        else:
            channels = config.get('default_channels', ['webhook'])
        
        # Send through each channel
        for channel in channels:
            if channel in self.notification_methods:
                try:
                    await self.notification_methods[channel](alert, config)
                except Exception as e:
                    print(f"Failed to send alert via {channel}: {e}")
    
    async def _send_email(self, alert: Dict, config: Dict) -> None:
        """Send email notification"""
        # Placeholder for email implementation
        print(f"Would send email alert: {alert['type']}")
    
    async def _send_webhook(self, alert: Dict, config: Dict) -> None:
        """Send webhook notification"""
        webhook_url = config.get('webhook_url')
        if not webhook_url:
            return
        
        async with aiohttp.ClientSession() as session:
            payload = {
                'alert': alert,
                'source': 'cyba-inspector-tor-monitor',
                'timestamp': datetime.now().isoformat()
            }
            
            await session.post(webhook_url, json=payload)
    
    async def _send_to_siem(self, alert: Dict, config: Dict) -> None:
        """Send to SIEM system"""
        # Format for common SIEM systems
        siem_event = {
            'event_type': 'tor_monitoring_alert',
            'severity': alert['severity'],
            'category': alert['type'],
            'timestamp': alert['timestamp'],
            'details': json.dumps(alert['details'])
        }
        
        # Placeholder for SIEM integration
        print(f"Would send to SIEM: {siem_event}")
    
    async def _send_slack(self, alert: Dict, config: Dict) -> None:
        """Send Slack notification"""
        slack_webhook = config.get('slack_webhook')
        if not slack_webhook:
            return
        
        # Format for Slack
        color_map = {
            'critical': '#FF0000',
            'high': '#FF9900',
            'medium': '#FFCC00',
            'low': '#00FF00'
        }
        
        slack_message = {
            'attachments': [{
                'color': color_map.get(alert['severity'], '#808080'),
                'title': f"🚨 Tor Monitoring Alert: {alert['type']}",
                'fields': [
                    {
                        'title': 'Severity',
                        'value': alert['severity'].upper(),
                        'short': True
                    },
                    {
                        'title': 'Monitor',
                        'value': alert.get('monitor', 'unknown'),
                        'short': True
                    },
                    {
                        'title': 'Details',
                        'value': json.dumps(alert['details'], indent=2)[:500],
                        'short': False
                    },
                    {
                        'title': 'Recommendation',
                        'value': alert.get('recommendation', 'No recommendation'),
                        'short': False
                    }
                ],
                'footer': 'Cyba-HTB Tor Monitor',
                'ts': int(datetime.now().timestamp())
            }]
        }
        
        async with aiohttp.ClientSession() as session:
            await session.post(slack_webhook, json=slack_message)