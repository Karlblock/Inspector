# Tor OSINT Module - Defensive Security Guide

## 🛡️ Overview

The Tor OSINT module for cyba-HTB provides defensive security capabilities for monitoring and protecting your organization from dark web threats. This module focuses exclusively on legal and ethical research activities.

## 🚀 Quick Start

### Prerequisites

1. **Install Tor** (Ubuntu/Debian):
```bash
sudo apt update
sudo apt install tor
sudo systemctl start tor
sudo systemctl enable tor
```

2. **Install Python dependencies**:
```bash
pip install requests[socks] pysocks
```

3. **Verify Tor is running**:
```bash
systemctl status tor
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

### Basic Usage

#### Using with cyba-HTB profiles:
```bash
# Defensive OSINT profile
cyba-htb enum -t example.com -n defensive-scan -p defensive-osint

# Threat intelligence profile
cyba-htb enum -t example.com -n threat-scan -p threat-intel --tor
```

#### Direct module usage:
```python
from src.enumeration.modules.tor_osint import TorOSINTModule

module = TorOSINTModule()
results = module.run(
    target="your-domain.com",
    session_id="scan-001",
    output_dir="./reports",
    use_tor=True,
    keywords=["password", "leak", "breach"]
)
```

## 🔍 Features

### 1. Data Leak Detection
- Search for exposed credentials
- Identify leaked documents
- Monitor paste sites
- Check breach databases

### 2. Threat Intelligence
- Monitor underground forums
- Track threat actors
- Identify targeted campaigns
- Detect exploit availability

### 3. Brand Protection
- Phishing site detection
- Fraudulent domain monitoring
- Impersonation tracking
- Reputation monitoring

## 🛠️ Configuration

### Module Options

```python
# Configuration options
config = {
    'use_tor': True,                    # Enable Tor routing
    'keywords': ['password', 'leak'],   # Search keywords
    'org_keywords': ['CompanyName'],    # Organization identifiers
    'check_interval': 3600,             # Check frequency (seconds)
    'timeout': 30,                      # Request timeout
    'max_results': 100                  # Result limit
}
```

### Environment Variables

```bash
# Tor proxy settings
export TOR_PROXY_HOST="127.0.0.1"
export TOR_PROXY_PORT="9050"

# Module settings
export CYBA_TOR_TIMEOUT="30"
export CYBA_TOR_MAX_RETRIES="3"
```

## 📊 Output Format

### Report Structure
```
reports/
├── tor_osint_report_[session_id].md    # Main report
├── findings_[timestamp].json            # Structured data
└── evidence/                            # Supporting files
    ├── screenshots/
    └── raw_data/
```

### Report Sections
1. **Executive Summary** - High-level findings
2. **Risk Assessment** - Severity ratings
3. **Detailed Findings** - Specific issues
4. **Recommendations** - Action items
5. **Evidence** - Supporting data

## ⚖️ Legal & Ethical Guidelines

### ✅ Allowed Activities
- Research YOUR organization's data
- Monitor for threats against YOUR company
- Defensive intelligence gathering
- Authorized penetration testing

### ❌ Prohibited Activities
- Purchasing illegal data
- Interacting with criminals
- Accessing illegal content
- Unauthorized research

### Compliance Requirements
- Document all activities
- Obtain written authorization
- Follow data protection laws
- Report findings immediately

## 🔒 Security Best Practices

### 1. Operational Security
```bash
# Use isolated VM
VBoxManage clonevm "SecurityResearchVM" --name "TorOSINT"

# Configure firewall
sudo ufw deny out to any
sudo ufw allow out to 127.0.0.1 port 9050
```

### 2. Data Handling
- Encrypt all findings
- Secure storage only
- Limited access control
- Regular data purging

### 3. Monitoring Setup
```yaml
# monitoring.yaml
alerts:
  critical:
    - credential_leak
    - active_threat
    - data_breach
  high:
    - phishing_campaign
    - brand_impersonation
```

## 🚨 Incident Response

### If You Find a Leak:
1. **Document** - Capture all evidence
2. **Isolate** - Secure the data
3. **Report** - Notify security team
4. **Remediate** - Take corrective action
5. **Monitor** - Watch for reoccurrence

### Response Playbook
```python
# Example response automation
if finding['severity'] == 'critical':
    notify_security_team()
    initiate_password_reset()
    block_compromised_accounts()
    create_incident_ticket()
```

## 📈 Integration

### SIEM Integration
```python
# Send to SIEM
siem_event = {
    'source': 'tor_osint',
    'severity': finding['severity'],
    'category': 'data_leak',
    'details': finding['details']
}
send_to_siem(siem_event)
```

### API Endpoints
```python
# REST API integration
POST /api/osint/scan
{
    "target": "example.com",
    "profile": "defensive",
    "use_tor": true
}

GET /api/osint/results/{scan_id}
```

## 🎓 Training Resources

### Essential Skills
1. Understanding Tor architecture
2. OSINT methodologies
3. Threat intelligence
4. Legal compliance
5. Report writing

### Recommended Courses
- SANS SEC487: OSINT
- Dark Web Investigation
- Threat Intelligence Fundamentals
- Privacy Law for Security

## 🐛 Troubleshooting

### Common Issues

**Tor Connection Failed**
```bash
# Check Tor status
sudo systemctl status tor

# Test SOCKS proxy
curl --socks5-hostname 127.0.0.1:9050 https://example.com

# Check logs
sudo journalctl -u tor -f
```

**No Results Found**
- Verify search terms
- Check Tor circuit
- Try different keywords
- Expand search scope

**Performance Issues**
- Use connection pooling
- Implement caching
- Optimize queries
- Load balance requests

## 📝 Example Workflows

### Daily Monitoring
```bash
#!/bin/bash
# daily_monitoring.sh

TARGETS="company.com subsidiary.com"
KEYWORDS="password database leak breach"

for target in $TARGETS; do
    cyba-htb enum -t $target \
        -n "daily-$(date +%Y%m%d)" \
        -p defensive-osint \
        --tor \
        --keywords "$KEYWORDS"
done
```

### Incident Investigation
```python
# Investigate specific incident
module = TorOSINTModule()
results = module.run(
    target="company.com",
    session_id=f"incident-{ticket_id}",
    output_dir="./incidents",
    use_tor=True,
    keywords=incident_indicators,
    deep_search=True
)
```

## 🤝 Contributing

To improve the Tor OSINT module:

1. Follow defensive security principles
2. Add only legal research methods
3. Include proper documentation
4. Write comprehensive tests
5. Submit PR with examples

## 📞 Support

- **Documentation**: `/docs/tor_osint/`
- **Issues**: GitHub Issues
- **Security**: security@your-org.com
- **Legal**: legal@your-org.com

Remember: Always operate within legal boundaries and use this tool only for protecting your organization.