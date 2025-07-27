# Tor OSINT Module Documentation

## Overview

The Tor OSINT module provides defensive security research capabilities for identifying data leaks and threats against your organization on the Tor network and dark web. This module is designed for authorized security professionals conducting defensive research only.

## Features

### Core Capabilities
- **Data Leak Detection**: Search for exposed organizational data on paste sites and forums
- **Threat Intelligence**: Monitor for threats and mentions of your organization
- **Multi-Source Integration**: Integrate with HIBP, Shodan, and other threat intelligence sources
- **Comprehensive Reporting**: Generate detailed reports in multiple formats
- **Safety Measures**: Built-in protection mechanisms to ensure ethical research

### Components

1. **Main Module** (`tor_osint.py`)
   - Core enumeration and search functionality
   - Tor connection management
   - Session handling

2. **Reporting** (`tor_osint/reporting.py`)
   - Multiple report formats (Markdown, HTML, JSON, Executive)
   - Risk assessment and scoring
   - Sanitized data presentation

3. **Integrations** (`tor_osint/integrations.py`)
   - Have I Been Pwned (HIBP) integration
   - Shodan integration
   - SIEM integration
   - Slack/Jira alerting
   - STIX export

4. **Protection** (`tor_osint/protection.py`)
   - Legal compliance checks
   - Rate limiting
   - Scope validation
   - Activity logging
   - OPSEC guidelines

## Usage

### Basic Usage
```bash
# Basic domain research (clearnet only)
cyba-inspector tor-osint -t example.com

# Research with Tor enabled
cyba-inspector tor-osint -t example.com --use-tor

# Custom keywords
cyba-inspector tor-osint -t example.com -k password database credential leak

# Full scan with integrations
cyba-inspector tor-osint -t example.com --use-tor --check-hibp --check-shodan
```

### Advanced Options
```bash
# Generate executive report
cyba-inspector tor-osint -t example.com --executive-report

# Enable alerting for high-risk findings
cyba-inspector tor-osint -t example.com --slack-alerts --create-tickets

# Export to STIX format
cyba-inspector tor-osint -t example.com --export-stix

# Include OPSEC guidelines
cyba-inspector tor-osint -t example.com --include-opsec
```

## Configuration

### Environment Variables
```bash
# Tor configuration
export TOR_PROXY_ENABLED=true

# API Keys (optional)
export HIBP_API_KEY="your-hibp-api-key"
export SHODAN_API_KEY="your-shodan-api-key"

# Integrations (optional)
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."
export JIRA_URL="https://your-domain.atlassian.net"
export JIRA_USER="your-email@example.com"
export JIRA_API_TOKEN="your-api-token"
export JIRA_PROJECT="SEC"

# SIEM Integration
export SIEM_ENDPOINT="https://your-siem/api/events"
export SIEM_TOKEN="your-siem-token"

# Authorized domains (comma-separated)
export AUTHORIZED_DOMAINS="example.com,example.org"
```

### Tor Setup
```bash
# Install Tor
sudo apt install tor

# Start Tor service
sudo systemctl start tor

# Verify Tor is running
systemctl status tor
```

## Safety and Legal Compliance

### Built-in Protections
- **Scope Validation**: Only researches authorized domains
- **Rate Limiting**: Prevents excessive requests
- **Content Filtering**: Blocks searches for illegal content
- **Activity Logging**: Maintains audit trail
- **Data Sanitization**: Redacts sensitive information

### Legal Requirements
- **Authorization Required**: Only use on domains you own or have explicit permission to test
- **Defensive Only**: No offensive activities or unauthorized access
- **Compliance**: Follows CFAA, GDPR, and other applicable laws
- **Reporting**: Report any illegal content discovered to appropriate authorities

## Report Types

### 1. Main Report (Markdown/HTML)
- Comprehensive findings
- Risk assessment
- Technical details
- Recommendations

### 2. Executive Report
- High-level summary
- Key metrics
- Action items
- Non-technical language

### 3. Safety Report
- Compliance verification
- Activity summary
- Safety checks
- Recommendations

### 4. OPSEC Guidelines
- Operational security best practices
- Technical setup requirements
- Identity separation
- Emergency procedures

## Risk Levels

The module assigns risk levels based on findings:

- **Low**: No significant issues found
- **Medium**: Minor data exposures or mentions
- **High**: Significant data leaks or active threats
- **Critical**: Immediate action required

## Integration Workflows

### SIEM Integration
Findings are automatically sent to configured SIEM systems for correlation and alerting.

### Slack Alerts
High and Critical findings trigger immediate Slack notifications to security teams.

### Jira Tickets
Critical findings automatically create Jira tickets for tracking and remediation.

### STIX Export
Findings can be exported in STIX 2.1 format for threat intelligence sharing.

## Best Practices

1. **Always obtain authorization** before researching any domain
2. **Use Tor** for anonymous research when appropriate
3. **Review all reports** before sharing
4. **Monitor rate limits** to avoid detection
5. **Keep API keys secure** and rotate regularly
6. **Document all activities** for compliance

## Troubleshooting

### Tor Connection Issues
```bash
# Check Tor service
sudo systemctl status tor

# Check SOCKS proxy
netstat -an | grep 9050

# Test Tor connection
curl --socks5 localhost:9050 https://check.torproject.org
```

### API Key Issues
- Ensure API keys are properly set in environment
- Check API rate limits
- Verify API key permissions

### Report Generation Issues
- Check output directory permissions
- Ensure sufficient disk space
- Verify all dependencies installed

## Ethical Guidelines

This module is designed for defensive security research only:

- ✅ Identify data leaks affecting your organization
- ✅ Monitor for threats against your company
- ✅ Assess external attack surface
- ✅ Compliance verification

- ❌ Access illegal marketplaces
- ❌ Purchase illegal goods or services
- ❌ Hack or exploit systems
- ❌ Collect personal data without authorization

## Support

For issues or questions:
1. Check the logs in `~/.cyba-inspector/logs/`
2. Review the safety report for compliance issues
3. Ensure all dependencies are installed
4. Verify Tor and API configurations