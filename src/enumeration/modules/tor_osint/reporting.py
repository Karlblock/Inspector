#!/usr/bin/env python3
"""
Tor OSINT Reporting Component
Generates comprehensive security reports from Tor/dark web findings
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional
import hashlib
from jinja2 import Template

from ....utils.logger import Logger


class TorOSINTReporter:
    """Generate comprehensive reports from Tor OSINT findings"""
    
    def __init__(self):
        self.logger = Logger(__name__)
        self.report_formats = ['markdown', 'html', 'json', 'executive']
        
    def generate_report(self, findings: Dict, format: str = 'markdown', 
                       include_recommendations: bool = True) -> str:
        """Generate report in specified format"""
        if format not in self.report_formats:
            self.logger.warning(f"Unknown format {format}, using markdown")
            format = 'markdown'
            
        if format == 'markdown':
            return self._generate_markdown_report(findings, include_recommendations)
        elif format == 'html':
            return self._generate_html_report(findings, include_recommendations)
        elif format == 'json':
            return self._generate_json_report(findings)
        elif format == 'executive':
            return self._generate_executive_report(findings)
            
    def _generate_markdown_report(self, findings: Dict, include_recs: bool) -> str:
        """Generate detailed markdown report"""
        report = f"""# Tor/Dark Web OSINT Security Report

**Report ID**: {self._generate_report_id(findings)}  
**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Classification**: Confidential - Internal Use Only

## Executive Summary

This report presents findings from authorized defensive security research conducted on the Tor network and dark web sources to identify potential data leaks, security threats, and risks to the organization.

**Overall Risk Level**: {self._calculate_overall_risk(findings)}

## 1. Scope and Methodology

### 1.1 Target Information
- **Primary Domain**: {findings.get('target', 'N/A')}
- **Keywords Monitored**: {', '.join(findings.get('keywords', []))}
- **Search Period**: {findings.get('search_period', 'Point-in-time')}

### 1.2 Sources Checked
- Tor network searches: {'Yes' if findings.get('tor_enabled') else 'No'}
- Paste sites monitored: {len(findings.get('paste_sites_checked', []))}
- Forums analyzed: {len(findings.get('forums_checked', []))}
- Threat intel feeds: {len(findings.get('intel_sources', []))}

## 2. Key Findings

### 2.1 Data Leak Assessment
"""
        
        # Add leak findings
        leaks = findings.get('leak_search', {}).get('potential_leaks', [])
        if leaks:
            report += f"\n**{len(leaks)} potential data exposure(s) identified:**\n\n"
            for i, leak in enumerate(leaks, 1):
                report += f"#### Finding #{i}: {leak.get('type', 'Unknown Type')}\n"
                report += f"- **Source**: {leak.get('source', 'Unknown')}\n"
                report += f"- **Severity**: {leak.get('severity', 'Unknown')}\n"
                report += f"- **Details**: {leak.get('details', 'No details available')}\n"
                report += f"- **First Seen**: {leak.get('timestamp', 'Unknown')}\n"
                if leak.get('sample_data'):
                    report += f"- **Sample**: `{self._sanitize_sample(leak['sample_data'])}`\n"
                report += "\n"
        else:
            report += "\n✅ **No data leaks detected** in current scan.\n"
            
        # Add threat intelligence
        report += "\n### 2.2 Threat Intelligence\n"
        threats = findings.get('threat_intel', {}).get('threats_found', [])
        if threats:
            report += f"\n⚠️ **{len(threats)} potential threat(s) identified:**\n\n"
            for threat in threats:
                report += f"- {threat}\n"
        else:
            report += "\n✅ **No active threats detected** against the organization.\n"
            
        # Add monitoring alerts
        report += "\n### 2.3 Monitoring Alerts\n"
        alerts = findings.get('monitoring_alerts', [])
        if alerts:
            for alert in alerts:
                report += f"- 🚨 {alert['type']}: {alert['message']}\n"
        else:
            report += "- No critical alerts at this time\n"
            
        # Add recommendations if requested
        if include_recs:
            report += self._generate_recommendations(findings)
            
        # Add technical details
        report += self._generate_technical_appendix(findings)
        
        # Add legal notice
        report += """
## Legal and Compliance Notice

This research was conducted in accordance with:
- Authorized security testing agreement
- Applicable privacy and data protection laws
- Ethical hacking guidelines and best practices

All activities were defensive in nature and limited to:
- Identifying exposed organizational data
- Monitoring for threats against the organization
- Assessing security posture from an external perspective

No unauthorized access, data exfiltration, or malicious activities were performed.
"""
        
        return report
        
    def _generate_html_report(self, findings: Dict, include_recs: bool) -> str:
        """Generate HTML formatted report"""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Tor OSINT Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #2c3e50; color: white; padding: 20px; }
        .risk-high { color: #e74c3c; font-weight: bold; }
        .risk-medium { color: #f39c12; font-weight: bold; }
        .risk-low { color: #27ae60; font-weight: bold; }
        .finding { border: 1px solid #ddd; padding: 15px; margin: 10px 0; }
        .recommendation { background: #ecf0f1; padding: 15px; margin: 10px 0; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Tor/Dark Web OSINT Security Report</h1>
        <p>Generated: {{ timestamp }}</p>
    </div>
    
    <h2>Executive Summary</h2>
    <p>Risk Level: <span class="risk-{{ risk_level }}">{{ risk_level|upper }}</span></p>
    
    <h2>Findings</h2>
    {% for finding in findings %}
    <div class="finding">
        <h3>{{ finding.type }}</h3>
        <p>{{ finding.details }}</p>
        <p>Severity: <span class="risk-{{ finding.severity }}">{{ finding.severity|upper }}</span></p>
    </div>
    {% endfor %}
    
    {% if include_recommendations %}
    <h2>Recommendations</h2>
    {% for rec in recommendations %}
    <div class="recommendation">
        <h4>{{ rec.title }}</h4>
        <p>{{ rec.description }}</p>
    </div>
    {% endfor %}
    {% endif %}
</body>
</html>
"""
        
        # Prepare template data
        template_data = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'risk_level': self._calculate_overall_risk(findings).lower(),
            'findings': findings.get('leak_search', {}).get('potential_leaks', []),
            'include_recommendations': include_recs,
            'recommendations': self._get_recommendations_list(findings) if include_recs else []
        }
        
        template = Template(html_template)
        return template.render(**template_data)
        
    def _generate_json_report(self, findings: Dict) -> str:
        """Generate JSON formatted report for automation"""
        report_data = {
            'report_id': self._generate_report_id(findings),
            'timestamp': datetime.now().isoformat(),
            'target': findings.get('target'),
            'risk_level': self._calculate_overall_risk(findings),
            'summary': {
                'data_leaks_found': len(findings.get('leak_search', {}).get('potential_leaks', [])),
                'threats_detected': len(findings.get('threat_intel', {}).get('threats_found', [])),
                'tor_enabled': findings.get('tor_enabled', False)
            },
            'findings': findings,
            'recommendations': self._get_recommendations_list(findings)
        }
        
        return json.dumps(report_data, indent=2)
        
    def _generate_executive_report(self, findings: Dict) -> str:
        """Generate high-level executive summary"""
        risk_level = self._calculate_overall_risk(findings)
        leak_count = len(findings.get('leak_search', {}).get('potential_leaks', []))
        threat_count = len(findings.get('threat_intel', {}).get('threats_found', []))
        
        report = f"""# Executive Summary - Tor/Dark Web Security Assessment

**Date**: {datetime.now().strftime('%B %d, %Y')}  
**Overall Risk**: {risk_level}

## Key Metrics
- Data Exposures Found: {leak_count}
- Active Threats: {threat_count}
- Immediate Action Required: {'Yes' if risk_level in ['High', 'Critical'] else 'No'}

## Summary
"""
        
        if leak_count == 0 and threat_count == 0:
            report += """
No significant security issues were identified during this dark web assessment. 
The organization's data appears to be well-protected with no evidence of breaches 
or active threats found in underground forums or paste sites.
"""
        else:
            report += f"""
The assessment identified {leak_count + threat_count} security concern(s) requiring attention:

"""
            if leak_count > 0:
                report += f"- **{leak_count} potential data exposure(s)** discovered\n"
            if threat_count > 0:
                report += f"- **{threat_count} threat indicator(s)** identified\n"
                
        report += """
## Recommended Actions

1. **Immediate** (within 24 hours):
   - Review all identified exposures
   - Reset any compromised credentials
   - Activate incident response if needed

2. **Short-term** (within 1 week):
   - Implement continuous dark web monitoring
   - Enhance employee security training
   - Review data handling procedures

3. **Long-term** (within 1 month):
   - Strengthen data loss prevention controls
   - Establish threat intelligence program
   - Regular security assessments

## Next Steps

A detailed technical report is available for the security team. Please schedule a 
briefing to discuss findings and remediation strategies.
"""
        
        return report
        
    def _generate_recommendations(self, findings: Dict) -> str:
        """Generate detailed recommendations section"""
        recs = "\n## 3. Recommendations\n\n"
        
        risk_level = self._calculate_overall_risk(findings)
        
        if risk_level in ['High', 'Critical']:
            recs += "### 3.1 🚨 Immediate Actions (Within 24 Hours)\n\n"
            recs += "1. **Incident Response Activation**\n"
            recs += "   - Activate security incident response team\n"
            recs += "   - Document all findings for investigation\n"
            recs += "   - Preserve evidence for analysis\n\n"
            
        recs += "### 3.2 Short-term Improvements (Within 1 Week)\n\n"
        recs += "1. **Credential Management**\n"
        recs += "   - Force password reset for affected accounts\n"
        recs += "   - Implement multi-factor authentication\n"
        recs += "   - Review privileged access management\n\n"
        
        recs += "2. **Monitoring Enhancement**\n"
        recs += "   - Deploy continuous dark web monitoring\n"
        recs += "   - Set up automated alerts for brand mentions\n"
        recs += "   - Increase logging and retention\n\n"
        
        recs += "### 3.3 Long-term Security Posture (Within 1 Month)\n\n"
        recs += "1. **Data Loss Prevention**\n"
        recs += "   - Implement DLP solutions\n"
        recs += "   - Classify and tag sensitive data\n"
        recs += "   - Regular data exposure assessments\n\n"
        
        recs += "2. **Security Awareness**\n"
        recs += "   - Conduct phishing simulations\n"
        recs += "   - Dark web awareness training\n"
        recs += "   - Update security policies\n\n"
        
        return recs
        
    def _generate_technical_appendix(self, findings: Dict) -> str:
        """Generate technical details appendix"""
        appendix = "\n## Appendix A: Technical Details\n\n"
        
        appendix += "### Search Parameters\n"
        appendix += "```\n"
        appendix += f"Target: {findings.get('target', 'N/A')}\n"
        appendix += f"Keywords: {findings.get('keywords', [])}\n"
        appendix += f"Tor Enabled: {findings.get('tor_enabled', False)}\n"
        if findings.get('tor_exit_ip'):
            appendix += f"Exit IP: {findings.get('tor_exit_ip')}\n"
        appendix += "```\n\n"
        
        appendix += "### Sources Checked\n"
        for source in findings.get('sources_checked', []):
            appendix += f"- {source}\n"
            
        return appendix
        
    def _calculate_overall_risk(self, findings: Dict) -> str:
        """Calculate overall risk level from findings"""
        risk_score = 0
        
        # Check data leaks
        leaks = findings.get('leak_search', {}).get('potential_leaks', [])
        for leak in leaks:
            severity = leak.get('severity', 'low')
            if severity == 'critical':
                risk_score += 10
            elif severity == 'high':
                risk_score += 7
            elif severity == 'medium':
                risk_score += 4
            elif severity == 'low':
                risk_score += 1
                
        # Check threats
        threats = findings.get('threat_intel', {}).get('threats_found', [])
        risk_score += len(threats) * 5
        
        # Determine risk level
        if risk_score >= 20:
            return 'Critical'
        elif risk_score >= 10:
            return 'High'
        elif risk_score >= 5:
            return 'Medium'
        else:
            return 'Low'
            
    def _generate_report_id(self, findings: Dict) -> str:
        """Generate unique report ID"""
        data = f"{findings.get('target', '')}{findings.get('timestamp', '')}"
        return hashlib.sha256(data.encode()).hexdigest()[:12].upper()
        
    def _sanitize_sample(self, sample: str) -> str:
        """Sanitize sample data for safe display"""
        # Redact sensitive patterns
        import re
        # Redact emails partially
        sample = re.sub(r'([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', 
                       r'\1@*****.***', sample)
        # Redact IPs
        sample = re.sub(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', 
                       r'***.***.***.***', sample)
        # Limit length
        if len(sample) > 100:
            sample = sample[:100] + '...'
        return sample
        
    def _get_recommendations_list(self, findings: Dict) -> List[Dict]:
        """Get list of recommendations for templates"""
        recs = []
        risk_level = self._calculate_overall_risk(findings)
        
        if risk_level in ['High', 'Critical']:
            recs.append({
                'title': 'Immediate Incident Response',
                'description': 'Activate security incident response team immediately',
                'priority': 'critical'
            })
            
        recs.extend([
            {
                'title': 'Credential Reset',
                'description': 'Force password reset for potentially affected accounts',
                'priority': 'high'
            },
            {
                'title': 'Dark Web Monitoring',
                'description': 'Implement continuous monitoring for organizational data',
                'priority': 'medium'
            },
            {
                'title': 'Security Training',
                'description': 'Conduct security awareness training on data protection',
                'priority': 'medium'
            }
        ])
        
        return recs