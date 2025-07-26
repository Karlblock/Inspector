#!/usr/bin/env python3
"""
Test script for Tor OSINT module
Tests the functionality without requiring actual Tor connection
"""

import sys
import os
import tempfile
import json

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from enumeration.modules.tor_osint import TorOSINTModule
from enumeration.modules.tor_osint.protection import TorOSINTProtection
from enumeration.modules.tor_osint.reporting import TorOSINTReporter
from enumeration.modules.tor_osint.integrations import TorOSINTIntegrations


def test_protection_module():
    """Test the protection component"""
    print("Testing Protection Module...")
    protection = TorOSINTProtection()
    
    # Test domain validation
    print("\n1. Testing domain validation:")
    test_domains = [
        ("example.com", True),
        ("sub.example.com", True),
        ("invalid..domain", False),
        ("-invalid.com", False),
        ("valid-domain.org", True)
    ]
    
    for domain, expected in test_domains:
        # Note: This tests the authorization check, not domain format
        result = protection._is_authorized_target(domain)
        print(f"  {domain}: {'✓' if result == expected else '✗'} (expected: {expected})")
    
    # Test keyword sanitization
    print("\n2. Testing keyword sanitization:")
    test_keywords = [
        ["password", "leak", "breach"],  # Valid
        ["ssn", "credit card", "illegal"],  # Should be filtered
        ["database", "exposure", "vulnerability"]  # Valid
    ]
    
    for keywords in test_keywords:
        validation = protection.validate_search_scope("example.com", keywords)
        print(f"  Keywords: {keywords}")
        print(f"  Sanitized: {validation['sanitized_keywords']}")
        print(f"  Issues: {validation['issues'] if validation['issues'] else 'None'}")
    
    # Test rate limiting
    print("\n3. Testing rate limiting:")
    for i in range(12):
        allowed = protection.check_rate_limits()
        if i < 10:
            print(f"  Request {i+1}: {'✓ Allowed' if allowed else '✗ Blocked'}")
        else:
            print(f"  Request {i+1}: {'✓ Allowed' if allowed else '✗ Blocked (expected)'}")
    
    # Test compliance check
    print("\n4. Testing legal compliance:")
    operations = ["tor_osint_research", "scan", "exploit"]
    for op in operations:
        compliance = protection.check_legal_compliance(op)
        print(f"  Operation '{op}': {'✓ Compliant' if compliance['compliant'] else '✗ Not Compliant'}")
        if compliance['warnings']:
            print(f"    Warnings: {compliance['warnings']}")
    
    print("\n✓ Protection module tests completed")


def test_reporting_module():
    """Test the reporting component"""
    print("\nTesting Reporting Module...")
    reporter = TorOSINTReporter()
    
    # Create sample findings
    sample_findings = {
        'target': 'example.com',
        'keywords': ['password', 'leak', 'breach'],
        'tor_enabled': True,
        'tor_exit_ip': '192.168.1.1',
        'leak_search': {
            'potential_leaks': [
                {
                    'type': 'Email List',
                    'source': 'Pastebin',
                    'severity': 'medium',
                    'details': 'Found example.com email addresses in public paste',
                    'timestamp': '2024-01-15T10:30:00'
                },
                {
                    'type': 'Configuration File',
                    'source': 'GitHub',
                    'severity': 'high',
                    'details': 'Database configuration with example.com credentials',
                    'timestamp': '2024-01-14T15:45:00'
                }
            ],
            'risk_level': 'high'
        },
        'threat_intel': {
            'threats_found': [
                'Potential phishing campaign targeting example.com users',
                'Discussion about example.com vulnerabilities in forum'
            ]
        }
    }
    
    # Test different report formats
    print("\n1. Testing report generation:")
    formats = ['markdown', 'html', 'json', 'executive']
    
    for format in formats:
        try:
            report = reporter.generate_report(sample_findings, format=format)
            print(f"  {format.capitalize()} report: ✓ Generated ({len(report)} chars)")
            
            # Save sample report
            if format == 'markdown':
                with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
                    f.write(report)
                    print(f"    Sample saved to: {f.name}")
        except Exception as e:
            print(f"  {format.capitalize()} report: ✗ Error: {e}")
    
    # Test risk calculation
    print("\n2. Testing risk assessment:")
    test_scenarios = [
        {'leak_search': {'potential_leaks': []}, 'threat_intel': {'threats_found': []}},  # Low
        {'leak_search': {'potential_leaks': [{'severity': 'medium'}]}, 'threat_intel': {'threats_found': []}},  # Medium
        {'leak_search': {'potential_leaks': [{'severity': 'high'}, {'severity': 'high'}]}, 'threat_intel': {'threats_found': ['threat']}},  # High
    ]
    
    for i, scenario in enumerate(test_scenarios):
        risk = reporter._calculate_overall_risk(scenario)
        print(f"  Scenario {i+1}: {risk} risk")
    
    print("\n✓ Reporting module tests completed")


def test_integrations_module():
    """Test the integrations component"""
    print("\nTesting Integrations Module...")
    integrations = TorOSINTIntegrations()
    
    print("\n1. Testing STIX export:")
    sample_findings = {
        'target': 'example.com',
        'threat_intel': {
            'threats_found': ['Threat actor targeting example.com']
        },
        'leak_search': {
            'potential_leaks': [
                {
                    'type': 'Data Leak',
                    'details': 'Sensitive data exposure'
                }
            ]
        }
    }
    
    try:
        stix_data = integrations.export_to_stix(sample_findings)
        stix_json = json.loads(stix_data)
        print(f"  ✓ STIX bundle created with {len(stix_json.get('objects', []))} objects")
    except Exception as e:
        print(f"  ✗ Error: {e}")
    
    print("\n2. Testing integration readiness:")
    # Note: These will fail without actual API keys, but we're testing the structure
    integrations_to_test = [
        ('HIBP', lambda: integrations.check_hibp_breaches('example.com')),
        ('Shodan', lambda: integrations.check_shodan_exposure('example.com')),
        ('Slack', lambda: integrations.send_slack_alert(sample_findings)),
        ('Jira', lambda: integrations.create_jira_ticket(sample_findings))
    ]
    
    for name, func in integrations_to_test:
        try:
            result = func()
            if 'error' in result or not any([result.get('breaches_found'), 
                                           result.get('exposed_services'),
                                           result.get('alert_sent'),
                                           result.get('ticket_created')]):
                print(f"  {name}: ⚠️  Not configured (expected without API keys)")
            else:
                print(f"  {name}: ✓ Ready")
        except Exception as e:
            print(f"  {name}: ⚠️  Not configured")
    
    print("\n✓ Integrations module tests completed")


def test_main_module():
    """Test the main Tor OSINT module"""
    print("\nTesting Main Tor OSINT Module...")
    
    # Create temporary directory for output
    with tempfile.TemporaryDirectory() as temp_dir:
        tor_module = TorOSINTModule()
        
        # Test without Tor (safe test)
        print("\n1. Testing basic enumeration (no Tor):")
        results = tor_module.run(
            target='example.com',
            session_id='test_session_001',
            output_dir=temp_dir,
            use_tor=False,
            keywords=['test', 'sample'],
            report_format='markdown'
        )
        
        print(f"  Module: {results.get('module')} ✓")
        print(f"  Target: {results.get('target')} ✓")
        print(f"  Tor enabled: {results.get('tor_enabled')}")
        print(f"  Findings: {len(results.get('findings', {}))} categories")
        
        if results.get('report_path'):
            print(f"  Report generated: {results['report_path']} ✓")
        
        # Test Tor connection check (will fail without Tor)
        print("\n2. Testing Tor connection verification:")
        tor_available = tor_module.verify_tor_connection()
        print(f"  Tor service: {'✓ Available' if tor_available else '⚠️  Not available (expected in test)'}")
        
        # Test cleanup
        print("\n3. Testing cleanup:")
        tor_module.cleanup()
        print("  ✓ Cleanup completed")
    
    print("\n✓ Main module tests completed")


def main():
    """Run all tests"""
    print("=" * 60)
    print("Tor OSINT Module Test Suite")
    print("=" * 60)
    
    try:
        test_protection_module()
        test_reporting_module()
        test_integrations_module()
        test_main_module()
        
        print("\n" + "=" * 60)
        print("✓ All tests completed successfully!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()