#!/usr/bin/env python3
"""
Example usage of Tor OSINT module for defensive security
This demonstrates legal and ethical usage only
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.enumeration.modules.tor_osint import TorOSINTModule
from src.utils.logger import Logger

def defensive_osint_example():
    """
    Example of defensive OSINT research
    Only use for authorized targets!
    """
    logger = Logger(__name__)
    
    # Initialize module
    tor_module = TorOSINTModule()
    
    # IMPORTANT: Only use YOUR OWN domain
    target_domain = "your-company.com"  # Replace with YOUR authorized domain
    
    # Defensive keywords to monitor
    keywords = [
        'password',
        'database',
        'leak',
        'breach',
        'credentials',
        'api key',
        'internal'
    ]
    
    # Organization-specific keywords for threat monitoring
    org_keywords = [
        target_domain,
        'YourCompany',  # Your company name
        'YourProduct'   # Your product names
    ]
    
    print("🛡️  Defensive Tor OSINT Research")
    print("=" * 50)
    print(f"Target: {target_domain}")
    print(f"Scope: Defensive security only")
    print("=" * 50)
    
    # Check if Tor is available
    print("\n🔍 Checking Tor availability...")
    if tor_module.verify_tor_connection():
        print("✅ Tor is available and connected")
        use_tor = True
    else:
        print("⚠️  Tor is not available, will use clearnet only")
        print("   For better results, install and start Tor:")
        print("   sudo apt install tor")
        print("   sudo systemctl start tor")
        use_tor = False
    
    # Perform defensive research
    print("\n🔎 Starting defensive research...")
    results = tor_module.run(
        target=target_domain,
        session_id="defensive-example",
        output_dir="/tmp/cyba-osint",
        use_tor=use_tor,
        keywords=keywords,
        org_keywords=org_keywords
    )
    
    # Display results
    print("\n📊 Results Summary:")
    print("-" * 40)
    
    if 'findings' in results:
        findings = results['findings']
        
        # Data leak results
        if 'leak_search' in findings:
            leaks = findings['leak_search']
            risk_level = leaks.get('risk_level', 'unknown')
            leak_count = len(leaks.get('potential_leaks', []))
            
            print(f"Risk Level: {risk_level.upper()}")
            print(f"Potential Issues Found: {leak_count}")
            
            if leak_count > 0:
                print("\n⚠️  Action Required:")
                for leak in leaks['potential_leaks']:
                    print(f"  - {leak['type']}: {leak['recommendation']}")
        
        # Threat intelligence
        if 'threat_intel' in findings:
            threats = findings['threat_intel']
            threat_count = len(threats.get('threats_found', []))
            print(f"\nActive Threats Detected: {threat_count}")
    
    # Report location
    if 'report_path' in results:
        print(f"\n📄 Full report saved to: {results['report_path']}")
    
    print("\n✅ Defensive research completed")
    print("\n⚖️  Legal Notice:")
    print("This research was conducted for defensive purposes only.")
    print("All activities were within legal and ethical boundaries.")


def setup_monitoring():
    """
    Example of setting up continuous monitoring
    """
    print("\n🔔 Setting Up Continuous Monitoring")
    print("=" * 50)
    
    # Example monitoring configuration
    monitoring_config = """
# Example monitoring configuration (monitoring.yaml)
targets:
  - domain: your-company.com
    keywords:
      - password
      - database
      - breach
      - api key
    check_interval: 3600  # 1 hour
    
notifications:
  email: security@your-company.com
  webhook: https://your-company.com/security-webhook
  
tor_settings:
  use_tor: true
  circuit_refresh: 300  # 5 minutes
  
compliance:
  log_retention: 90  # days
  encryption: true
  gdpr_compliant: true
"""
    
    print(monitoring_config)
    print("\nImplement this configuration in your security monitoring system")


if __name__ == "__main__":
    print("🛡️  Tor OSINT Defensive Security Example")
    print("=" * 50)
    print("\n⚠️  IMPORTANT: Only use for authorized targets!")
    print("This tool is for defensive security research only.\n")
    
    # Run example
    defensive_osint_example()
    
    # Show monitoring setup
    setup_monitoring()
    
    print("\n📚 Next Steps:")
    print("1. Configure Tor for your security team")
    print("2. Set up continuous monitoring")
    print("3. Integrate with your SIEM/SOAR")
    print("4. Train team on defensive OSINT")
    print("5. Document all research activities")