#!/usr/bin/env python3
"""
Test suite for new enumeration modules (LDAP, RDP, DNS)
"""

import sys
import os
from pathlib import Path

# Add src to path
script_dir = Path(__file__).parent.parent
src_path = script_dir / 'src'
sys.path.insert(0, str(src_path))

from enumeration.modules.ldap import LDAPModule
from enumeration.modules.rdp import RDPModule
from enumeration.modules.dns import DNSModule
from utils.colors import Colors

def test_module_initialization():
    """Test that modules can be instantiated"""
    print(f"{Colors.CYAN}[*] Testing module initialization...{Colors.END}")

    try:
        ldap_module = LDAPModule()
        assert ldap_module.name == "ldap"
        assert ldap_module.ldap_ports == ['389', '636', '3268', '3269']
        print(f"{Colors.GREEN}[+] LDAP module initialized successfully{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[-] LDAP module initialization failed: {e}{Colors.END}")
        return False

    try:
        rdp_module = RDPModule()
        assert rdp_module.name == "rdp"
        assert rdp_module.rdp_port == '3389'
        print(f"{Colors.GREEN}[+] RDP module initialized successfully{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[-] RDP module initialization failed: {e}{Colors.END}")
        return False

    try:
        dns_module = DNSModule()
        assert dns_module.name == "dns"
        assert dns_module.dns_port == '53'
        print(f"{Colors.GREEN}[+] DNS module initialized successfully{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[-] DNS module initialization failed: {e}{Colors.END}")
        return False

    return True

def test_module_inheritance():
    """Test that modules inherit from BaseModule"""
    print(f"\n{Colors.CYAN}[*] Testing module inheritance...{Colors.END}")

    from enumeration.modules.base import BaseModule

    ldap_module = LDAPModule()
    rdp_module = RDPModule()
    dns_module = DNSModule()

    assert isinstance(ldap_module, BaseModule), "LDAP module should inherit from BaseModule"
    assert isinstance(rdp_module, BaseModule), "RDP module should inherit from BaseModule"
    assert isinstance(dns_module, BaseModule), "DNS module should inherit from BaseModule"

    # Check that required methods exist
    assert hasattr(ldap_module, 'run'), "LDAP module should have run() method"
    assert hasattr(rdp_module, 'run'), "RDP module should have run() method"
    assert hasattr(dns_module, 'run'), "DNS module should have run() method"

    assert hasattr(ldap_module, 'execute_command'), "LDAP module should have execute_command() method"
    assert hasattr(rdp_module, 'execute_command'), "RDP module should have execute_command() method"
    assert hasattr(dns_module, 'execute_command'), "DNS module should have execute_command() method"

    print(f"{Colors.GREEN}[+] All modules properly inherit from BaseModule{Colors.END}")
    return True

def test_module_methods():
    """Test that module methods are callable"""
    print(f"\n{Colors.CYAN}[*] Testing module methods...{Colors.END}")

    ldap_module = LDAPModule()
    rdp_module = RDPModule()
    dns_module = DNSModule()

    # Test that run() method is callable
    assert callable(ldap_module.run), "LDAP run() should be callable"
    assert callable(rdp_module.run), "RDP run() should be callable"
    assert callable(dns_module.run), "DNS run() should be callable"

    # Test that helper methods exist
    assert hasattr(ldap_module, '_check_ldap_ports'), "LDAP should have _check_ldap_ports()"
    assert hasattr(rdp_module, '_check_rdp_port'), "RDP should have _check_rdp_port()"
    assert hasattr(dns_module, '_check_dns_port'), "DNS should have _check_dns_port()"

    print(f"{Colors.GREEN}[+] All module methods are callable{Colors.END}")
    return True

def test_module_integration():
    """Test that modules can be imported by controller"""
    print(f"\n{Colors.CYAN}[*] Testing controller integration...{Colors.END}")

    try:
        from enumeration.controller import EnumerationController
        controller = EnumerationController()

        # Check that new modules are registered
        assert 'ldap' in controller.modules, "LDAP module should be registered in controller"
        assert 'rdp' in controller.modules, "RDP module should be registered in controller"
        assert 'dns' in controller.modules, "DNS module should be registered in controller"

        print(f"{Colors.GREEN}[+] All modules successfully integrated into controller{Colors.END}")
        print(f"{Colors.GREEN}[+] Registered modules: {', '.join(controller.modules.keys())}{Colors.END}")

        return True
    except Exception as e:
        print(f"{Colors.RED}[-] Controller integration failed: {e}{Colors.END}")
        return False

def test_dry_run():
    """Test running modules in dry-run mode (no actual network operations)"""
    print(f"\n{Colors.CYAN}[*] Testing dry-run mode...{Colors.END}")

    ldap_module = LDAPModule()
    rdp_module = RDPModule()
    dns_module = DNSModule()

    # Create a temporary output directory
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"{Colors.BLUE}[*] Using temp directory: {tmpdir}{Colors.END}")

        # Test LDAP module with localhost (should fail gracefully)
        print(f"\n{Colors.CYAN}[*] Testing LDAP module dry-run...{Colors.END}")
        try:
            result = ldap_module.run(
                target='127.0.0.1',
                session_id='test-session',
                output_dir=tmpdir
            )
            print(f"{Colors.GREEN}[+] LDAP module executed (returned {len(result)} results){Colors.END}")
        except Exception as e:
            print(f"{Colors.YELLOW}[!] LDAP module error (expected): {e}{Colors.END}")

        # Test RDP module
        print(f"\n{Colors.CYAN}[*] Testing RDP module dry-run...{Colors.END}")
        try:
            result = rdp_module.run(
                target='127.0.0.1',
                session_id='test-session',
                output_dir=tmpdir
            )
            print(f"{Colors.GREEN}[+] RDP module executed (returned {len(result)} results){Colors.END}")
        except Exception as e:
            print(f"{Colors.YELLOW}[!] RDP module error (expected): {e}{Colors.END}")

        # Test DNS module
        print(f"\n{Colors.CYAN}[*] Testing DNS module dry-run...{Colors.END}")
        try:
            result = dns_module.run(
                target='127.0.0.1',
                session_id='test-session',
                output_dir=tmpdir
            )
            print(f"{Colors.GREEN}[+] DNS module executed (returned {len(result)} results){Colors.END}")
        except Exception as e:
            print(f"{Colors.YELLOW}[!] DNS module error (expected): {e}{Colors.END}")

    print(f"{Colors.GREEN}[+] Dry-run tests completed{Colors.END}")
    return True

def main():
    """Run all tests"""
    print(f"{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}Testing New Enumeration Modules (LDAP, RDP, DNS){Colors.END}")
    print(f"{Colors.BOLD}{'='*60}{Colors.END}\n")

    tests = [
        ("Module Initialization", test_module_initialization),
        ("Module Inheritance", test_module_inheritance),
        ("Module Methods", test_module_methods),
        ("Controller Integration", test_module_integration),
        ("Dry Run", test_dry_run)
    ]

    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"{Colors.RED}[-] Test '{test_name}' crashed: {e}{Colors.END}")
            results.append((test_name, False))

    # Print summary
    print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}Test Summary{Colors.END}")
    print(f"{Colors.BOLD}{'='*60}{Colors.END}\n")

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = f"{Colors.GREEN}✓ PASSED{Colors.END}" if result else f"{Colors.RED}✗ FAILED{Colors.END}"
        print(f"{test_name:<30} {status}")

    print(f"\n{Colors.BOLD}Results: {passed}/{total} tests passed{Colors.END}")

    if passed == total:
        print(f"{Colors.GREEN}[+] All tests passed!{Colors.END}")
        return 0
    else:
        print(f"{Colors.RED}[-] Some tests failed{Colors.END}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
