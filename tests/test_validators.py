#!/usr/bin/env python3
"""
Basic tests for input validators
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from utils.validators import InputValidator

def test_ip_validation():
    """Test IP address validation"""
    print("Testing IP validation...")
    
    # Valid IPs
    assert InputValidator.validate_ip("192.168.1.1") == True
    assert InputValidator.validate_ip("10.0.0.1") == True
    assert InputValidator.validate_ip("127.0.0.1") == True
    assert InputValidator.validate_ip("8.8.8.8") == True
    
    # Invalid IPs
    assert InputValidator.validate_ip("256.1.1.1") == False
    assert InputValidator.validate_ip("192.168.1") == False
    assert InputValidator.validate_ip("not.an.ip") == False
    assert InputValidator.validate_ip("") == False
    
    print("✓ IP validation tests passed")

def test_port_validation():
    """Test port validation"""
    print("Testing port validation...")
    
    # Valid ports
    assert InputValidator.validate_port(80) == True
    assert InputValidator.validate_port("80") == True
    assert InputValidator.validate_port("80-443") == True
    assert InputValidator.validate_port("80,443,8080") == True
    
    # Invalid ports
    assert InputValidator.validate_port(0) == False
    assert InputValidator.validate_port(65536) == False
    assert InputValidator.validate_port("abc") == False
    assert InputValidator.validate_port("80-") == False
    
    print("✓ Port validation tests passed")

def test_machine_name_validation():
    """Test machine name validation"""
    print("Testing machine name validation...")
    
    # Valid names
    assert InputValidator.validate_machine_name("Cronos") == True
    assert InputValidator.validate_machine_name("Blue-Box") == True
    assert InputValidator.validate_machine_name("test_machine") == True
    assert InputValidator.validate_machine_name("Box123") == True
    
    # Invalid names
    assert InputValidator.validate_machine_name("Box@123") == False
    assert InputValidator.validate_machine_name("Box Name") == False
    assert InputValidator.validate_machine_name("") == False
    assert InputValidator.validate_machine_name("a" * 51) == False  # Too long
    
    print("✓ Machine name validation tests passed")

def test_profile_validation():
    """Test profile name validation"""
    print("Testing profile validation...")
    
    # Valid profiles
    assert InputValidator.validate_profile_name("basic") == True
    assert InputValidator.validate_profile_name("linux-basic") == True
    assert InputValidator.validate_profile_name("windows-ad") == True
    
    # Invalid profiles
    assert InputValidator.validate_profile_name("custom-profile") == False
    assert InputValidator.validate_profile_name("") == False
    assert InputValidator.validate_profile_name("unknown") == False
    
    print("✓ Profile validation tests passed")

def test_command_sanitization():
    """Test command argument sanitization"""
    print("Testing command sanitization...")
    
    # Test various inputs
    assert InputValidator.sanitize_command_arg("simple") == "simple"
    assert InputValidator.sanitize_command_arg("with space") == "'with space'"
    assert InputValidator.sanitize_command_arg("rm -rf /") == "'rm -rf /'"
    assert InputValidator.sanitize_command_arg("'; cat /etc/passwd") == "''\"'\"'; cat /etc/passwd'"
    
    print("✓ Command sanitization tests passed")

def main():
    """Run all tests"""
    print("Running cyba-HTB validator tests...\n")
    
    test_ip_validation()
    test_port_validation()
    test_machine_name_validation()
    test_profile_validation()
    test_command_sanitization()
    
    print("\n✅ All tests passed!")

if __name__ == "__main__":
    main()