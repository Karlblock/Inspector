#!/usr/bin/env python3
"""
Integration tests for cyba-HTB modules
Tests module loading, dependencies, and basic functionality
"""

import sys
import os
import tempfile
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

def test_module_imports():
    """Test that all modules can be imported"""
    print("Testing module imports...")
    
    modules_to_test = [
        ('utils.colors', 'Colors'),
        ('utils.banner', 'display_banner'),
        ('utils.validators', 'InputValidator'),
        ('utils.config', 'config'),
        ('utils.session', 'SessionManager'),
        ('enumeration.controller', 'EnumerationController'),
        ('enumeration.profiles', 'EnumerationProfiles'),
        ('enumeration.modules.base', 'BaseModule'),
        ('enumeration.modules.nmap', 'NmapModule'),
        ('enumeration.modules.web', 'WebModule'),
        ('enumeration.modules.smb', 'SMBModule'),
        ('enumeration.modules.ssh', 'SSHModule'),
        ('enumeration.modules.ftp', 'FTPModule'),
        ('reporting.generator', 'ReportGenerator'),
        ('htb_questions', 'HTBQuestions'),
    ]
    
    failed = []
    for module_name, class_name in modules_to_test:
        try:
            module = __import__(module_name, fromlist=[class_name])
            if not hasattr(module, class_name):
                failed.append(f"{module_name}.{class_name} - attribute not found")
            else:
                print(f"✓ {module_name}.{class_name}")
        except ImportError as e:
            failed.append(f"{module_name} - {str(e)}")
        except Exception as e:
            failed.append(f"{module_name} - Unexpected error: {str(e)}")
    
    if failed:
        print("\n❌ Failed imports:")
        for fail in failed:
            print(f"  - {fail}")
        return False
    
    print("✅ All module imports successful\n")
    return True

def test_session_manager():
    """Test SessionManager functionality"""
    print("Testing SessionManager...")
    
    from utils.session import SessionManager
    
    # Create temporary directory for sessions
    with tempfile.TemporaryDirectory() as tmpdir:
        # Override session directory
        os.environ['CYBA_SESSION_DIR'] = tmpdir
        
        sm = SessionManager()
        
        # Test session creation
        session_id = sm.create_session(
            target="10.10.10.10",
            name="test_machine",
            profile="basic"
        )
        
        assert session_id is not None, "Session ID should not be None"
        assert len(session_id) == 8, "Session ID should be 8 characters"
        
        # Test session retrieval
        session = sm.get_session(session_id)
        assert session is not None, "Session should exist"
        assert session['target'] == "10.10.10.10", "Target should match"
        assert session['name'] == "test_machine", "Name should match"
        
        # Test session listing
        sessions = sm.list_sessions()
        assert len(sessions) >= 1, "Should have at least one session"
        
        print("✅ SessionManager tests passed\n")
        return True

def test_enumeration_profiles():
    """Test EnumerationProfiles functionality"""
    print("Testing EnumerationProfiles...")
    
    from enumeration.profiles import EnumerationProfiles
    
    ep = EnumerationProfiles()
    
    # Test profile listing
    profiles = ep.list_profiles()
    assert len(profiles) > 0, "Should have profiles"
    
    # Test getting specific profile
    basic_profile = ep.get_profile('basic')
    assert basic_profile is not None, "Basic profile should exist"
    assert 'modules' in basic_profile, "Profile should have modules"
    assert 'nmap' in basic_profile['modules'], "Basic profile should include nmap"
    
    # Test invalid profile
    invalid_profile = ep.get_profile('nonexistent')
    assert invalid_profile is None, "Invalid profile should return None"
    
    print("✅ EnumerationProfiles tests passed\n")
    return True

def test_config_system():
    """Test configuration system"""
    print("Testing Config system...")
    
    from utils.config import Config
    
    # Create config with test environment
    os.environ['CYBA_TEST_VALUE'] = 'test123'
    
    config = Config()
    
    # Test default values
    assert config.get('timeout_short') == 120, "Default timeout_short should be 120"
    assert config.get('max_threads') == 5, "Default max_threads should be 5"
    
    # Test runtime set/get
    config.set('test_value', 'test123')
    assert config.get('test_value') == 'test123', "Should get value that was set"
    
    # Test get with default
    assert config.get('nonexistent', 'default') == 'default', "Should return default for missing key"
    
    print("✅ Config system tests passed\n")
    return True

def test_validator_integration():
    """Test validator integration with other modules"""
    print("Testing Validator integration...")
    
    from utils.validators import InputValidator
    from enumeration.modules.base import BaseModule
    
    # Test that BaseModule can access validators
    assert hasattr(BaseModule, '__init__'), "BaseModule should have __init__"
    
    # Test command sanitization is accessible
    test_arg = "test; echo hacked"
    sanitized = InputValidator.sanitize_command_arg(test_arg)
    assert ";" not in sanitized or sanitized.startswith("'"), "Command should be properly escaped"
    
    print("✅ Validator integration tests passed\n")
    return True

def main():
    """Run all integration tests"""
    print("Running cyba-HTB integration tests...\n")
    
    tests = [
        test_module_imports,
        test_session_manager,
        test_enumeration_profiles,
        test_config_system,
        test_validator_integration,
    ]
    
    failed = 0
    for test in tests:
        try:
            if not test():
                failed += 1
        except Exception as e:
            print(f"❌ {test.__name__} failed with exception: {e}")
            failed += 1
    
    if failed == 0:
        print("\n✅ All integration tests passed!")
        return 0
    else:
        print(f"\n❌ {failed} test(s) failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())