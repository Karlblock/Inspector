#!/usr/bin/env python3
"""
Tests for Tor OSINT module
Focus on defensive security testing only
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import tempfile
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.enumeration.modules.tor_osint import TorOSINTModule


class TestTorOSINTModule(unittest.TestCase):
    """Test cases for Tor OSINT module"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.module = TorOSINTModule()
        self.test_target = "example.com"
        self.test_session = "test-session-123"
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up after tests"""
        # Clean up temp directory
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_module_initialization(self):
        """Test module initializes correctly"""
        self.assertEqual(self.module.name, 'tor_osint')
        self.assertEqual(self.module.tor_proxy, "socks5h://127.0.0.1:9050")
        self.assertIsNotNone(self.module.logger)
        self.assertIsNotNone(self.module.validator)
    
    @patch('subprocess.run')
    @patch('socket.socket')
    def test_verify_tor_connection_success(self, mock_socket, mock_run):
        """Test successful Tor connection verification"""
        # Mock systemctl check
        mock_run.return_value = Mock(stdout='active\n')
        
        # Mock socket connection
        mock_socket_instance = Mock()
        mock_socket.return_value = mock_socket_instance
        
        result = self.module.verify_tor_connection()
        self.assertTrue(result)
        
        # Verify systemctl was called
        mock_run.assert_called_with(['systemctl', 'is-active', 'tor'], 
                                   capture_output=True, text=True)
    
    @patch('subprocess.run')
    def test_verify_tor_connection_service_not_active(self, mock_run):
        """Test Tor connection when service is not active"""
        mock_run.return_value = Mock(stdout='inactive\n')
        
        result = self.module.verify_tor_connection()
        self.assertFalse(result)
    
    def test_search_data_leaks_valid_domain(self):
        """Test data leak search with valid domain"""
        keywords = ['password', 'leak', 'database']
        
        results = self.module.search_data_leaks(self.test_target, keywords)
        
        self.assertIn('searched_terms', results)
        self.assertIn('potential_leaks', results)
        self.assertIn('risk_level', results)
        self.assertIn('timestamp', results)
        
        # Check search terms were built correctly
        self.assertIn(self.test_target, results['searched_terms'])
        self.assertIn(f"@{self.test_target}", results['searched_terms'])
    
    def test_search_data_leaks_invalid_domain(self):
        """Test data leak search with invalid domain"""
        invalid_domain = "not-a-valid-domain!"
        keywords = ['test']
        
        results = self.module.search_data_leaks(invalid_domain, keywords)
        
        # Should return empty results for invalid domain
        self.assertEqual(results['risk_level'], 'low')
        self.assertEqual(len(results['potential_leaks']), 0)
    
    def test_monitor_threat_intel(self):
        """Test threat intelligence monitoring"""
        org_keywords = ['example corp', 'example.com', 'example']
        
        intel = self.module.monitor_threat_intel(org_keywords)
        
        self.assertIn('monitoring_keywords', intel)
        self.assertIn('threats_found', intel)
        self.assertIn('monitoring_timestamp', intel)
        self.assertEqual(intel['monitoring_keywords'], org_keywords)
    
    def test_generate_defensive_report(self):
        """Test defensive report generation"""
        findings = {
            'target_domain': 'example.com',
            'tor_enabled': True,
            'leak_search': {
                'potential_leaks': [
                    {
                        'type': 'email_pattern',
                        'details': 'Found example.com emails',
                        'severity': 'medium',
                        'recommendation': 'Review and rotate credentials'
                    }
                ],
                'risk_level': 'medium'
            },
            'threat_intel': {
                'threats_found': []
            }
        }
        
        report = self.module.generate_defensive_report(findings)
        
        # Verify report contains key sections
        self.assertIn('Tor OSINT Defensive Security Report', report)
        self.assertIn('Executive Summary', report)
        self.assertIn('Findings', report)
        self.assertIn('Recommendations', report)
        self.assertIn('Legal Notice', report)
        
        # Verify findings are included
        self.assertIn('example.com', report)
        self.assertIn('email_pattern', report)
        self.assertIn('Review and rotate credentials', report)
    
    @patch.object(TorOSINTModule, 'verify_tor_connection')
    @patch.object(TorOSINTModule, 'check_tor_circuit')
    def test_run_without_tor(self, mock_check_circuit, mock_verify):
        """Test module run without Tor"""
        # Run without Tor
        results = self.module.run(
            self.test_target,
            self.test_session,
            self.temp_dir,
            use_tor=False,
            keywords=['test']
        )
        
        self.assertEqual(results['module'], 'tor_osint')
        self.assertEqual(results['target'], self.test_target)
        self.assertFalse(results['tor_enabled'])
        self.assertIn('findings', results)
        
        # Verify Tor methods were not called
        mock_verify.assert_not_called()
        mock_check_circuit.assert_not_called()
    
    @patch.object(TorOSINTModule, 'verify_tor_connection')
    @patch.object(TorOSINTModule, 'check_tor_circuit')
    def test_run_with_tor(self, mock_check_circuit, mock_verify):
        """Test module run with Tor enabled"""
        # Mock Tor connection success
        mock_verify.return_value = True
        mock_check_circuit.return_value = '1.2.3.4'
        
        results = self.module.run(
            self.test_target,
            self.test_session,
            self.temp_dir,
            use_tor=True,
            keywords=['password', 'leak']
        )
        
        self.assertTrue(results['tor_enabled'])
        self.assertEqual(results['tor_exit_ip'], '1.2.3.4')
        
        # Verify Tor methods were called
        mock_verify.assert_called_once()
        mock_check_circuit.assert_called_once()
    
    def test_cleanup(self):
        """Test module cleanup"""
        # Add some data to searches
        self.module.searches_performed = ['test1', 'test2']
        
        # Run cleanup
        self.module.cleanup()
        
        # Verify data was cleared
        self.assertEqual(len(self.module.searches_performed), 0)
    
    def test_report_file_creation(self):
        """Test that report file is created correctly"""
        results = self.module.run(
            self.test_target,
            self.test_session,
            self.temp_dir,
            use_tor=False
        )
        
        # Check report was created
        self.assertIn('report_path', results)
        report_path = results['report_path']
        self.assertTrue(os.path.exists(report_path))
        
        # Verify report content
        with open(report_path, 'r') as f:
            content = f.read()
            self.assertIn('Tor OSINT Defensive Security Report', content)
            self.assertIn(self.test_target, content)


if __name__ == '__main__':
    unittest.main()