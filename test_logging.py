#!/usr/bin/env python3
"""
Simple test script to verify logging functionality in STAT modules.
"""

import logging
import io
import sys
from unittest.mock import patch
import json

# Setup logging to capture output
log_capture_string = io.StringIO()
ch = logging.StreamHandler(log_capture_string)
ch.setLevel(logging.INFO)

# Get the root logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(ch)

def test_kql_module_logging():
    """Test that KQL module logs parameters correctly."""
    # Import after logging setup
    from modules import kql
    
    # Sample request body
    req_body = {
        'KQLQuery': 'SecurityAlert | take 10',
        'LookbackInDays': 7,
        'RunQueryAgainst': 'Sentinel',
        'AddIncidentComments': True,
        'BaseModuleBody': {
            'Accounts': [],
            'IPs': [],
            'Hosts': []
        }
    }
    
    # Mock the external dependencies to avoid actual API calls
    with patch('modules.kql.rest.execute_la_query') as mock_la_query, \
         patch('modules.kql.rest.execute_m365d_query') as mock_m365_query, \
         patch('modules.kql.rest.add_incident_comment') as mock_comment, \
         patch('modules.kql.rest.add_incident_task') as mock_task:
        
        mock_la_query.return_value = []
        mock_m365_query.return_value = []
        
        try:
            result = kql.execute_kql_module(req_body)
            print("KQL module executed successfully")
        except Exception as e:
            print(f"Expected error (missing environment config): {e}")
    
    # Check if logging messages were captured
    log_contents = log_capture_string.getvalue()
    print(f"Captured logs:\n{log_contents}")
    
    # Verify logging occurred
    assert "KQL Module invoked with parameters:" in log_contents
    assert "LookbackInDays" in log_contents
    assert "BaseModuleBody" not in log_contents  # Should be excluded
    
    print("✓ KQL module logging test passed")

def test_ti_module_logging():
    """Test that TI module logs parameters correctly."""
    from modules import ti
    
    req_body = {
        'CheckDomains': True,
        'CheckIPs': True,
        'CheckFileHashes': False,
        'CheckURLs': True,
        'BaseModuleBody': {
            'Domains': [{'Domain': 'example.com'}],
            'IPs': [{'IPAddress': '192.168.1.1'}],
            'FileHashes': [],
            'URLs': []
        }
    }
    
    # Clear previous logs
    log_capture_string.seek(0)
    log_capture_string.truncate(0)
    
    with patch('modules.ti.rest.execute_la_query') as mock_query:
        mock_query.return_value = []
        
        try:
            result = ti.execute_ti_module(req_body)
            print("TI module executed successfully")
        except Exception as e:
            print(f"Expected error (missing environment config): {e}")
    
    log_contents = log_capture_string.getvalue()
    print(f"Captured logs:\n{log_contents}")
    
    assert "Threat Intelligence Module invoked with parameters:" in log_contents
    assert "CheckDomains" in log_contents
    assert "BaseModuleBody" not in log_contents  # Should be excluded
    
    print("✓ TI module logging test passed")

if __name__ == "__main__":
    print("Testing STAT module logging functionality...")
    
    test_kql_module_logging()
    test_ti_module_logging()
    
    print("\n✓ All logging tests passed!")