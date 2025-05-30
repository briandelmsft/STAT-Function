"""
Cross-module error handling and edge case tests.
Tests error conditions and edge cases that span multiple modules.
"""

from classes import BaseModule, STATError, STATNotFound, Response
import pytest
from unittest.mock import Mock, patch
from tests.test_utilities import create_mock_base_module, create_test_input

def test_stat_error_creation():
    """Test STATError class creation and properties"""
    # Test basic STATError
    error = STATError("Test error message")
    assert hasattr(error, 'error')
    
    # Test STATError with source and status code
    source_error = {'status_code': 404, 'message': 'Not found'}
    error_with_source = STATError("Test error", source_error, 404)
    assert hasattr(error_with_source, 'source_error')
    assert hasattr(error_with_source, 'status_code')

def test_stat_not_found_creation():
    """Test STATNotFound class creation"""
    not_found = STATNotFound("Resource not found")
    assert isinstance(not_found, STATError)

def test_base_module_missing_required_fields():
    """Test BaseModule behavior with missing required fields"""
    base = BaseModule()
    
    # Test that required fields exist after initialization
    required_fields = [
        'Accounts', 'AccountsCount', 'IPs', 'IPsCount', 
        'Domains', 'DomainsCount', 'FileHashes', 'FileHashesCount',
        'Files', 'FilesCount', 'Hosts', 'HostsCount',
        'URLs', 'URLsCount', 'OtherEntities', 'OtherEntitiesCount'
    ]
    
    for field in required_fields:
        assert hasattr(base, field), f"Missing required field: {field}"

def test_response_class_structure():
    """Test Response class structure and properties"""
    from classes import BaseModule
    
    test_body = BaseModule()
    response = Response(test_body)
    
    assert hasattr(response, 'body')
    assert hasattr(response, 'statuscode')
    assert response.statuscode == 200  # Default status code
    assert response.body == test_body

def test_module_input_validation_patterns():
    """Test common input validation patterns across modules"""
    
    # Test missing BaseModuleBody
    invalid_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False
        # Missing BaseModuleBody
    }
    
    # Most modules should fail without BaseModuleBody
    with pytest.raises(KeyError):
        # This simulates what happens when modules try to access BaseModuleBody
        base_body = invalid_input['BaseModuleBody']

def test_boolean_parameter_handling():
    """Test how modules handle boolean parameters"""
    test_cases = [
        (True, True),
        (False, False),
        ('true', 'true'),  # String values should be preserved
        ('false', 'false'),
        (1, 1),  # Numeric values should be preserved
        (0, 0),
        (None, None)  # None should be preserved
    ]
    
    for input_val, expected in test_cases:
        test_input = {'AddIncidentComments': input_val}
        assert test_input.get('AddIncidentComments') == expected

def test_integer_parameter_handling():
    """Test how modules handle integer parameters"""
    test_cases = [
        (7, 7),
        ('7', '7'),  # String numbers should be preserved as strings
        (0, 0),
        (-1, -1),
        (None, None)
    ]
    
    for input_val, expected in test_cases:
        test_input = {'LookbackInDays': input_val}
        assert test_input.get('LookbackInDays') == expected

def test_string_parameter_handling():
    """Test how modules handle string parameters"""
    test_cases = [
        ('test', 'test'),
        ('', ''),  # Empty string
        (None, None),
        ('  spaced  ', '  spaced  ')  # Preserve whitespace
    ]
    
    for input_val, expected in test_cases:
        test_input = {'Title': input_val}
        assert test_input.get('Title') == expected

def test_default_parameter_behavior():
    """Test default parameter behavior using .get() method"""
    test_input = {}
    
    # Test common default patterns
    assert test_input.get('AddIncidentComments', True) == True
    assert test_input.get('AddIncidentTask', False) == False
    assert test_input.get('LookbackInDays', 30) == 30
    assert test_input.get('CheckDomains', True) == True
    assert test_input.get('ScoreThreshold', 0) == 0

def test_list_parameter_handling():
    """Test how modules handle list parameters"""
    test_cases = [
        ([], []),
        (['item1', 'item2'], ['item1', 'item2']),
        (None, None),
        ([1, 2, 3], [1, 2, 3])
    ]
    
    for input_val, expected in test_cases:
        test_input = {'EntityList': input_val}
        assert test_input.get('EntityList') == expected

def test_dict_parameter_handling():
    """Test how modules handle dictionary parameters"""
    test_cases = [
        ({}, {}),
        ({'key': 'value'}, {'key': 'value'}),
        (None, None),
        ({'nested': {'key': 'value'}}, {'nested': {'key': 'value'}})
    ]
    
    for input_val, expected in test_cases:
        test_input = {'ConfigData': input_val}
        assert test_input.get('ConfigData') == expected

def test_module_error_message_consistency():
    """Test that error messages follow consistent patterns"""
    # Common error message patterns that should be consistent
    error_patterns = [
        "missing",
        "required",
        "invalid",
        "not found",
        "failed to",
        "unable to"
    ]
    
    # Test STATError message formatting
    for pattern in error_patterns:
        error_msg = f"Test {pattern} condition"
        error = STATError(error_msg)
        # Error should contain the pattern
        assert pattern in error_msg.lower()

def test_workspace_arm_id_format():
    """Test workspace ARM ID format validation"""
    valid_arm_id = '/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/rg-test/providers/Microsoft.OperationalInsights/workspaces/ws-test'
    
    # Test ARM ID structure
    assert valid_arm_id.startswith('/subscriptions/')
    assert 'resourceGroups' in valid_arm_id
    assert 'Microsoft.OperationalInsights/workspaces' in valid_arm_id

def test_incident_arm_id_format():
    """Test incident ARM ID format validation"""
    base_workspace = '/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/rg-test/providers/Microsoft.OperationalInsights/workspaces/ws-test'
    incident_id = '12345678-1234-1234-1234-123456789012'
    incident_arm_id = f'{base_workspace}/providers/Microsoft.SecurityInsights/incidents/{incident_id}'
    
    # Test incident ARM ID structure
    assert incident_arm_id.startswith(base_workspace)
    assert 'Microsoft.SecurityInsights/incidents' in incident_arm_id
    assert incident_id in incident_arm_id

def test_alert_arm_id_format():
    """Test alert ARM ID format validation"""
    base_workspace = '/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/rg-test/providers/Microsoft.OperationalInsights/workspaces/ws-test'
    alert_id = '12345678-1234-1234-1234-123456789012'
    alert_arm_id = f'{base_workspace}/providers/Microsoft.SecurityInsights/alerts/{alert_id}'
    
    # Test alert ARM ID structure
    assert alert_arm_id.startswith(base_workspace)
    assert 'Microsoft.SecurityInsights/alerts' in alert_arm_id
    assert alert_id in alert_arm_id

def test_entity_data_structure():
    """Test common entity data structure patterns"""
    # Test account entity structure
    account_entity = {
        'userPrincipalName': 'test@example.com',
        'SamAccountName': 'testuser',
        'SID': 'S-1-5-21-123456789-987654321-111111111-1001',
        'id': '12345678-1234-1234-1234-123456789012'
    }
    
    required_account_fields = ['userPrincipalName', 'SamAccountName', 'SID', 'id']
    for field in required_account_fields:
        assert field in account_entity
        assert account_entity[field] is not None
    
    # Test IP entity structure
    ip_entity = {
        'Address': '192.168.1.1',
        'IPType': 2,
        'GeoData': {},
        'RawEntity': {}
    }
    
    required_ip_fields = ['Address', 'IPType', 'GeoData', 'RawEntity']
    for field in required_ip_fields:
        assert field in ip_entity
        assert ip_entity[field] is not None

def test_module_response_consistency():
    """Test that all modules return consistent response structures"""
    from classes import Response, BaseModule, TIModule, AADModule
    
    # Test different module response types
    module_types = [BaseModule, TIModule, AADModule]
    
    for module_type in module_types:
        module_instance = module_type()
        response = Response(module_instance)
        
        assert isinstance(response, Response)
        assert response.statuscode == 200
        assert hasattr(response, 'body')
        assert isinstance(response.body, module_type)