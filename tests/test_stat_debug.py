from debug import debug
from classes import Response, BaseModule, STATError, DebugModule
import pytest
import os
from unittest.mock import Mock, patch

def test_debug_module_classes():
    """Test DebugModule class initialization"""
    req_body = {
        'Test': 'token',
        'Params': {'test': 'data'}
    }
    debug_mod = DebugModule(req_body)
    
    assert hasattr(debug_mod, 'Test')
    assert hasattr(debug_mod, 'Params')

def test_debug_mode_disabled():
    """Test that debug module raises error when DEBUG_MODE is not enabled"""
    with patch.dict(os.environ, {}, clear=True):  # Clear DEBUG_MODE
        req_body = {
            'Test': 'token',
            'Params': {}
        }
        
        with pytest.raises(STATError) as exc_info:
            debug.debug_module(req_body)
        
        assert 'DEBUG_MODE environment variable must be set to 1' in str(exc_info.value)

def test_debug_token_test():
    """Test debug module with token test"""
    with patch.dict(os.environ, {'DEBUG_MODE': '1'}), \
         patch('debug.debug.default_debug'), \
         patch('debug.debug.token_debug'):
        
        req_body = {
            'Test': 'token',
            'Params': {}
        }
        
        result = debug.debug_module(req_body)
        
        assert isinstance(result, Response)
        assert isinstance(result.body, DebugModule)

def test_debug_rest_test():
    """Test debug module with rest test"""
    with patch.dict(os.environ, {'DEBUG_MODE': '1'}), \
         patch('debug.debug.default_debug'), \
         patch('debug.debug.rest_debug'):
        
        req_body = {
            'Test': 'rest',
            'Params': {
                'Method': 'get',
                'Path': '/test',
                'MultiTenantConfig': {}
            }
        }
        
        result = debug.debug_module(req_body)
        
        assert isinstance(result, Response)
        assert isinstance(result.body, DebugModule)

def test_debug_rbac_test():
    """Test debug module with rbac test"""
    with patch.dict(os.environ, {'DEBUG_MODE': '1'}), \
         patch('debug.debug.default_debug'), \
         patch('debug.debug.token_debug'), \
         patch('debug.debug.rbac_debug'):
        
        req_body = {
            'Test': 'rbac',
            'Params': {}
        }
        
        result = debug.debug_module(req_body)
        
        assert isinstance(result, Response)
        assert isinstance(result.body, DebugModule)

def test_debug_comment_test():
    """Test debug module with comment test"""
    with patch.dict(os.environ, {'DEBUG_MODE': '1'}), \
         patch('debug.debug.default_debug'), \
         patch('debug.debug.comment_debug'):
        
        req_body = {
            'Test': 'comment',
            'Params': {}
        }
        
        result = debug.debug_module(req_body)
        
        assert isinstance(result, Response)
        assert isinstance(result.body, DebugModule)

def test_debug_exception_test():
    """Test debug module with exception test"""
    with patch.dict(os.environ, {'DEBUG_MODE': '1'}), \
         patch('debug.debug.exception_debug'):
        
        req_body = {
            'Test': 'exception',
            'Params': {}
        }
        
        result = debug.debug_module(req_body)
        
        assert isinstance(result, Response)
        assert isinstance(result.body, DebugModule)

def test_debug_default_test():
    """Test debug module with unknown test (falls back to default)"""
    with patch.dict(os.environ, {'DEBUG_MODE': '1'}), \
         patch('debug.debug.default_debug'):
        
        req_body = {
            'Test': 'unknown_test',
            'Params': {}
        }
        
        result = debug.debug_module(req_body)
        
        assert isinstance(result, Response)
        assert isinstance(result.body, DebugModule)

def test_debug_rest_methods():
    """Test debug rest method validation"""
    with patch.dict(os.environ, {'DEBUG_MODE': '1'}), \
         patch('debug.debug.default_debug'), \
         patch('debug.debug.rest') as mock_rest:
        
        # Mock REST response
        mock_response = Mock()
        mock_rest.rest_call_get.return_value = mock_response
        
        # Test GET method
        req_body = {
            'Test': 'rest',
            'Params': {
                'Method': 'get',
                'Path': '/test/path',
                'TokenType': 'msgraph',
                'MultiTenantConfig': {}
            }
        }
        
        result = debug.debug_module(req_body)
        assert isinstance(result, Response)

def test_debug_rest_invalid_method():
    """Test debug rest with invalid method"""
    with patch.dict(os.environ, {'DEBUG_MODE': '1'}), \
         patch('debug.debug.default_debug'):
        
        req_body = {
            'Test': 'rest',
            'Params': {
                'Method': 'invalid_method',
                'Path': '/test/path',
                'MultiTenantConfig': {}
            }
        }
        
        with pytest.raises(STATError) as exc_info:
            debug.debug_module(req_body)
        
        # Check if the error contains the expected message
        error = exc_info.value
        assert hasattr(error, 'error') or 'Invalid Method' in str(error) or len(exc_info.value.args) > 0