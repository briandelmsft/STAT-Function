from modules import playbook
from classes import Response, BaseModule, STATError, RunPlaybook
import pytest
from unittest.mock import Mock, patch

def test_playbook_classes():
    """Test RunPlaybook class initialization and properties"""
    pb = RunPlaybook()
    
    # Test default initialization
    assert hasattr(pb, 'LogicAppArmId')
    assert hasattr(pb, 'TenantId')
    assert hasattr(pb, 'PlaybookName')
    assert hasattr(pb, 'IncidentArmId')

def test_playbook_missing_required_params():
    """Test that playbook raises error when required parameters are missing"""
    with patch('modules.playbook.BaseModule') as mock_base:
        mock_base_instance = Mock()
        mock_base_instance.IncidentAvailable = True
        mock_base_instance.IncidentARMId = 'test-incident-id'
        mock_base.return_value = mock_base_instance
        
        # Missing LogicAppResourceId
        playbook_input = {
            'BaseModuleBody': {'test': 'data'},
            'TenantId': 'test-tenant-id'
            # LogicAppResourceId is missing (None)
        }
        
        with pytest.raises(STATError) as exc_info:
            playbook.execute_playbook_module(playbook_input)
        
        assert 'Missing logic app id' in str(exc_info.value)

def test_playbook_missing_tenant_id():
    """Test that playbook raises error when TenantId is missing"""
    with patch('modules.playbook.BaseModule') as mock_base:
        mock_base_instance = Mock()
        mock_base_instance.IncidentAvailable = True
        mock_base_instance.IncidentARMId = 'test-incident-id'
        mock_base.return_value = mock_base_instance
        
        playbook_input = {
            'BaseModuleBody': {'test': 'data'},
            'LogicAppResourceId': '/subscriptions/test/resourceGroups/test/providers/Microsoft.Logic/workflows/test-playbook'
            # TenantId is missing (None)
        }
        
        with pytest.raises(STATError) as exc_info:
            playbook.execute_playbook_module(playbook_input)
        
        assert 'Missing logic app id' in str(exc_info.value) and 'tenant id' in str(exc_info.value)

def test_playbook_no_incident_available():
    """Test that playbook raises error when no incident is available"""
    with patch('modules.playbook.BaseModule') as mock_base:
        mock_base_instance = Mock()
        mock_base_instance.IncidentAvailable = False
        mock_base.return_value = mock_base_instance
        
        playbook_input = {
            'BaseModuleBody': {'test': 'data'},
            'LogicAppResourceId': '/subscriptions/test/resourceGroups/test/providers/Microsoft.Logic/workflows/test-playbook',
            'TenantId': 'test-tenant-id'
        }
        
        with pytest.raises(STATError) as exc_info:
            playbook.execute_playbook_module(playbook_input)
        
        assert 'There is no incident associated with this STAT triage' in str(exc_info.value)

def test_playbook_successful_execution():
    """Test successful playbook execution with mocked REST call"""
    with patch('modules.playbook.BaseModule') as mock_base, \
         patch('modules.playbook.rest') as mock_rest:
        
        # Setup mocks
        mock_base_instance = Mock()
        mock_base_instance.IncidentAvailable = True
        mock_base_instance.IncidentARMId = 'test-incident-arm-id'
        mock_base.return_value = mock_base_instance
        
        # Mock successful REST response
        mock_response = Mock()
        mock_rest.rest_call_post.return_value = mock_response
        mock_rest.add_incident_comment.return_value = Mock()
        
        playbook_input = {
            'BaseModuleBody': {'test': 'data'},
            'LogicAppResourceId': '/subscriptions/test/resourceGroups/test/providers/Microsoft.Logic/workflows/test-playbook',
            'TenantId': 'test-tenant-id',
            'PlaybookName': 'Test Playbook',
            'AddIncidentComments': True
        }
        
        result = playbook.execute_playbook_module(playbook_input)
        
        # Verify result type
        assert isinstance(result, Response)
        assert isinstance(result.body, RunPlaybook)
        
        # Verify REST call was made with correct parameters
        mock_rest.rest_call_post.assert_called_once()
        
        # Verify comment was added
        mock_rest.add_incident_comment.assert_called_once()

def test_playbook_default_name():
    """Test that playbook uses incident ARM ID as default name"""
    with patch('modules.playbook.BaseModule') as mock_base, \
         patch('modules.playbook.rest') as mock_rest:
        
        # Setup mocks
        mock_base_instance = Mock()
        mock_base_instance.IncidentAvailable = True
        mock_base_instance.IncidentARMId = 'test-incident-arm-id'
        mock_base.return_value = mock_base_instance
        
        # Mock successful REST response
        mock_response = Mock()
        mock_rest.rest_call_post.return_value = mock_response
        mock_rest.add_incident_comment.return_value = Mock()
        
        playbook_input = {
            'BaseModuleBody': {'test': 'data'},
            'LogicAppResourceId': '/subscriptions/test/resourceGroups/test/providers/Microsoft.Logic/workflows/test-playbook',
            'TenantId': 'test-tenant-id'
            # No PlaybookName provided - should default to incident ARM ID
        }
        
        result = playbook.execute_playbook_module(playbook_input)
        
        # Default playbook name should be the incident ARM ID
        assert result.body.PlaybookName == 'test-incident-arm-id'

def test_playbook_error_handling():
    """Test playbook error handling with STATError"""
    with patch('modules.playbook.BaseModule') as mock_base, \
         patch('modules.playbook.rest') as mock_rest:
        
        # Setup mocks
        mock_base_instance = Mock()
        mock_base_instance.IncidentAvailable = True
        mock_base_instance.IncidentARMId = 'test-incident-arm-id'
        mock_base.return_value = mock_base_instance
        
        # Mock REST error with 400 status code
        error_obj = STATError('Test error', {'status_code': 400}, 400)
        mock_rest.rest_call_post.side_effect = error_obj
        mock_rest.add_incident_comment.return_value = Mock()
        
        playbook_input = {
            'BaseModuleBody': {'test': 'data'},
            'LogicAppResourceId': '/subscriptions/test/resourceGroups/test/providers/Microsoft.Logic/workflows/test-playbook',
            'TenantId': 'test-tenant-id',
            'AddIncidentComments': True
        }
        
        with pytest.raises(STATError) as exc_info:
            playbook.execute_playbook_module(playbook_input)
        
        # Should contain permission guidance for 400 errors
        assert 'missing permissions' in str(exc_info.value)
        assert 'Microsoft Sentinel Playbook Operator' in str(exc_info.value)

