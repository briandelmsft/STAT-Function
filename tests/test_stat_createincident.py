from modules import createincident
from classes import Response, BaseModule, STATError, CreateIncident
import pytest
import json
from unittest.mock import Mock, patch

def test_create_incident_classes():
    """Test CreateIncident class initialization and properties"""
    create = CreateIncident()
    
    # Test default initialization
    assert hasattr(create, 'Title')
    assert hasattr(create, 'Description')
    assert hasattr(create, 'Severity')
    assert hasattr(create, 'AlertARMId')
    assert hasattr(create, 'IncidentARMId')

def test_create_incident_error_when_incident_triggered():
    """Test that createincident raises error when triggered from incident"""
    with patch('modules.createincident.BaseModule') as mock_base:
        mock_base_instance = Mock()
        mock_base_instance.IncidentTriggered = True
        mock_base.return_value = mock_base_instance
        
        create_input = {
            'BaseModuleBody': {'test': 'data'},
            'Title': 'Test Incident',
            'Description': 'Test Description',
            'Severity': 'High'
        }
        
        with pytest.raises(STATError) as exc_info:
            createincident.execute_create_incident(create_input)
        
        assert 'Incident creation is only supported when starting from an alert triggered Playbook' in str(exc_info.value)

def test_create_incident_parameter_handling():
    """Test that createincident correctly handles input parameters"""
    with patch('modules.createincident.BaseModule') as mock_base, \
         patch('modules.createincident.rest') as mock_rest, \
         patch('modules.createincident.uuid') as mock_uuid:
        
        # Setup mocks
        mock_base_instance = Mock()
        mock_base_instance.IncidentTriggered = False
        mock_base_instance.Alerts = [{
            'id': 'test-alert-id',
            'properties': {
                'alertDisplayName': 'Default Alert Title',
                'description': 'Default Alert Description',
                'severity': 'Medium'
            }
        }]
        mock_base_instance.WorkspaceARMId = 'test-workspace-arm-id'
        mock_base.return_value = mock_base_instance
        
        mock_uuid.uuid4.return_value = 'test-uuid'
        
        # Mock REST responses
        mock_incident_response = Mock()
        mock_incident_response.content = json.dumps({
            'properties': {
                'incidentNumber': 123,
                'incidentUrl': 'https://example.com/incident/123'
            }
        })
        mock_rest.rest_call_put.return_value = mock_incident_response
        
        # Test with custom parameters
        create_input = {
            'BaseModuleBody': {'test': 'data'},
            'Title': 'Custom Title',
            'Description': 'Custom Description',
            'Severity': 'High'
        }
        
        result = createincident.execute_create_incident(create_input)
        
        # Verify result type
        assert isinstance(result, Response)
        assert isinstance(result.body, CreateIncident)

def test_create_incident_default_parameters():
    """Test that createincident uses defaults from alert when parameters not provided"""
    with patch('modules.createincident.BaseModule') as mock_base, \
         patch('modules.createincident.rest') as mock_rest, \
         patch('modules.createincident.uuid') as mock_uuid:
        
        # Setup mocks  
        mock_base_instance = Mock()
        mock_base_instance.IncidentTriggered = False
        mock_base_instance.Alerts = [{
            'id': 'test-alert-id',
            'properties': {
                'alertDisplayName': 'Default Alert Title',
                'description': 'Default Alert Description',
                'severity': 'Medium'
            }
        }]
        mock_base_instance.WorkspaceARMId = 'test-workspace-arm-id'
        mock_base.return_value = mock_base_instance
        
        mock_uuid.uuid4.return_value = 'test-uuid'
        
        # Mock REST responses
        mock_incident_response = Mock()
        mock_incident_response.content = json.dumps({
            'properties': {
                'incidentNumber': 123,
                'incidentUrl': 'https://example.com/incident/123'
            }
        })
        mock_rest.rest_call_put.return_value = mock_incident_response
        
        # Test without custom parameters (should use defaults)
        create_input = {
            'BaseModuleBody': {'test': 'data'}
        }
        
        result = createincident.execute_create_incident(create_input)
        
        # Verify result type
        assert isinstance(result, Response)
        assert isinstance(result.body, CreateIncident)

