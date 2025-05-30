from modules import ti
from classes import Response, BaseModule, TIModule, STATError
import pytest
from unittest.mock import Mock, patch

def test_ti_module_classes():
    """Test TIModule class initialization"""
    ti_mod = TIModule()
    
    # Test default initialization
    assert hasattr(ti_mod, 'DetailedResults')
    assert hasattr(ti_mod, 'AnyTIFound')
    assert hasattr(ti_mod, 'DomainTIFound')
    assert hasattr(ti_mod, 'FileHashTIFound')
    assert hasattr(ti_mod, 'IPTIFound')
    assert hasattr(ti_mod, 'URLTIFound')

def test_ti_all_checks_disabled_error():
    """Test that TI module raises error when all checks are disabled"""
    with patch('modules.ti.BaseModule') as mock_base:
        mock_base_instance = Mock()
        mock_base.return_value = mock_base_instance
        
        ti_input = {
            'BaseModuleBody': {'test': 'data'},
            'CheckDomains': False,
            'CheckFileHashes': False,
            'CheckIPs': False,
            'CheckURLs': False
        }
        
        with pytest.raises(STATError) as exc_info:
            ti.execute_ti_module(ti_input)
        
        assert 'all TI checks were disabled' in str(exc_info.value)

def test_ti_module_default_parameters():
    """Test TI module with default parameters (all checks enabled)"""
    with patch('modules.ti.BaseModule') as mock_base, \
         patch('modules.ti.rest') as mock_rest:
        
        # Setup mocks
        mock_base_instance = Mock()
        mock_base_instance.Domains = []
        mock_base_instance.FileHashes = []
        mock_base_instance.IPs = []
        mock_base_instance.URLs = []
        mock_base_instance.IncidentAvailable = False
        mock_base.return_value = mock_base_instance
        
        mock_rest.execute_la_query.return_value = []
        
        ti_input = {
            'BaseModuleBody': {'test': 'data'}
            # No explicit check parameters - should default to True
        }
        
        result = ti.execute_ti_module(ti_input)
        
        assert isinstance(result, Response)
        assert isinstance(result.body, TIModule)

def test_ti_module_partial_checks():
    """Test TI module with only some checks enabled"""
    with patch('modules.ti.BaseModule') as mock_base, \
         patch('modules.ti.rest') as mock_rest:
        
        # Setup mocks
        mock_base_instance = Mock()
        mock_base_instance.Domains = [{'Domain': 'test.com'}]
        mock_base_instance.FileHashes = []
        mock_base_instance.IPs = []
        mock_base_instance.URLs = []
        mock_base_instance.IncidentAvailable = False
        mock_base_instance.get_domain_kql_table.return_value = 'test kql'
        mock_base_instance.get_domain_list.return_value = ['test.com']
        mock_base.return_value = mock_base_instance
        
        mock_rest.execute_la_query.return_value = []
        
        ti_input = {
            'BaseModuleBody': {'test': 'data'},
            'CheckDomains': True,
            'CheckFileHashes': False,
            'CheckIPs': False,
            'CheckURLs': False
        }
        
        result = ti.execute_ti_module(ti_input)
        
        assert isinstance(result, Response)
        assert isinstance(result.body, TIModule)

def test_ti_module_with_results():
    """Test TI module when threat intelligence is found"""
    with patch('modules.ti.BaseModule') as mock_base, \
         patch('modules.ti.rest') as mock_rest, \
         patch('modules.ti.data') as mock_data:
        
        # Setup mocks
        mock_base_instance = Mock()
        mock_base_instance.Domains = [{'Domain': 'malicious.com'}]
        mock_base_instance.FileHashes = []
        mock_base_instance.IPs = []
        mock_base_instance.URLs = []
        mock_base_instance.IncidentAvailable = True
        mock_base_instance.get_domain_kql_table.return_value = 'test kql'
        mock_base_instance.get_domain_list.return_value = ['malicious.com']
        mock_base.return_value = mock_base_instance
        
        # Mock TI results found
        mock_ti_results = [
            {'TIType': 'Domain', 'TIData': 'malicious.com', 'ThreatType': 'Malware'}
        ]
        mock_rest.execute_la_query.return_value = mock_ti_results
        mock_rest.add_incident_comment.return_value = Mock()
        
        # Mock data utilities
        mock_data.replace_column_value_in_list.return_value = mock_ti_results
        mock_data.list_to_html_table.return_value = '<table>test</table>'
        
        ti_input = {
            'BaseModuleBody': {'test': 'data'},
            'CheckDomains': True,
            'CheckFileHashes': False,
            'CheckIPs': False,
            'CheckURLs': False,
            'AddIncidentComments': True
        }
        
        result = ti.execute_ti_module(ti_input)
        
        assert isinstance(result, Response)
        assert result.body.AnyTIFound == True
        assert result.body.DomainTIFound == True
        assert result.body.TotalTIMatchCount == 1
        
        # Verify comment was added
        mock_rest.add_incident_comment.assert_called_once()

def test_ti_module_comment_disabled():
    """Test TI module with incident comments disabled"""
    with patch('modules.ti.BaseModule') as mock_base, \
         patch('modules.ti.rest') as mock_rest:
        
        # Setup mocks
        mock_base_instance = Mock()
        mock_base_instance.Domains = [{'Domain': 'test.com'}]
        mock_base_instance.FileHashes = []
        mock_base_instance.IPs = []
        mock_base_instance.URLs = []
        mock_base_instance.IncidentAvailable = True
        mock_base_instance.get_domain_kql_table.return_value = 'test kql'
        mock_base_instance.get_domain_list.return_value = ['test.com']
        mock_base.return_value = mock_base_instance
        
        mock_rest.execute_la_query.return_value = [
            {'TIType': 'Domain', 'TIData': 'test.com'}
        ]
        
        ti_input = {
            'BaseModuleBody': {'test': 'data'},
            'CheckDomains': True,
            'CheckFileHashes': False,
            'CheckIPs': False,
            'CheckURLs': False,
            'AddIncidentComments': False
        }
        
        result = ti.execute_ti_module(ti_input)
        
        # Should not add incident comment
        mock_rest.add_incident_comment.assert_not_called()

def test_ti_module_no_entities():
    """Test TI module when no entities of enabled types are present"""
    with patch('modules.ti.BaseModule') as mock_base:
        
        # Setup mocks
        mock_base_instance = Mock()
        mock_base_instance.Domains = []  # No domains
        mock_base_instance.FileHashes = []
        mock_base_instance.IPs = []
        mock_base_instance.URLs = []
        mock_base_instance.IncidentAvailable = False
        mock_base.return_value = mock_base_instance
        
        ti_input = {
            'BaseModuleBody': {'test': 'data'},
            'CheckDomains': True,
            'CheckFileHashes': False,
            'CheckIPs': False,
            'CheckURLs': False
        }
        
        result = ti.execute_ti_module(ti_input)
        
        assert isinstance(result, Response)
        assert result.body.AnyTIFound == False
        assert result.body.TotalTIMatchCount == 0