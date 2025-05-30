"""
Test utilities for STAT Function testing.
Provides common helper functions and mock objects for testing.
"""

from unittest.mock import Mock
from classes import BaseModule

def create_mock_base_module(incident_available=True, incident_triggered=True, entities=None):
    """
    Create a mock BaseModule with common defaults for testing.
    
    Args:
        incident_available (bool): Whether incident is available
        incident_triggered (bool): Whether triggered from incident
        entities (dict): Dictionary of entities to include (accounts, ips, domains, etc.)
    
    Returns:
        Mock: Configured mock BaseModule instance
    """
    if entities is None:
        entities = {
            'accounts': [],
            'ips': [],
            'domains': [],
            'filehashes': [],
            'files': [],
            'hosts': [],
            'urls': [],
            'alerts': []
        }
    
    mock_base = Mock(spec=BaseModule)
    mock_base.IncidentAvailable = incident_available
    mock_base.IncidentTriggered = incident_triggered
    mock_base.IncidentARMId = '/subscriptions/test/resourceGroups/test/providers/Microsoft.OperationalInsights/workspaces/test/providers/Microsoft.SecurityInsights/incidents/test-incident'
    mock_base.WorkspaceARMId = '/subscriptions/test/resourceGroups/test/providers/Microsoft.OperationalInsights/workspaces/test'
    mock_base.TenantId = 'test-tenant-id'
    mock_base.TenantDisplayName = 'Test Tenant'
    mock_base.WorkspaceId = 'test-workspace-id'
    
    # Set entities
    mock_base.Accounts = entities.get('accounts', [])
    mock_base.AccountsCount = len(mock_base.Accounts)
    mock_base.IPs = entities.get('ips', [])
    mock_base.IPsCount = len(mock_base.IPs)
    mock_base.Domains = entities.get('domains', [])
    mock_base.DomainsCount = len(mock_base.Domains)
    mock_base.FileHashes = entities.get('filehashes', [])
    mock_base.FileHashesCount = len(mock_base.FileHashes)
    mock_base.Files = entities.get('files', [])
    mock_base.FilesCount = len(mock_base.Files)
    mock_base.Hosts = entities.get('hosts', [])
    mock_base.HostsCount = len(mock_base.Hosts)
    mock_base.URLs = entities.get('urls', [])
    mock_base.URLsCount = len(mock_base.URLs)
    mock_base.Alerts = entities.get('alerts', [])
    mock_base.OtherEntities = entities.get('other', [])
    mock_base.OtherEntitiesCount = len(mock_base.OtherEntities)
    
    # Mock KQL table methods
    mock_base.get_domain_kql_table.return_value = 'mock kql table for domains'
    mock_base.get_filehash_kql_table.return_value = 'mock kql table for filehashes'
    mock_base.get_account_kql_table.return_value = 'mock kql table for accounts'
    mock_base.get_url_kql_table.return_value = 'mock kql table for urls'
    mock_base.get_ip_kql_table.return_value = 'mock kql table for ips'
    
    # Mock list methods
    mock_base.get_domain_list.return_value = [d.get('Domain', '') for d in mock_base.Domains]
    mock_base.get_filehash_list.return_value = [f.get('FileHash', '') for f in mock_base.FileHashes]
    mock_base.get_ip_list.return_value = [i.get('Address', '') for i in mock_base.IPs]
    mock_base.get_url_list.return_value = [u.get('Url', '') for u in mock_base.URLs]
    mock_base.get_account_upn_list.return_value = [a.get('userPrincipalName', '') for a in mock_base.Accounts]
    
    return mock_base

def create_sample_entities():
    """
    Create sample entity data for testing.
    
    Returns:
        dict: Dictionary containing sample entities
    """
    return {
        'accounts': [
            {
                'userPrincipalName': 'test.user@example.com',
                'SamAccountName': 'testuser',
                'SID': 'S-1-5-21-123456789-987654321-111111111-1001',
                'id': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
                'displayName': 'Test User'
            }
        ],
        'ips': [
            {
                'Address': '192.168.1.100',
                'IPType': 2,  # private
                'GeoData': {'country': 'Unknown'},
                'RawEntity': {}
            },
            {
                'Address': '8.8.8.8',
                'IPType': 1,  # global
                'GeoData': {'country': 'US'},
                'RawEntity': {}
            }
        ],
        'domains': [
            {'Domain': 'example.com'},
            {'Domain': 'test.org'}
        ],
        'filehashes': [
            {
                'FileHash': 'abc123def456789',
                'Algorithm': 'SHA256'
            }
        ],
        'files': [
            {
                'Name': 'test.exe',
                'Directory': 'C:\\temp\\'
            }
        ],
        'hosts': [
            {
                'HostName': 'TEST-COMPUTER',
                'DnsDomain': 'example.com',
                'MDEDeviceId': 'device-123'
            }
        ],
        'urls': [
            {'Url': 'https://example.com/test'},
            {'Url': 'http://malicious.bad/path'}
        ],
        'alerts': [
            {
                'id': '/subscriptions/test/resourceGroups/test/providers/Microsoft.OperationalInsights/workspaces/test/providers/Microsoft.SecurityInsights/alerts/test-alert',
                'properties': {
                    'alertDisplayName': 'Test Security Alert',
                    'description': 'This is a test security alert',
                    'severity': 'High',
                    'status': 'New'
                }
            }
        ]
    }

def create_mock_rest_response(status_code=200, content='{"result": "success"}'):
    """
    Create a mock REST response object.
    
    Args:
        status_code (int): HTTP status code
        content (str): Response content
        
    Returns:
        Mock: Configured mock response object
    """
    mock_response = Mock()
    mock_response.status_code = status_code
    mock_response.content = content
    return mock_response

def assert_response_structure(response, expected_body_type):
    """
    Assert that a response has the expected structure.
    
    Args:
        response: Response object to check
        expected_body_type: Expected type of response.body
    """
    from classes import Response
    
    assert isinstance(response, Response), f"Expected Response, got {type(response)}"
    assert response.statuscode == 200, f"Expected status code 200, got {response.statuscode}"
    assert isinstance(response.body, expected_body_type), f"Expected body type {expected_body_type}, got {type(response.body)}"

def create_test_input(module_name, base_module_body=None, **kwargs):
    """
    Create standard test input for module functions.
    
    Args:
        module_name (str): Name of the module being tested
        base_module_body (dict): Base module body data
        **kwargs: Additional parameters for the input
        
    Returns:
        dict: Test input dictionary
    """
    if base_module_body is None:
        base_module_body = {'test': 'data'}
    
    base_input = {
        'BaseModuleBody': base_module_body,
        'AddIncidentComments': False,
        'AddIncidentTask': False
    }
    
    # Add module-specific defaults
    if module_name.lower() == 'ti':
        base_input.update({
            'CheckDomains': True,
            'CheckFileHashes': True,
            'CheckIPs': True,
            'CheckURLs': True
        })
    elif module_name.lower() == 'watchlist':
        base_input.update({
            'WatchlistName': 'TestWatchlist',
            'WatchlistKey': 'SearchKey',
            'WatchlistKeyDataType': 'UPN'
        })
    elif module_name.lower() == 'kql':
        base_input.update({
            'KQLQuery': 'TestTable | take 5',
            'RunQueryAgainst': 'Sentinel',
            'QueryDescription': 'Test Query',
            'LookbackInDays': 7
        })
    
    # Override with any provided kwargs
    base_input.update(kwargs)
    
    return base_input