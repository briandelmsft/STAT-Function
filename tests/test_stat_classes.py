from classes import BaseModule, UserExposureModule, DeviceExposureModule
import pytest

def test_base_module_initialization():
    """Test BaseModule class initialization"""
    base = BaseModule()
    
    # Test that all required attributes are initialized
    assert hasattr(base, 'Accounts')
    assert hasattr(base, 'AccountsCount')
    assert hasattr(base, 'IPs')
    assert hasattr(base, 'IPsCount')
    assert hasattr(base, 'Domains')
    assert hasattr(base, 'DomainsCount')
    assert hasattr(base, 'FileHashes')
    assert hasattr(base, 'FileHashesCount')
    assert hasattr(base, 'Files')
    assert hasattr(base, 'FilesCount')
    assert hasattr(base, 'Hosts')
    assert hasattr(base, 'HostsCount')
    assert hasattr(base, 'URLs')
    assert hasattr(base, 'URLsCount')
    assert hasattr(base, 'OtherEntities')
    assert hasattr(base, 'OtherEntitiesCount')
    assert hasattr(base, 'ModuleName')
    
    # Test default values
    assert base.ModuleName == 'BaseModule'

def test_base_module_add_ip_entity():
    """Test BaseModule add_ip_entity method"""
    base = BaseModule()
    base.IPs = []
    
    # Add a global IP
    base.add_ip_entity('8.8.8.8', {'country': 'US'}, {'raw': 'data'}, 1)
    
    assert len(base.IPs) == 1
    assert base.IPs[0]['Address'] == '8.8.8.8'
    assert base.IPs[0]['IPType'] == 1
    assert base.IPs[0]['GeoData']['country'] == 'US'
    
    # Add a private IP
    base.add_ip_entity('192.168.1.1', {}, {'raw': 'data'}, 2)
    
    assert len(base.IPs) == 2
    assert base.IPs[1]['Address'] == '192.168.1.1'
    assert base.IPs[1]['IPType'] == 2
    
    # Add an IP with default type (unknown)
    base.add_ip_entity('10.0.0.1', {}, {'raw': 'data'})
    
    assert len(base.IPs) == 3
    assert base.IPs[2]['IPType'] == 9  # default unknown type

def test_base_module_get_filehash_kql_table():
    """Test BaseModule get_filehash_kql_table method"""
    base = BaseModule()
    base.FileHashes = [
        {'FileHash': 'abc123', 'Algorithm': 'SHA256'},
        {'FileHash': 'def456', 'Algorithm': 'MD5'}
    ]
    
    kql = base.get_filehash_kql_table()
    
    assert 'let hashEntities = print t = todynamic(url_decode(' in kql
    assert 'FileHash=tostring(t.FileHash)' in kql
    assert 'Algorithm=tostring(t.Algorithm)' in kql

def test_base_module_get_domain_kql_table():
    """Test BaseModule get_domain_kql_table method"""
    base = BaseModule()
    base.Domains = [
        {'Domain': 'example.com'},
        {'Domain': 'test.org'}
    ]
    
    kql = base.get_domain_kql_table()
    
    assert 'let domainEntities = print t = todynamic(url_decode(' in kql
    assert 'Domain=tostring(t.Domain)' in kql

def test_base_module_get_account_kql_table():
    """Test BaseModule get_account_kql_table method"""
    base = BaseModule()
    base.Accounts = [
        {
            'userPrincipalName': 'user1@example.com',
            'SamAccountName': 'user1',
            'SID': 'S-1-5-21-123',
            'id': 'abc-123',
            'ManagerUPN': 'manager@example.com'
        }
    ]
    
    kql = base.get_account_kql_table()
    
    assert 'let accountEntities = print t = todynamic(url_decode(' in kql
    assert 'UserPrincipalName=tostring(t.userPrincipalName)' in kql
    assert 'SamAccountName=tostring(t.SamAccountName)' in kql
    assert 'ObjectSID=tostring(t.SID)' in kql

def test_base_module_check_global_and_local_ips():
    """Test BaseModule check_global_and_local_ips method"""
    base = BaseModule()
    base.IPs = [
        {'Address': '8.8.8.8', 'IPType': 1},  # global
        {'Address': '192.168.1.1', 'IPType': 2},  # private
        {'Address': '127.0.0.1', 'IPType': 9}  # unknown
    ]
    
    result = base.check_global_and_local_ips()
    
    # The method should return information about IP types present
    assert result is not None

def test_user_exposure_module():
    """Test UserExposureModule class"""
    user_exp = UserExposureModule()
    
    assert user_exp.ModuleName == 'UserExposureModule'
    assert user_exp.AnalyzedEntities == 0
    assert user_exp.Nodes == []
    assert user_exp.Paths == []

def test_user_exposure_module_load_from_input():
    """Test UserExposureModule load_from_input method"""
    user_exp = UserExposureModule()
    
    test_data = {
        'AnalyzedEntities': 5,
        'Nodes': [{'UserNodeId': 'user1'}, {'UserNodeId': 'user2'}],
        'Paths': [{'UserNodeId': 'user1', 'path': 'test'}]
    }
    
    user_exp.load_from_input(test_data)
    
    assert user_exp.AnalyzedEntities == 5
    assert len(user_exp.Nodes) == 2
    assert len(user_exp.Paths) == 1

def test_user_exposure_module_nodes_without_paths():
    """Test UserExposureModule nodes_without_paths method"""
    user_exp = UserExposureModule()
    
    user_exp.Nodes = [
        {'UserNodeId': 'user1'},
        {'UserNodeId': 'user2'},
        {'UserNodeId': 'user3'}
    ]
    user_exp.Paths = [
        {'UserNodeId': 'user1', 'path': 'test1'},
        {'UserNodeId': 'user2', 'path': 'test2'}
    ]
    
    nodes_without_paths = user_exp.nodes_without_paths()
    
    # Should return only user3 since user1 and user2 have paths
    assert len(nodes_without_paths) == 1
    assert nodes_without_paths[0]['UserNodeId'] == 'user3'

def test_device_exposure_module():
    """Test DeviceExposureModule class"""
    device_exp = DeviceExposureModule()
    
    assert device_exp.ModuleName == 'DeviceExposureModule'
    assert device_exp.AnalyzedEntities == 0
    assert device_exp.Nodes == []
    assert device_exp.Paths == []

def test_device_exposure_module_load_from_input():
    """Test DeviceExposureModule load_from_input method"""
    device_exp = DeviceExposureModule()
    
    test_data = {
        'AnalyzedEntities': 3,
        'Nodes': [{'ComputerNodeId': 'comp1'}, {'ComputerNodeId': 'comp2'}],
        'Paths': [{'ComputerNodeId': 'comp1', 'path': 'test'}]
    }
    
    device_exp.load_from_input(test_data)
    
    assert device_exp.AnalyzedEntities == 3
    assert len(device_exp.Nodes) == 2
    assert len(device_exp.Paths) == 1

def test_device_exposure_module_nodes_without_paths():
    """Test DeviceExposureModule nodes_without_paths method"""
    device_exp = DeviceExposureModule()
    
    device_exp.Nodes = [
        {'ComputerNodeId': 'comp1'},
        {'ComputerNodeId': 'comp2'},
        {'ComputerNodeId': 'comp3'}
    ]
    device_exp.Paths = [
        {'ComputerNodeId': 'comp1', 'path': 'test1'}
    ]
    
    nodes_without_paths = device_exp.nodes_without_paths()
    
    # Should return comp2 and comp3 since only comp1 has a path
    assert len(nodes_without_paths) == 2
    node_ids = [node['ComputerNodeId'] for node in nodes_without_paths]
    assert 'comp2' in node_ids
    assert 'comp3' in node_ids