from classes import *
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
    
    # Add a global IP
    base.add_ip_entity('4.172.0.0', {'country': 'CA'}, {'raw': 'data'}, 1)
    
    assert len(base.IPs) == 1
    assert base.IPs[0]['Address'] == '4.172.0.0'
    assert base.IPs[0]['IPType'] == 1
    assert base.IPs[0]['GeoData']['country'] == 'CA'
    
    # Add a private IP
    base.add_ip_entity('192.168.1.1', {}, {'raw': 'data'}, 2)
    
    assert len(base.IPs) == 2
    assert base.IPs[1]['Address'] == '192.168.1.1'
    assert base.IPs[1]['IPType'] == 2
    
    # Add an IP with default type (unknown)
    base.add_ip_entity('10.0.0.1', {}, {'raw': 'data'})
    
    assert len(base.IPs) == 3
    assert base.IPs[2]['IPType'] == 9  # default unknown type

def test_base_module_get_ip_list():
    """Test BaseModule get_ip_list method"""
    base = BaseModule()
    base.add_ip_entity('4.172.0.0', {'country': 'CA'}, {'raw': 'data'}, 1)
    base.add_ip_entity('192.168.1.1', {}, {'raw': 'data'}, 2)
    base.add_ip_entity('10.0.0.1', {}, {'raw': 'data'})

    ip_list = base.get_ip_list()
    assert len(ip_list) == 3
    assert ip_list[0] == '4.172.0.0'

def test_base_module_get_ip_kql_table():
    """Test BaseModule get_ip_kql_table method"""
    base = BaseModule()
    base.add_ip_entity('4.172.0.0', {'country': 'CA'}, {'raw': 'data'}, 1)
    base.add_ip_entity('192.168.1.1', {}, {'raw': 'data'}, 2)
    base.add_ip_entity('10.0.0.1', {}, {'raw': 'data'})
    kql = base.get_ip_kql_table()
    
    assert '4.172.0.0' in kql
    assert 'let ipEntities = print t = todynamic(url_decode(' in kql
    assert 'IPAddress=tostring(t.Address)' in kql

def test_base_module_get_host_mdeid_list():
    """Test BaseModule get_host_mdeid_list method"""
    base = BaseModule()
    base.add_host_entity('host1.contoso.com', 'host1', 'contoso.com', 'mdedeviceid1', {'raw': 'data'})
    base.add_host_entity('host2.contoso.com', 'host2', 'contoso.com', 'mdedeviceid2', {'raw': 'data'})
    
    host_list = base.get_host_mdeid_list()
    assert len(host_list) == 2
    assert host_list[0] == 'mdedeviceid1'

def test_base_module_get_host_kql_table():
    """Test BaseModule get_host_kql_table method"""
    base = BaseModule()
    base.add_host_entity('host1.contoso.com', 'host1', 'contoso.com', 'mdedeviceid1', {'raw': 'data'})
    base.add_host_entity('host2.contoso.com', 'host2', 'contoso.com', 'mdedeviceid2', {'raw': 'data'})
    
    kql = base.get_host_kql_table()
    
    assert 'host1.contoso.com' in kql
    assert 'host2.contoso.com' in kql
    assert 'let hostEntities = print t = todynamic(url_decode(' in kql
    assert 'FQDN=tostring(t.FQDN), Hostname=tostring(t.Hostname);' in kql

def test_base_module_get_filehash_list():
    """Test BaseModule get_filehash_list method"""
    base = BaseModule()
    base.FileHashes = [
        {'FileHash': 'abc123', 'Algorithm': 'SHA256'},
        {'FileHash': 'def456', 'Algorithm': 'MD5'}
    ]
    
    hash_list = base.get_filehash_list()
    assert len(hash_list) == 2
    assert hash_list[0] == 'abc123'

def test_base_module_get_filehash_kql_table():
    """Test BaseModule get_filehash_kql_table method"""
    base = BaseModule()
    base.FileHashes = [
        {'FileHash': 'abc123', 'Algorithm': 'SHA256'},
        {'FileHash': 'def456', 'Algorithm': 'MD5'}
    ]
    
    kql = base.get_filehash_kql_table()
    
    assert 'abc123' in kql
    assert 'def456' in kql
    assert 'let hashEntities = print t = todynamic(url_decode(' in kql
    assert 'FileHash=tostring(t.FileHash)' in kql
    assert 'Algorithm=tostring(t.Algorithm)' in kql

def test_base_module_get_domain_list():
    """Test BaseModule get_domain_list method"""
    base = BaseModule()
    base.Domains = [
        {'Domain': 'contoso.com'},
        {'Domain': 'fabrikam.com'},
    ]
    
    domain_list = base.get_domain_list()
    assert len(domain_list) == 2
    assert domain_list[0] == 'contoso.com'

def test_base_module_get_domain_kql_table():
    """Test BaseModule get_domain_kql_table method"""
    base = BaseModule()
    base.Domains = [
        {'Domain': 'contoso.com'},
        {'Domain': 'fabrikam.com'},
    ]
    
    kql = base.get_domain_kql_table()
    
    assert 'contoso.com' in kql
    assert 'fabrikam.com' in kql
    assert 'let domainEntities = print t = todynamic(url_decode(' in kql
    assert 'Domain=tostring(t.Domain)' in kql

def test_base_module_get_account_kql_table():
    """Test BaseModule get_account_kql_table method"""
    base = BaseModule()
    base.Accounts = [
        {
            'userPrincipalName': 'user1@contoso.com',
            'onPremisesSamAccountName': 'user1',
            'onPremisesSecurityIdentifier': 'S-1-5-21-123',
            'id': 'abc-123',
            'manager': {
                'userPrincipalName': 'manager@contoso.com'
            }
        }
    ]

    kql = base.get_account_kql_table()
    print(kql)
    
    assert 'user1%40contoso.com' in kql
    assert 'S-1-5-21-123' in kql
    assert 'manager%40contoso.com' in kql
    assert 'let accountEntities = print t = todynamic(url_decode(' in kql
    assert 'UserPrincipalName=tostring(t.userPrincipalName)' in kql
    assert 'SamAccountName=tostring(t.SamAccountName)' in kql
    assert 'ObjectSID=tostring(t.SID)' in kql

def test_base_module_get_url_list():
    """Test BaseModule get_url_list method"""
    base = BaseModule()
    base.URLs = [
        {'Url': 'https://contoso.com'},
        {'Url': 'https://fabrikam.com'},
    ]
    
    url_list = base.get_url_list()
    assert len(url_list) == 2
    assert url_list[0] == 'https://contoso.com'

def test_base_module_get_url_kql_table():
    """Test BaseModule get_url_kql_table method"""
    base = BaseModule()
    base.URLs = [
        {'Url': 'https://contoso.com'},
        {'Url': 'https://fabrikam.com'},
    ]
    
    kql = base.get_url_kql_table()
    
    assert 'https%3A//contoso.com' in kql
    assert 'https%3A//fabrikam.com' in kql
    assert 'let urlEntities = print t = todynamic(url_decode(' in kql
    assert 'Url=tostring(t.Url)' in kql

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
    assert result is True

def test_user_exposure_module():
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
    
    nodes_without_paths = user_exp.nodes_without_paths()
    
    # Should return only user2 since user1 has a path
    assert len(nodes_without_paths) == 1
    assert nodes_without_paths[0]['UserNodeId'] == 'user2'

def test_device_exposure_module():
    """Test DeviceExposureModule class"""
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

    nodes_without_paths = device_exp.nodes_without_paths()
    
    # Should return comp2
    assert len(nodes_without_paths) == 1
    assert nodes_without_paths[0]['ComputerNodeId'] == 'comp2'

def test_response_initialization():
    """Test Response class initialization"""
    body = {'key': 'value'}
    response = Response(body, statuscode=200, contenttype='application/json')
    
    assert response.body == body
    assert response.statuscode == 200
    assert response.contenttype == 'application/json'

def test_kql_module_initialization():
    """Test KQLModule class initialization"""
    kql_module = KQLModule()
    
    assert kql_module.ModuleName == 'KQLModule'
    assert kql_module.DetailedResults == []
    assert kql_module.ResultsCount == 0
    assert kql_module.ResultsFound is False

def test_watchlist_module_initialization():
    """Test WatchlistModule class initialization"""
    watchlist_module = WatchlistModule()
    
    assert watchlist_module.ModuleName == 'WatchlistModule'
    assert watchlist_module.DetailedResults == []
    assert watchlist_module.EntitiesAnalyzedCount == 0
    assert watchlist_module.EntitiesOnWatchlist is False
    assert watchlist_module.EntitiesOnWatchlistCount == 0
    assert watchlist_module.WatchlistName == ''

def test_ti_module_initialization():
    """Test TIModule class initialization"""
    ti_module = TIModule()
    
    assert ti_module.ModuleName == 'TIModule'
    assert ti_module.AnyTIFound is False
    assert ti_module.DetailedResults == []
    assert ti_module.DomainEntitiesCount == 0
    assert ti_module.DomainEntitiesWithTI == 0
    assert ti_module.DomainTIFound is False
    assert ti_module.FileHashEntitiesCount == 0
    assert ti_module.FileHashEntitiesWithTI == 0
    assert ti_module.FileHashTIFound is False
    assert ti_module.IPEntitiesCount == 0
    assert ti_module.IPEntitiesWithTI == 0
    assert ti_module.IPTIFound is False
    assert ti_module.TotalTIMatchCount == 0
    assert ti_module.URLEntitiesCount == 0
    assert ti_module.URLEntitiesWithTI == 0
    assert ti_module.URLTIFound is False

def test_related_alerts_module_initialization():
    """Test RelatedAlertsModule class initialization"""
    related_alerts_module = RelatedAlertsModule()
    
    assert related_alerts_module.ModuleName == 'RelatedAlerts'
    assert related_alerts_module.AllTactics == []
    assert related_alerts_module.AllTacticsCount == 0
    assert related_alerts_module.DetailedResults == []
    assert related_alerts_module.FusionIncident is False
    assert related_alerts_module.HighestSeverityAlert == ''
    assert related_alerts_module.RelatedAccountAlertsCount == 0
    assert related_alerts_module.RelatedAccountAlertsFound is False
    assert related_alerts_module.RelatedAlertsCount == 0
    assert related_alerts_module.RelatedAlertsFound is False
    assert related_alerts_module.RelatedHostAlertsCount == 0
    assert related_alerts_module.RelatedHostAlertsFound is False
    assert related_alerts_module.RelatedIPAlertsCount == 0
    assert related_alerts_module.RelatedIPAlertsFound is False

def test_ueba_module_initialization():
    """Test UEBAModule class initialization"""
    ueba_module = UEBAModule()
    
    assert ueba_module.ModuleName == 'UEBAModule'
    assert ueba_module.AllEntityEventCount == 0
    assert ueba_module.AllEntityInvestigationPriorityAverage == 0.0
    assert ueba_module.AllEntityInvestigationPriorityMax == 0
    assert ueba_module.AllEntityInvestigationPrioritySum == 0
    assert ueba_module.AnomaliesFound is False
    assert ueba_module.AnomalyCount == 0
    assert ueba_module.AnomalyTactics == []
    assert ueba_module.AnomalyTacticsCount == 0
    assert ueba_module.DetailedResults == []
    assert ueba_module.InvestigationPrioritiesFound is False
    assert ueba_module.ThreatIntelFound is False
    assert ueba_module.ThreatIntelMatchCount == 0

def test_scoring_module_initialization():
    """Test ScoringModule class initialization"""
    scoring_module = ScoringModule()
    
    assert scoring_module.ModuleName == 'ScoringModule'
    assert scoring_module.DetailedResults == []
    assert scoring_module.TotalScore == 0     

def test_aad_module_initialization():
    """Test AADModule class initialization"""
    aad_module = AADModule()
    
    assert aad_module.ModuleName == 'AADRisksModule'
    assert aad_module.AnalyzedEntities == 0
    assert aad_module.FailedMFATotalCount == 0
    assert aad_module.HighestRiskLevel == ''
    assert aad_module.MFAFraudTotalCount == 0
    assert aad_module.SuspiciousActivityReportTotalCount == 0
    assert aad_module.DetailedResults == []
    assert aad_module.RiskDetectionTotalCount == 0

def test_file_module_initialization():
    """Test FileModule class initialization"""
    file_module = FileModule()
    
    assert file_module.ModuleName == 'FileModule'
    assert file_module.AnalyzedEntities == 0
    assert file_module.DeviceUniqueDeviceTotalCount == 0
    assert file_module.DeviceUniqueFileNameTotalCount == 0
    assert file_module.DeviceFileActionTotalCount == 0
    assert file_module.EntitiesAttachmentCount == 0
    assert file_module.HashesLinkedToThreatCount == 0
    assert file_module.HashesNotMicrosoftSignedCount == 0
    assert file_module.HashesThreatList == []
    assert file_module.MaximumGlobalPrevalence == 0
    assert file_module.MinimumGlobalPrevalence == 0
    assert file_module.DetailedResults == []

def test_run_playbook_initialization():
    """Test RunPlaybook class initialization"""
    run_playbook = RunPlaybook()
    
    assert run_playbook.LogicAppArmId == ''
    assert run_playbook.TenantId == ''
    assert run_playbook.PlaybookName == ''
    assert run_playbook.IncidentArmId == ''
    assert run_playbook.ModuleName == 'RunPlaybook'

def test_exchange_module_initialization():
    """Test ExchangeModule class initialization"""
    exchange_module = ExchangeModule()
    
    assert exchange_module.AllUsersInOffice is True
    assert exchange_module.AllUsersOutOfOffice is False
    assert exchange_module.Rules == []
    assert exchange_module.AuditEvents == []
    assert exchange_module.OOF == []
    assert exchange_module.UsersInOffice == 0
    assert exchange_module.UsersOutOfOffice == 0
    assert exchange_module.PrivilegedUsersWithMailbox == 0
    assert exchange_module.UsersUnknown == 0
    assert exchange_module.RulesDelete == 0
    assert exchange_module.RulesMove == 0
    assert exchange_module.RulesForward == 0
    assert exchange_module.DelegationsFound == 0
    assert exchange_module.ModuleName == 'ExchangeModule'
        
def test_mde_module_initialization():
    """Test MDEModule class initialization"""
    mde_module = MDEModule()
    
    assert mde_module.AnalyzedEntities == 0
    assert mde_module.IPsHighestExposureLevel == ''
    assert mde_module.IPsHighestRiskScore == ''
    assert mde_module.UsersHighestExposureLevel == ''
    assert mde_module.UsersHighestRiskScore == ''
    assert mde_module.HostsHighestExposureLevel == ''
    assert mde_module.HostsHighestRiskScore == ''
    assert mde_module.ModuleName == 'MDEModule'
    assert mde_module.DetailedResults == {}

def test_device_exposure_module_initialization():
    """Test DeviceExposureModule class initialization"""
    device_exp_module = DeviceExposureModule()
    
    assert device_exp_module.AnalyzedEntities == 0
    assert device_exp_module.ModuleName == 'DeviceExposureModule'
    assert device_exp_module.Nodes == []
    assert device_exp_module.Paths == []

def test_user_exposure_module_initialization():
    """Test UserExposureModule class initialization"""
    user_exp_module = UserExposureModule()
    
    assert user_exp_module.AnalyzedEntities == 0
    assert user_exp_module.ModuleName == 'UserExposureModule'
    assert user_exp_module.Nodes == []
    assert user_exp_module.Paths == []

def test_create_incident_initialization():
    """Test CreateIncident class initialization"""
    create_incident = CreateIncident()
    
    assert create_incident.IncidentARMId == ''
    assert create_incident.AlertARMId == ''
    assert create_incident.Title == ''
    assert create_incident.Description == ''
    assert create_incident.Severity == ''
    assert create_incident.IncidentNumber == 0
    assert create_incident.IncidentUrl == ''
    assert create_incident.ModuleName == 'CreateIncident'

def test_debug_module_initialization():
    """Test DebugModule class initialization"""
    debug_module = DebugModule({'Test': 'Debug', 'Params': {'param1': 'value1'}})
    
    assert debug_module.ModuleName == 'DebugModule'
    assert debug_module.STATVersion is not None  # Assuming data.get_current_version() returns a version
    assert debug_module.Test == 'Debug'
    assert debug_module.Params == {'param1': 'value1'}
