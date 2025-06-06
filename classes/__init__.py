import urllib.parse
import json
from shared import data

class Response:
    """HTTP response object for STAT Function modules.
    
    This class encapsulates the response data, status code, and content type
    for HTTP responses returned by STAT Function modules.  All modules should return this class.
    
    Args:
        body: The response body content, typically a dictionary or object.
        statuscode (int, optional): HTTP status code. Defaults to 200.
        contenttype (str, optional): Content type header. Defaults to 'application/json'.
    
    Attributes:
        body: The response body content.
        statuscode (int): HTTP status code.
        contenttype (str): Content type header.
    """
    
    def __init__(self, body, statuscode=200, contenttype='application/json'):
        self.body = body
        self.statuscode = statuscode
        self.contenttype = contenttype

class STATError(Exception):
    """Exception class for STAT Function errors.
    
    This exception is raised when a handled error occurs in STAT Function processing.
    It includes additional context such as source error details and HTTP status codes.
    
    Args:
        error (str): The error message describing what went wrong.
        source_error (dict, optional): Additional error details from the source. Defaults to {}.
        status_code (int, optional): HTTP status code associated with the error. Defaults to 400.
    
    Attributes:
        error (str): The error message.
        source_error (dict): Additional error details from the source.
        status_code (int): HTTP status code associated with the error.
    """

    def __init__(self, error:str, source_error:dict={}, status_code:int=400):
        self.error = error
        self.source_error = source_error
        self.status_code = status_code

class STATNotFound(STATError):
    """STAT exception raised when an API call returns a 404 Not Found error.
    
    This exception is a specialized version of STATError for cases where
    a resource or endpoint could not be found.
    """
    pass

class STATTooManyRequests(STATError):
    """STAT exception raised when an API call returns a 429 Too Many Requests error.
    
    This exception includes retry timing information to help with rate limiting handling.
    
    Args:
        error (str): The error message describing what went wrong.
        source_error (dict, optional): Additional error details from the source. Defaults to {}.
        status_code (int, optional): HTTP status code associated with the error. Defaults to 400.
        retry_after (int, optional): Number of seconds to wait before retrying. Defaults to 10.
    
    Attributes:
        error (str): The error message.
        source_error (dict): Additional error details from the source.
        status_code (int): HTTP status code associated with the error.
        retry_after (str): String representation of seconds to wait before retrying.
    """
    def __init__(self, error:str, source_error:dict={}, status_code:int=400, retry_after:int=10):
        self.error = error
        self.source_error = source_error
        self.status_code = status_code
        self.retry_after = str(retry_after)

class BaseModule:
    '''A base module object'''
    
    def __init__(self):
        self.Accounts = []
        self.AccountsCount = 0
        self.AccountsOnPrem = []
        self.Alerts = []
        self.Domains = []
        self.DomainsCount = 0
        self.EntitiesCount = 0
        self.FileHashes = []
        self.FileHashesCount = 0
        self.Files = []
        self.FilesCount = 0
        self.Hosts = []
        self.HostsCount = 0
        self.IPs = []
        self.IPsCount = 0
        self.IncidentARMId = ""
        self.IncidentTriggered = False
        self.IncidentAvailable = False
        self.ModuleVersions = {}
        self.MultiTenantConfig = {}
        self.OtherEntities = []
        self.OtherEntitiesCount = 0
        self.RelatedAnalyticRuleIds = []
        self.SentinelRGARMId = ""
        self.TenantDisplayName = ""
        self.TenantId = ""
        self.URLs = []
        self.URLsCount = 0
        self.WorkspaceARMId = ""
        self.WorkspaceId = ""
        self.CurrentVersion = ""
        self.ModuleName = 'BaseModule'

    def load_incident_trigger(self, req_body):
        
        self.IncidentARMId = req_body['object']['id']
        self.IncidentTriggered = True
        self.IncidentAvailable = True
        self.SentinelRGARMId = "/subscriptions/" + req_body['workspaceInfo']['SubscriptionId'] + "/resourceGroups/" + req_body['workspaceInfo']['ResourceGroupName']
        self.WorkspaceARMId = self.SentinelRGARMId + "/providers/Microsoft.OperationalInsights/workspaces/" + req_body['workspaceInfo']['WorkspaceName']
        self.WorkspaceId = req_body['workspaceId']
        self.RelatedAnalyticRuleIds = req_body['object']['properties'].get('relatedAnalyticRuleIds', [])
        self.Alerts = req_body['object']['properties'].get('alerts', [])

    def load_alert_trigger(self, req_body):
        self.IncidentTriggered = False
        self.SentinelRGARMId = "/subscriptions/" + req_body['WorkspaceSubscriptionId'] + "/resourceGroups/" + req_body['WorkspaceResourceGroup']
        self.WorkspaceId = req_body['WorkspaceId']

    def load_from_input(self, basebody):
        self.Accounts = basebody['Accounts']
        self.AccountsCount = basebody['AccountsCount']
        self.AccountsOnPrem = basebody.get('AccountsOnPrem', [])
        self.Alerts = basebody.get('Alerts', [])
        self.Domains = basebody['Domains']
        self.DomainsCount = basebody['DomainsCount']
        self.EntitiesCount = basebody['EntitiesCount']
        self.FileHashes = basebody['FileHashes']
        self.FileHashesCount = basebody['FileHashesCount']
        self.Files = basebody['Files']
        self.FilesCount = basebody['FilesCount']
        self.Hosts = basebody['Hosts']
        self.HostsCount = basebody['HostsCount']
        self.IPs = basebody['IPs']
        self.IPsCount = basebody['IPsCount']
        self.IncidentTriggered = basebody['IncidentTriggered']
        self.IncidentAvailable = basebody['IncidentAvailable']
        self.IncidentARMId = basebody['IncidentARMId']
        self.ModuleVersions = basebody['ModuleVersions']
        self.MultiTenantConfig = basebody.get('MultiTenantConfig', {})
        self.OtherEntities = basebody['OtherEntities']
        self.OtherEntitiesCount = basebody['OtherEntitiesCount']
        self.RelatedAnalyticRuleIds = basebody.get('RelatedAnalyticRuleIds', [])
        self.SentinelRGARMId = basebody['SentinelRGARMId']
        self.TenantDisplayName = basebody['TenantDisplayName']
        self.TenantId = basebody['TenantId']
        self.URLs = basebody['URLs']
        self.URLsCount = basebody['URLsCount']
        self.WorkspaceARMId = basebody['WorkspaceARMId']
        self.WorkspaceId = basebody['WorkspaceId']
        self.CurrentVersion = basebody.get('CurrentVersion')
        self.ModuleName = basebody.get('ModuleName')

    def add_ip_entity(self, address, geo_data, rawentity, ip_type:int=9):
        '''Adds an IP entity, types 1=global, 2=private, 3=link-local, 9=unknown'''
        self.IPs.append({'Address': address, 'IPType': ip_type, 'GeoData': geo_data, 'RawEntity': rawentity })

    def check_global_and_local_ips(self):
        '''Checks if any private or global IPs are in the IPs array for IP comment'''
        found = False
        for ip in self.IPs:
            if ip.get('IPType') != 3:
                found = True
                break
        return found

    def add_host_entity(self, fqdn, hostname, dnsdomain, mdedeviceid, rawentity, mde_enrichment:str='Unknown'):
        if mdedeviceid:
            self.Hosts.append({'DnsDomain': dnsdomain, 'FQDN': fqdn, 'Hostname': hostname, 'MdatpDeviceId': mdedeviceid, 'MDEEnrichment': mde_enrichment, 'RawEntity': rawentity })
        else:
            self.Hosts.append({'DnsDomain': dnsdomain, 'FQDN': fqdn, 'Hostname': hostname, 'MDEEnrichment': mde_enrichment, 'RawEntity': rawentity })

    def add_account_entity(self, data):
        self.Accounts.append(data)

    def add_onprem_account_entity(self, data):
        self.AccountsOnPrem.append(data)

    def get_ip_list(self):
        ip_list = []
        for ip in self.IPs:
            ip_list.append(ip['Address'])

        return ip_list
    
    def get_domain_list(self):
        domain_list = []
        for domain in self.Domains:
            domain_list.append(domain['Domain'])
        
        return domain_list
    
    def get_url_list(self):
        url_list = []
        for url in self.URLs:
            url_list.append(url['Url'])
        
        return url_list
    
    def get_filehash_list(self):
        hash_list = []
        for hash in self.FileHashes:
            hash_list.append(hash['FileHash'])
        
        return hash_list
    
    def get_ip_kql_table(self):

        ip_data = []

        for ip in self.IPs:
            ip_data.append({'Address': ip.get('Address'), 'Latitude': ip.get('GeoData').get('latitude'), 'Longitude': ip.get('GeoData').get('longitude'), \
                            'Country': ip.get('GeoData').get('country'), 'State': ip.get('GeoData').get('state')})

        encoded = urllib.parse.quote(json.dumps(ip_data))

        kql = f'''let ipEntities = print t = todynamic(url_decode('{encoded}'))
| mv-expand t
| project IPAddress=tostring(t.Address), Latitude=toreal(t.Latitude), Longitude=toreal(t.Longitude), Country=tostring(t.Country), State=tostring(t.State);
'''
        return kql
    
    def get_account_kql_table(self, include_unsynced:bool=False):

        account_data = []

        for account in self.Accounts:
            account_data.append({'userPrincipalName': account.get('userPrincipalName'), 'SamAccountName': account.get('onPremisesSamAccountName'), \
                                 'SID': account.get('onPremisesSecurityIdentifier'), 'id': account.get('id'), 'ManagerUPN': account.get('manager', {}).get('userPrincipalName')})
        if include_unsynced:
            for onprem_account in self.AccountsOnPrem:
                account_data.append({'userPrincipalName': onprem_account.get('userPrincipalName', 'NoUPNFound'), 'SamAccountName': onprem_account.get('onPremisesSamAccountName'), \
                                     'SID': onprem_account.get('onPremisesSecurityIdentifier'), 'id': onprem_account.get('id', 'NoIdFound'), 'ManagerUPN': 'NoManagerUpnFound'})

        encoded = urllib.parse.quote(json.dumps(account_data))

        kql = f'''let accountEntities = print t = todynamic(url_decode('{encoded}'))
| mv-expand t
| project UserPrincipalName=tostring(t.userPrincipalName), SamAccountName=tostring(t.SamAccountName), ObjectSID=tostring(t.SID), AADUserId=tostring(t.id), ManagerUPN=tostring(t.ManagerUPN);
'''
        return kql
    
    def get_host_kql_table(self):

        host_data = []

        for host in self.Hosts:
            host_data.append({'FQDN': host.get('FQDN'), 'Hostname': host.get('Hostname')})

        encoded = urllib.parse.quote(json.dumps(host_data))

        kql = f'''let hostEntities = print t = todynamic(url_decode('{encoded}'))
| mv-expand t
| project FQDN=tostring(t.FQDN), Hostname=tostring(t.Hostname);
'''
        return kql
    
    def get_url_kql_table(self):
        url_data = []

        for url in self.URLs:
            url_data.append({'Url': url.get('Url')})

        encoded = urllib.parse.quote(json.dumps(url_data))

        kql = f'''let urlEntities = print t = todynamic(url_decode('{encoded}'))
| mv-expand t
| project Url=tostring(t.Url);
'''
        return kql

    def get_filehash_kql_table(self):
        hash_data = []

        for hash in self.FileHashes:
            hash_data.append({'FileHash': hash.get('FileHash'), 'Algorithm': hash.get('Algorithm')})

        encoded = urllib.parse.quote(json.dumps(hash_data))

        kql = f'''let hashEntities = print t = todynamic(url_decode('{encoded}'))
| mv-expand t
| project FileHash=tostring(t.FileHash), Algorithm=tostring(t.Algorithm);
'''
        return kql

    def get_domain_kql_table(self):
        
        domain_data = []

        for domain in self.Domains:
            domain_data.append({'Domain': domain.get('Domain')})

        encoded = urllib.parse.quote(json.dumps(domain_data))

        kql = f'''let domainEntities = print t = todynamic(url_decode('{encoded}'))
| mv-expand t
| project Domain=tostring(t.Domain);
'''
        return kql
        
    def get_account_id_and_sid_list(self):
        account_list = []
        for account in self.Accounts:
            try:
                account_list.append(account['id'])
            except KeyError:
                raw_entity = account.get('RawEntity', {})
                sid = data.coalesce(raw_entity.get('properties',{}).get('sid'), raw_entity.get('sid'), raw_entity.get('Sid'))
                if sid:
                    account_list.append(sid)

        for onprem_account in self.AccountsOnPrem:
            try:
                account_list.append(onprem_account['onPremisesSecurityIdentifier'])
            except KeyError:
                pass
        
        return account_list

    def get_account_upn_list(self, include_unsynced:bool=False):
        '''Returns a list of all UPNs, including unsynced accounts accounts'''
        account_list = []
        for account in self.Accounts:
            try:
                account_list.append(account['userPrincipalName'])
            except KeyError:
                pass

        if include_unsynced:
            for onprem_account in self.AccountsOnPrem:
                try:
                    account_list.append(onprem_account['userPrincipalName'])
                except KeyError:
                    pass
        
        return account_list
    
    def get_account_sam_list(self):
        account_list = []
        for account in self.Accounts:
            try:
                account_list.append(account['onPremisesSamAccountName'])
            except:
                pass

        return account_list
    
    def get_host_mdeid_list(self):
        host_list = []
        for host in self.Hosts:
            if host.get('MdatpDeviceId'):
                host_list.append(host.get('MdatpDeviceId'))
        
        return host_list
    
    def get_alert_ids(self):
        alert_list = []
        for alert in self.Alerts:
            alert_id = alert.get('properties', {}).get('systemAlertId')
            if alert_id:
                alert_list.append(alert_id)
        
        return alert_list
    
    def get_alert_tactics(self):
        tactics_list = []
        for alert in self.Alerts:
            tactics_list = tactics_list + alert['properties']['tactics']

        return list(set(tactics_list))

class KQLModule:
    '''A KQL module object'''
    
    def __init__(self):
        self.DetailedResults = []
        self.ModuleName = 'KQLModule'
        self.ResultsCount = 0
        self.ResultsFound = False

    def load_from_input(self, body):
        self.DetailedResults = body['DetailedResults']
        self.ResultsCount = body['ResultsCount']
        self.ResultsFound = body['ResultsFound']

class WatchlistModule:
    '''A Watchlist module object'''
    
    def __init__(self):
        self.DetailedResults = []
        self.EntitiesAnalyzedCount = 0
        self.EntitiesOnWatchlist = False
        self.EntitiesOnWatchlistCount = 0
        self.WatchlistName = ""
        self.ModuleName = 'WatchlistModule'

    def load_from_input(self, body):
        self.DetailedResults = body['DetailedResults']
        self.EntitiesAnalyzedCount = body['EntitiesAnalyzedCount']
        self.EntitiesOnWatchlist = body['EntitiesOnWatchlist']
        self.EntitiesOnWatchlistCount = body['EntitiesOnWatchlistCount']
        self.WatchlistName = body['WatchlistName']

class TIModule:
    '''A Threat Intelligence module object'''

    def __init__(self):
        self.AnyTIFound = False
        self.DetailedResults = []
        self.DomainEntitiesCount = 0
        self.DomainEntitiesWithTI = 0
        self.DomainTIFound = False
        self.FileHashEntitiesCount = 0
        self.FileHashEntitiesWithTI = 0
        self.FileHashTIFound = False
        self.IPEntitiesCount = 0
        self.IPEntitiesWithTI = 0
        self.IPTIFound = False
        self.ModuleName = 'TIModule'
        self.TotalTIMatchCount = 0
        self.URLEntitiesCount = 0
        self.URLEntitiesWithTI = 0
        self.URLTIFound = False

    def load_from_input(self, body):
        self.AnyTIFound = body['AnyTIFound']
        self.DetailedResults = body['DetailedResults']
        self.DomainEntitiesCount = body['DomainEntitiesCount']
        self.DomainEntitiesWithTI = body['DomainEntitiesWithTI']
        self.DomainTIFound = body['DomainTIFound']
        self.FileHashEntitiesCount = body['FileHashEntitiesCount']
        self.FileHashEntitiesWithTI = body['FileHashEntitiesWithTI']
        self.FileHashTIFound = body['FileHashTIFound']
        self.IPEntitiesCount = body['IPEntitiesCount']
        self.IPEntitiesWithTI = body['IPEntitiesWithTI']
        self.IPTIFound = body['IPTIFound']
        self.TotalTIMatchCount = body['TotalTIMatchCount']
        self.URLEntitiesCount = body['URLEntitiesCount']
        self.URLEntitiesWithTI = body['URLEntitiesWithTI']
        self.URLTIFound = body['URLTIFound']       

class RelatedAlertsModule:
    '''A Related Alerts module object'''

    def __init__(self):
        self.AllTactics =  []
        self.AllTacticsCount = 0
        self.DetailedResults = []
        self.FusionIncident = False
        self.HighestSeverityAlert = ''
        self.ModuleName = 'RelatedAlerts'
        self.RelatedAccountAlertsCount = 0
        self.RelatedAccountAlertsFound = False
        self.RelatedAlertsCount = 0
        self.RelatedAlertsFound = False
        self.RelatedHostAlertsCount = 0
        self.RelatedHostAlertsFound = False
        self.RelatedIPAlertsCount = 0
        self.RelatedIPAlertsFound = False

    def load_from_input(self, body):
        self.AllTactics =  body['AllTactics']
        self.AllTacticsCount = body['AllTacticsCount']
        self.DetailedResults = body['DetailedResults']
        self.FusionIncident = body['FusionIncident']
        self.HighestSeverityAlert = body['HighestSeverityAlert']
        self.RelatedAccountAlertsCount = body['RelatedAccountAlertsCount']
        self.RelatedAccountAlertsFound = body['RelatedAccountAlertsFound']
        self.RelatedAlertsCount = body['RelatedAlertsCount']
        self.RelatedAlertsFound = body['RelatedAlertsFound']
        self.RelatedHostAlertsCount = body['RelatedHostAlertsCount']
        self.RelatedHostAlertsFound = body['RelatedHostAlertsFound']
        self.RelatedIPAlertsCount = body['RelatedIPAlertsCount']
        self.RelatedIPAlertsFound = body['RelatedIPAlertsFound']

class UEBAModule:
    '''A UEBA module object'''
    
    def __init__(self):
        self.AllEntityEventCount = 0
        self.AllEntityInvestigationPriorityAverage = float(0)
        self.AllEntityInvestigationPriorityMax = 0
        self.AllEntityInvestigationPrioritySum = 0
        self.AnomaliesFound = False
        self.AnomalyCount = 0
        self.AnomalyTactics = []
        self.AnomalyTacticsCount = 0
        self.DetailedResults = []
        self.InvestigationPrioritiesFound = False
        self.ModuleName = 'UEBAModule'
        self.ThreatIntelFound = False
        self.ThreatIntelMatchCount = 0

    def load_from_input(self, body):
        self.AllEntityEventCount = body['AllEntityEventCount']
        self.AllEntityInvestigationPriorityAverage = body['AllEntityInvestigationPriorityAverage']
        self.AllEntityInvestigationPriorityMax = body['AllEntityInvestigationPriorityMax']
        self.AllEntityInvestigationPrioritySum = body['AllEntityInvestigationPrioritySum']
        self.AnomaliesFound = body['AnomaliesFound']
        self.AnomalyCount = body['AnomalyCount']
        self.AnomalyTactics = body['AnomalyTactics']
        self.AnomalyTacticsCount = body['AnomalyTacticsCount']
        self.DetailedResults = body['DetailedResults']
        self.InvestigationPrioritiesFound = body['InvestigationPrioritiesFound']
        self.ThreatIntelFound = body['ThreatIntelFound']
        self.ThreatIntelMatchCount = body['ThreatIntelMatchCount']       

class ScoringModule:
    '''A Scoring Module object'''
    
    def __init__(self):
        self.DetailedResults = []
        self.TotalScore = 0
        self.ModuleName = 'ScoringModule'

    def append_score(self, score, label):
        '''Adds to the TotalScore and DetailedResults list'''
        self.TotalScore += score
        self.DetailedResults.append({'Score': score, 'ScoreSource': label})

class AADModule:
    '''An AAD Module object'''

    def __init__(self):
        self.AnalyzedEntities = 0
        self.FailedMFATotalCount = 0
        self.HighestRiskLevel = ''
        self.MFAFraudTotalCount = 0
        self.SuspiciousActivityReportTotalCount = 0
        self.ModuleName = 'AADRisksModule'
        self.DetailedResults = []
        self.RiskDetectionTotalCount = 0

    def load_from_input(self, body):
        self.AnalyzedEntities = body['AnalyzedEntities']
        self.FailedMFATotalCount = body['FailedMFATotalCount']
        self.HighestRiskLevel = body['HighestRiskLevel']
        self.MFAFraudTotalCount = body['MFAFraudTotalCount']
        self.SuspiciousActivityReportTotalCount = body['SuspiciousActivityReportTotalCount']
        self.DetailedResults = body['DetailedResults']
        self.RiskDetectionTotalCount = body.get('RiskDetectionTotalCount')

class FileModule:
    '''A File Module object'''
    
    def __init__(self):
        self.AnalyzedEntities = 0
        self.DeviceUniqueDeviceTotalCount = 0
        self.DeviceUniqueFileNameTotalCount = 0
        self.DeviceFileActionTotalCount = 0
        self.EntitiesAttachmentCount = 0
        self.HashesLinkedToThreatCount = 0
        self.HashesNotMicrosoftSignedCount = 0
        self.HashesThreatList = []
        self.MaximumGlobalPrevalence = 0
        self.MinimumGlobalPrevalence = 0
        self.ModuleName = 'FileModule'
        self.DetailedResults = []

    def load_from_input(self, body):
        self.AnalyzedEntities = body['AnalyzedEntities']
        self.DeviceUniqueDeviceTotalCount = body['DeviceUniqueDeviceTotalCount']
        self.DeviceUniqueFileNameTotalCount = body['DeviceUniqueFileNameTotalCount']
        self.DeviceFileActionTotalCount = body['DeviceFileActionTotalCount']
        self.EntitiesAttachmentCount = body['EntitiesAttachmentCount']
        self.HashesLinkedToThreatCount = body['HashesLinkedToThreatCount']
        self.HashesNotMicrosoftSignedCount = body['HashesNotMicrosoftSignedCount']
        self.HashesThreatList = body['HashesThreatList']
        self.MaximumGlobalPrevalence = body['MaximumGlobalPrevalence']
        self.MinimumGlobalPrevalence = body['MinimumGlobalPrevalence']
        self.DetailedResults = body['DetailedResults']

class MDCAModule:
    '''A Microsoft Defender for Cloud Apps Module object'''
    
    def __init__(self):
        self.AboveThresholdCount = 0
        self.AnalyzedEntities = 0
        self.DetailedResults = []
        self.MaximumScore = 0
        self.HighestScorePercentile = 0
        self.TopUserThresholdCount = 0
        self.AnyThreatScoreTrendingUp = False
        self.ModuleName = 'MDCAModule'
        self.Warning = "The Sentinel Triage AssistanT's (STAT) Microsoft Defender for Cloud Apps module has been deprecated. This is due to Microsoft's deprecation of the MDCA investigation score. Please remove the MDCA module from your STAT Analysis."

class RunPlaybook:
    '''A RunPlaybook module object'''

    def __init__(self):
        self.LogicAppArmId = ''
        self.TenantId = ''
        self.PlaybookName = ''
        self.IncidentArmId = ''
        self.ModuleName = 'RunPlaybook'
        
class ExchangeModule:
    '''An Exchange module object'''
    def __init__(self):
        self.AllUsersInOffice = True
        self.AllUsersOutOfOffice = False
        self.Rules = []
        self.AuditEvents = []
        self.OOF = []
        self.UsersInOffice = 0
        self.UsersOutOfOffice = 0
        self.PrivilegedUsersWithMailbox = 0
        self.UsersUnknown = 0
        self.RulesDelete = 0
        self.RulesMove = 0
        self.RulesForward = 0
        self.DelegationsFound = 0
        self.ModuleName = 'ExchangeModule'

    def load_from_input(self, body):
        self.AllUsersInOffice = body['AllUsersInOffice']
        self.AllUsersOutOfOffice = body['AllUsersOutOfOffice']
        self.Rules = body['Rules']
        self.AuditEvents = body['AuditEvents']
        self.OOF = body['OOF']
        self.UsersInOffice = body['UsersInOffice']
        self.UsersOutOfOffice = body['UsersOutOfOffice']
        self.PrivilegedUsersWithMailbox = body['PrivilegedUsersWithMailbox']
        self.UsersUnknown = body['UsersUnknown']
        self.RulesDelete = body['RulesDelete']
        self.RulesMove = body['RulesMove']
        self.RulesForward = body['RulesForward']
        self.DelegationsFound = body['DelegationsFound']

class MDEModule:
    '''An MDE module object'''
    def __init__(self):
        self.AnalyzedEntities = 0
        self.IPsHighestExposureLevel = ''
        self.IPsHighestRiskScore = ''
        self.UsersHighestExposureLevel = ''
        self.UsersHighestRiskScore = ''
        self.HostsHighestExposureLevel = ''
        self.HostsHighestRiskScore = ''
        self.ModuleName = 'MDEModule'
        self.DetailedResults = {}

    def load_from_input(self, body):
        self.AnalyzedEntities = body['AnalyzedEntities']
        self.IPsHighestExposureLevel = body['IPsHighestExposureLevel']
        self.IPsHighestRiskScore = body['IPsHighestRiskScore']
        self.UsersHighestExposureLevel = body['UsersHighestExposureLevel']
        self.UsersHighestRiskScore = body['UsersHighestRiskScore']
        self.HostsHighestExposureLevel = body['HostsHighestExposureLevel']
        self.HostsHighestRiskScore = body['HostsHighestRiskScore']
        self.DetailedResults = body['DetailedResults']

class DeviceExposureModule:
    '''An Device Exposure module object'''
    def __init__(self):
        self.AnalyzedEntities = 0
        self.ModuleName = 'DeviceExposureModule'
        self.Nodes = []
        self.Paths = []

    def load_from_input(self, body):
        self.AnalyzedEntities = body['AnalyzedEntities']
        self.Nodes = body['Nodes']
        self.Paths = body['Paths']

    def nodes_without_paths(self):
        '''Only returns nodes where no path from node is present'''
        out = []
        path_nodes = []
        for path in self.Paths:
            path_nodes.append(path['ComputerNodeId'])

        for node in self.Nodes:
            if node['ComputerNodeId'] not in path_nodes:
                out.append(node)

        return out

class UserExposureModule:
    '''An User Exposure module object'''
    def __init__(self):
        self.AnalyzedEntities = 0
        self.ModuleName = 'UserExposureModule'
        self.Nodes = []
        self.Paths = []

    def load_from_input(self, body):
        self.AnalyzedEntities = body['AnalyzedEntities']
        self.Nodes = body['Nodes']
        self.Paths = body['Paths']

    def nodes_without_paths(self):
        '''Only returns nodes where no path from node is present'''
        out = []
        path_nodes = []
        for path in self.Paths:
            path_nodes.append(path['UserNodeId'])

        for node in self.Nodes:
            if node['UserNodeId'] not in path_nodes:
                out.append(node)

        return out

class CreateIncident:
    '''A CreateIncident object'''
    def __init__(self):
        self.IncidentARMId = ''
        self.AlertARMId = ''
        self.Title = ''
        self.Description = ''
        self.Severity = ''
        self.IncidentNumber = 0
        self.IncidentUrl = ''
        self.ModuleName = 'CreateIncident'

class DebugModule:
    '''A Debug Module Instance'''
    def __init__(self, req_body):
        self.ModuleName = 'DebugModule'
        self.STATVersion = data.get_current_version()
        self.Test = req_body.get('Test', 'Default')
        self.Params = req_body.get('Params', {})