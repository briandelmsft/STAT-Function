import urllib.parse
import json

class Response:
    '''A response object'''
    
    def __init__(self, body, statuscode=200, contenttype='application/json'):
        self.body = body
        self.statuscode = statuscode
        self.contenttype = contenttype

class STATError(Exception):
    '''A handled STAT exception'''

    def __init__(self, error:str, source_error:dict={}, status_code:int=400):
        self.error = error
        self.source_error = source_error
        self.status_code = status_code

class BaseModule:
    '''A base module object'''
    
    def __init__(self):
        self.Accounts = []
        self.AccountsCount = 0
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

    def add_ip_entity(self, address, geo_data, rawentity):
        self.IPs.append({'Address': address, 'GeoData': geo_data, 'RawEntity': rawentity })

    def add_host_entity(self, fqdn, hostname, dnsdomain, mdedeviceid, rawentity):
        if mdedeviceid:
            self.Hosts.append({'DnsDomain': dnsdomain, 'FQDN': fqdn, 'Hostname': hostname, 'MdatpDeviceId': mdedeviceid, 'RawEntity': rawentity })
        else:
            self.Hosts.append({'DnsDomain': dnsdomain, 'FQDN': fqdn, 'Hostname': hostname, 'RawEntity': rawentity })

    def add_account_entity(self, data):
        self.Accounts.append(data)

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
    
    def get_account_kql_table(self):

        account_data = []

        for account in self.Accounts:
            account_data.append({'userPrincipalName': account.get('userPrincipalName'), 'SamAccountName': account.get('onPremisesSamAccountName'), \
                                 'SID': account.get('onPremisesSecurityIdentifier'), 'id': account.get('id'), 'ManagerUPN': account.get('manager', {}).get('userPrincipalName')})

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
        
    def get_account_id_list(self):
        account_list = []
        for account in self.Accounts:
            account_list.append(account['id'])
        
        return account_list

    def get_account_upn_list(self):
        account_list = []
        for account in self.Accounts:
            account_list.append(account['userPrincipalName'])
        
        return account_list
    
    def get_account_sam_list(self):
        account_list = []
        for account in self.Accounts:
            account_list.append(account['onPremisesSamAccountName'])

        return account_list
    
    def get_alert_ids(self):
        alert_list = []
        for alert in self.Alerts:
            alert_list.append(alert['name'])
        
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

    def append_score(self, score, label):
        '''Adds to the TotalScore and DetailedResults list'''
        self.TotalScore += score
        self.DetailedResults.append({'Score': score, 'ScoreSource': label})

class AADModule:
    '''An AAD Module object'''

    def __init__(self):
        self.AnalyzedEntities = 0
        self.FailedMFATotalCount = None
        self.HighestRiskLevel = ''
        self.MFAFraudTotalCount = None
        self.SuspiciousActivityReportTotalCount = None
        self.ModuleName = 'AADRisksModule'
        self.DetailedResults = []

    def load_from_input(self, body):
        self.AnalyzedEntities = body['AnalyzedEntities']
        self.FailedMFATotalCount = body['FailedMFATotalCount']
        self.HighestRiskLevel = body['HighestRiskLevel']
        self.MFAFraudTotalCount = body['MFAFraudTotalCount']
        self.SuspiciousActivityReportTotalCount = body['SuspiciousActivityReportTotalCount']
        self.DetailedResults = body['DetailedResults']

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
        self.ModuleName = 'MDCAModule'

    def load_from_input(self, body):
        self.AboveThresholdCount = body['AboveThresholdCount']
        self.AnalyzedEntities = body['AnalyzedEntities']
        self.DetailedResults = body['DetailedResults']
        self.MaximumScore = body['MaximumScore']

class RunPlaybook:
    '''A RunPlaybook module object'''

    def __init__(self):
        self.LogicAppArmId = ''
        self.TenantId = ''
        self.PlaybookName = ''
        self.IncidentArmId = ''
        
class OOFModule:
    '''An Out of Office module object'''
    def __init__(self):
        self.AllUsersInOffice = True
        self.AllUsersOutOfOffice = False
        self.DetailedResults = []
        self.UsersInOffice = 0
        self.UsersOutOfOffice = 0
        self.UsersUnknown = 0

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
        self.DetailedResults = []

    def load_from_input(self, body):
        self.AnalyzedEntities = body['AnalyzedEntities']
        self.IPsHighestExposureLevel = body['IPsHighestExposureLevel']
        self.IPsHighestRiskScore = body['IPsHighestRiskScore']
        self.UsersHighestExposureLevel = body['UsersHighestExposureLevel']
        self.UsersHighestRiskScore = body['UsersHighestRiskScore']
        self.HostsHighestExposureLevel = body['HostsHighestExposureLevel']
        self.HostsHighestRiskScore = body['HostsHighestRiskScore']
        self.DetailedResults = body['DetailedResults']

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
