import base64
import urllib.parse
import json

class Response:
    '''A response object'''
    
    def __init__(self, body, statuscode=200, contenttype='application/json'):
        self.body = body
        self.statuscode = statuscode
        self.contenttype = contenttype

class Error:
    '''An error'''

    def __init__(self, error):
        self.error = error

class STATError(Exception):
    '''A handled STAT exception'''

    def __init__(self, error:str, source_error:object={}, status_code:int=400):
        self.error = error
        self.source_error = source_error
        self.status_code = status_code

class BaseModule:
    '''A base module object'''
    
    def __init__(self):
        self.Accounts = []
        self.AccountsCount = 0
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
        self.ModuleVersions = {}
        self.OtherEntities = []
        self.OtherEntitiesCount = 0
        self.SentinelRGARMId = ""
        self.TenantDisplayName = ""
        self.TenantId = ""
        self.URLs = []
        self.URLsCount = 0
        self.WorkspaceARMId = ""
        self.WorkspaceId = ""

    def load_incident_trigger(self, req_body):
        
        self.IncidentARMId = req_body['object']['id']
        self.SentinelRGARMId = "/subscriptions/" + req_body['workspaceInfo']['SubscriptionId'] + "/resourceGroups/" + req_body['workspaceInfo']['ResourceGroupName']
        self.WorkspaceARMId = self.SentinelRGARMId + "/providers/Microsoft.OperationalInsights/workspaces/" + req_body['workspaceInfo']['WorkspaceName']
        self.WorkspaceId = req_body['workspaceId']

    def load_from_input(self, basebody):
        self.Accounts = basebody['Accounts']
        self.AccountsCount = basebody['AccountsCount']
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
        self.IncidentARMId = basebody['IncidentARMId']
        self.ModuleVersions = basebody['ModuleVersions']
        self.OtherEntities = basebody['OtherEntities']
        self.OtherEntitiesCount = basebody['OtherEntitiesCount']
        self.SentinelRGARMId = basebody['SentinelRGARMId']
        self.TenantDisplayName = basebody['TenantDisplayName']
        self.TenantId = basebody['TenantId']
        self.URLs = basebody['URLs']
        self.URLsCount = basebody['URLsCount']
        self.WorkspaceARMId = basebody['WorkspaceARMId']
        self.WorkspaceId = basebody['WorkspaceId']

    def add_ip_entity(self, address, geo_data, rawentity):
        self.IPs.append({'Address': address, 'GeoData': geo_data, 'RawEntity': rawentity })

    def add_host_entity(self, fqdn, hostname, dnsdomain, rawentity):
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
    
class KQLModule:
    '''A KQL module object'''
    
    def __init__(self):
        self.DetailedResults = []
        self.ModuleName = 'KQLModule'
        self.ResultsCount = 0
        self.ResultsFound = False

class WatchlistModule:
    '''A Watchlist module object'''
    
    def __init__(self):
        self.DetailedResults = []
        self.EntitiesAnalyzedCount = 0
        self.EntitiesOnWatchlist = False
        self.EntitiesOnWatchlistCount = 0
        self.WatchlistName = ""
        self.ModuleName = 'WatchlistModule'

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

class RelatedAlertsModule:
    '''A Related Alerts module object'''

    def __init__(self):
        self.AllTactics =  []
        self.AllTacticsCount = 0
        self.DetailedResults = []
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
