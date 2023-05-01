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

    def add_ip_entity(self, address, geo_data, rawentity):
        self.IPs.append({'Address': address, 'GeoData': geo_data, 'RawEntity': rawentity })

    def get_ip_list(self):
        ip_list = []
        for ip in self.IPs:
            ip_list.append(ip['Address'])

        return ip_list