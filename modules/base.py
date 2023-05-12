from classes import BaseModule, Response, STATError
from shared import rest, data
import json

def execute_base_module (req_body):
    global base_object
    
    base_object = BaseModule()
    base_object.load_incident_trigger(req_body['Body'])
    
    entities = req_body['Body']['object']['properties']['relatedEntities']

    if not entities:
        rest.add_incident_comment(base_object.IncidentARMId, 'The Microsoft Sentinel Triage AssistanT failed to analyze this incident. \
                                  This error was due to no incident entities being available at the time the incident was processed.')
        raise STATError('No entities found in the trigger data. The Microsoft Sentinel Triage AssistanT requires at least 1 entity be linked to the alert.')

    enrich_ips(entities, req_body.get('EnrichIPsWithGeoData', True))
    enrich_accounts(entities)
    enrich_hosts(entities)
    enrich_domains(entities)
    enrich_files(entities)
    enrich_filehashes(entities)
    enrich_urls(entities)
    append_other_entities(entities)

    base_object.EntitiesCount = base_object.AccountsCount + base_object.DomainsCount + base_object.FileHashesCount + base_object.FilesCount + base_object.HostsCount + base_object.OtherEntitiesCount + base_object.URLsCount

    org_info = json.loads(rest.rest_call_get(api='msgraph', path='/v1.0/organization').content)
    base_object.TenantDisplayName = org_info['value'][0]['displayName']
    base_object.TenantId = org_info['value'][0]['id']

    account_comment = ''
    ip_comment = ''

    if req_body.get('AddAccountComment', True) and base_object.AccountsCount > 0:
        account_comment = 'Account Info:<br>' + get_account_comment()

    if req_body.get('AddIPComment', True) and base_object.IPsCount > 0:
        ip_comment = 'IP Info:<br>' + get_ip_comment()

    if (req_body.get('AddAccountComment', True) and base_object.AccountsCount > 0) or (req_body.get('AddIPComment', True) and base_object.IPsCount > 0):
        comment = account_comment + '<br><p>' + ip_comment
        rest.add_incident_comment(base_object.IncidentARMId, comment)

    return Response(base_object)

def enrich_ips (entities, get_geo):
    ip_entities = list(filter(lambda x: x['kind'].lower() == 'ip', entities))
    base_object.IPsCount = len(ip_entities)

    for ip in ip_entities:
        if get_geo:
            path = base_object.SentinelRGARMId + "/providers/Microsoft.SecurityInsights/enrichment/ip/geodata/?api-version=2023-04-01-preview&ipAddress=" + ip['properties']['address']
            response = rest.rest_call_get(api='arm', path=path)
            base_object.add_ip_entity(address=ip['properties']['address'], geo_data=json.loads(response.content), rawentity=ip['properties'])
        else:
            base_object.add_ip_entity(address=ip['properties']['address'], geo_data={}, rawentity=ip['properties'])

def enrich_accounts(entities):
    account_entities = list(filter(lambda x: x['kind'].lower() == 'account', entities))
    base_object.AccountsCount = len(account_entities)

    attributes = 'userPrincipalName,id,onPremisesSecurityIdentifier,onPremisesDistinguishedName,onPremisesDomainName,onPremisesSamAccountName,onPremisesSyncEnabled,mail,city,state,country,department,jobTitle,officeLocation,accountEnabled&$expand=manager($select=userPrincipalName,mail,id)'

    for account in account_entities:
        properties = account.get('properties')
        if properties.get('aadUserId'):
            get_account_by_upn_or_id(properties['aadUserId'], attributes, properties)
        elif properties.get('upnSuffix'):
            get_account_by_upn_or_id(properties['accountName'] + '@' + properties['upnSuffix'], attributes, properties)

def enrich_domains(entities):
    domain_entities = list(filter(lambda x: x['kind'].lower() == 'dnsresolution', entities))
    base_object.DomainsCount = len(domain_entities)
    
    for domain in domain_entities:
        base_object.Domains.append({'Domain': domain['properties']['domainName'], 'RawEntity': domain['properties']})

def enrich_files(entities):
    file_entities = list(filter(lambda x: x['kind'].lower() == 'file', entities))
    base_object.FilesCount = len(file_entities)

    for file in file_entities:
        base_object.Files.append({'RawEntity': file['properties']})

def enrich_filehashes(entities):
    filehash_entities = list(filter(lambda x: x['kind'].lower() == 'filehash', entities))
    base_object.FileHashesCount = len(filehash_entities)

    for hash in filehash_entities:
        base_object.FileHashes.append({'FileHash': hash['properties']['hashValue'], 'Algorithm': hash['properties']['algorithm'], 'RawEntity': hash['properties']})

def enrich_urls(entities):
    url_entities = list(filter(lambda x: x['kind'].lower() == 'url', entities))
    base_object.URLsCount = len(url_entities)

    for url in url_entities:
        base_object.URLs.append({'Url': url['properties']['url'], 'RawEntity': url['properties']})

def append_other_entities(entities):
    other_entities = list(filter(lambda x: x['kind'].lower() not in ('ip','account','dnsresolution','file','filehash','url'), entities))
    base_object.OtherEntitiesCount = len(other_entities)

    for entity in other_entities:
        base_object.OtherEntities.append({'RawEntity': entity})

def get_account_by_upn_or_id(account, attributes, properties):
    try:
        user_info = json.loads(rest.rest_call_get(api='msgraph', path='/v1.0/users/' + account + '?$select=' + attributes).content)
    except STATError as e:
        base_object.add_account_entity({'RawEntity': properties})
    else:
        append_account_details(account, user_info, properties)

def get_account_by_dn(account, attributes):
    None

def get_account_by_sid(account, attributes):
    None

def get_account_by_samaccountname(account, attributes):
    None

def append_account_details(account, user_info, raw_entity):

    assigned_roles = get_account_roles(user_info['id'])
    security_info = get_security_info(user_info['userPrincipalName'])

    user_info['AssignedRoles'] = assigned_roles
    user_info['isAADPrivileged'] = bool(assigned_roles)
    user_info['isMfaRegistered'] = security_info['isMfaRegistered']
    user_info['isSSPREnabled'] = security_info['isEnabled']
    user_info['isSSPRRegistered'] = security_info['isRegistered']
    user_info['RawEntity'] = raw_entity
    
    base_object.add_account_entity(user_info)

def get_account_roles(id):
    role_info = json.loads(rest.rest_call_get(api='msgraph', path="/v1.0/roleManagement/directory/roleAssignments?$filter=principalId%20eq%20'" + id + "'&$expand=roleDefinition").content)
    roles = []
    
    for role in role_info['value']:
        roles.append(role['roleDefinition']['displayName'])
    return roles

def get_security_info(upn):
    response = json.loads(rest.rest_call_get(api='msgraph', path="/beta/reports/credentialUserRegistrationDetails?$filter=userPrincipalName%20eq%20'" + upn + "'").content)
    security_info = response['value'][0]
    return security_info


def enrich_hosts(entities):
    host_entities = list(filter(lambda x: x['kind'].lower() == 'host', entities))
    base_object.HostsCount = len(host_entities)

    for host in host_entities:
        base_object.add_host_entity(fqdn=host['properties']['hostName'] + '.' + host['properties']['dnsDomain'], hostname=host['properties']['hostName'], dnsdomain=host['properties']['dnsDomain'], rawentity=host['properties'])

def get_account_comment():
    
    account_list = []
    for account in base_object.Accounts:
        account_list.append({'UserPrincipalName': account.get('userPrincipalName'), 'City': account.get('city'), 'Country': account.get('country'), \
                             'Department': account.get('department'), 'JobTitle': account.get('jobTitle'), 'Office': account.get('officeLocation'), \
                             'AADRoles': account.get('AssignedRoles'), 'ManagerUPN': account.get('manager', {}).get('userPrincipalName'), \
                             'MfaRegistered': account.get('isMfaRegistered'), 'SSPREnabled': account.get('isSSPREnabled'), \
                             'SSPRRegistered': account.get('isSSPRRegistered')})
        
    return data.list_to_html_table(account_list, 20, 20)

def get_ip_comment():
    
    ip_list = []
    for ip in base_object.IPs:
        geo = ip.get('GeoData')
        ip_list.append({'IP': geo.get('ipAddr'), 'City': geo.get('city'), 'State': geo.get('state'), 'Country': geo.get('country'), \
                        'Organization': geo.get('organization'), 'OrganizationType': geo.get('organizationType'), 'ASN': geo.get('asn') })
        
    return data.list_to_html_table(ip_list)
