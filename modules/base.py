from classes import BaseModule, Response, STATError, STATNotFound
from shared import rest, data
import json
import time
import logging
import requests
import pathlib

stat_version = None

def execute_base_module (req_body):
    global base_object
    
    base_object = BaseModule()

    trigger_type = req_body['Body'].get('objectSchemaType', 'alert')

    base_object.MultiTenantConfig = req_body.get('MultiTenantConfig', {})

    if trigger_type.lower() == 'incident':
        entities = process_incident_trigger(req_body)
    else:
        entities = process_alert_trigger(req_body)

    if not entities:
        if base_object.IncidentAvailable:
            rest.add_incident_comment(base_object, 'The Microsoft Sentinel Triage AssistanT failed to analyze this incident. This error was due to no incident entities being available at the time the incident was processed.')
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

    org_info = json.loads(rest.rest_call_get(base_object, api='msgraph', path='/v1.0/organization').content)
    base_object.TenantDisplayName = org_info['value'][0]['displayName']
    base_object.TenantId = org_info['value'][0]['id']

    req_header = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.58'
    }

    base_object.ModuleVersions = json.loads(requests.get('https://aka.ms/mstatversion', headers=req_header, allow_redirects=True).content)
    version_check_type = req_body.get('VersionCheckType', 'Build')
    
    if version_check_type != 'None':
        try:
            get_stat_version(version_check_type)
        except:
            pass

    account_comment = ''
    ip_comment = ''

    if req_body.get('AddAccountComments', True) and base_object.AccountsCount > 0:
        account_comment = 'Account Info:<br>' + get_account_comment()

    if req_body.get('AddIPComments', True) and base_object.IPsCount > 0:
        ip_comment = 'IP Info:<br>' + get_ip_comment()

    if (req_body.get('AddAccountComments', True) and base_object.AccountsCount > 0) or (req_body.get('AddIPComments', True) and base_object.IPsCount > 0):
        comment = account_comment + '<br><p>' + ip_comment
        rest.add_incident_comment(base_object, comment)

    return Response(base_object)

def process_incident_trigger (req_body):
    base_object.load_incident_trigger(req_body['Body'])
    return req_body['Body']['object']['properties']['relatedEntities']

def process_alert_trigger (req_body):
    base_object.load_alert_trigger(req_body['Body'])
    entities = req_body['Body']['Entities']
    for entity in entities:
        entity['kind'] = entity.pop('Type')
             
    #Get Workspace ARM Id
    subscription_id = req_body['Body']['WorkspaceSubscriptionId']
    workspace_query = json.loads(rest.rest_call_get(base_object, 'arm', f'/subscriptions/{subscription_id}/providers/Microsoft.OperationalInsights/workspaces?api-version=2021-12-01-preview').content)
    filter_workspace = list(filter(lambda x: x['properties']['customerId'] == req_body['Body']['WorkspaceId'], workspace_query['value']))
    base_object.WorkspaceARMId = filter_workspace[0]['id']

    alert_rule_id = base_object.WorkspaceARMId + '/providers/Microsoft.SecurityInsights/alertRules/' + req_body['Body']['AlertType'].split('_')[-1]
    base_object.RelatedAnalyticRuleIds.append(alert_rule_id)

    #Get Security Alert Entity
    alert_found = False
    x = 0
    alert_id = base_object.WorkspaceARMId + '/providers/Microsoft.SecurityInsights/entities/' + req_body['Body']['SystemAlertId']
    alert_path = alert_id + '?api-version=2023-05-01-preview'
    
    while not alert_found:
        x += 1
        try:
            alert_result = json.loads(rest.rest_call_get(base_object, 'arm', alert_path).content)
        except STATNotFound:
            if x > 5:
                raise STATError('Alert metadata is not currently available, consider adding a delay in the logic app before calling the base module using an alert.', status_code=503)
            time.sleep(20)
        else:
            logging.info('Alert found, processing')
            base_object.Alerts.append(alert_result)
            alert_found = True

        
    #Check if alert is already linked to an incident and retrieve Incident ARM Id
    alert_relation_path = alert_id + '/relations?api-version=2023-05-01-preview'
    alert_relation_result = json.loads(rest.rest_call_get(base_object, 'arm', alert_relation_path).content)
    filter_relations = list(filter(lambda x: x['properties']['relatedResourceType'] == 'Microsoft.SecurityInsights/Incidents', alert_relation_result['value']))
    
    if filter_relations:
        base_object.IncidentARMId = filter_relations[0]['properties']['relatedResourceId']
        base_object.IncidentAvailable = True

    return entities

def enrich_ips (entities, get_geo):
    ip_entities = list(filter(lambda x: x['kind'].lower() == 'ip', entities))
    base_object.IPsCount = len(ip_entities)

    for ip in ip_entities:
        current_ip = data.coalesce(ip.get('properties', {}).get('address'), ip.get('Address'))
        raw_entity = data.coalesce(ip.get('properties'), ip)
        if get_geo:
            path = base_object.SentinelRGARMId + "/providers/Microsoft.SecurityInsights/enrichment/ip/geodata/?api-version=2023-04-01-preview&ipAddress=" + current_ip
            try:
                response = rest.rest_call_get(base_object, api='arm', path=path)
            except STATError:
                base_object.add_ip_entity(address=current_ip, geo_data={}, rawentity=raw_entity)
            else:
                base_object.add_ip_entity(address=current_ip, geo_data=json.loads(response.content), rawentity=raw_entity)
        else:
            base_object.add_ip_entity(address=current_ip, geo_data={}, rawentity=raw_entity)

def enrich_accounts(entities):
    account_entities = list(filter(lambda x: x['kind'].lower() == 'account', entities))
    base_object.AccountsCount = len(account_entities)

    attributes = 'userPrincipalName,id,onPremisesSecurityIdentifier,onPremisesDistinguishedName,onPremisesDomainName,onPremisesSamAccountName,onPremisesSyncEnabled,mail,city,state,country,department,jobTitle,officeLocation,accountEnabled&$expand=manager($select=userPrincipalName,mail,id)'

    for account in account_entities:
        aad_id = data.coalesce(account.get('properties',{}).get('aadUserId'), account.get('AadUserId'))
        upn_suffix = data.coalesce(account.get('properties',{}).get('upnSuffix'), account.get('UPNSuffix'))
        account_name = data.coalesce(account.get('properties',{}).get('accountName'), account.get('Name'))
        friendly_name = data.coalesce(account.get('properties',{}).get('friendlyName'), account.get('DisplayName'), account.get('Name'))
        sid = data.coalesce(account.get('properties',{}).get('sid'), account.get('Sid'))
        nt_domain = data.coalesce(account.get('properties',{}).get('ntDomain'), account.get('NTDomain'))
        properties = data.coalesce(account.get('properties'), account)

        if aad_id:
            get_account_by_upn_or_id(aad_id, attributes, properties)
        elif upn_suffix:
            get_account_by_upn_or_id(account_name + '@' + upn_suffix, attributes, properties)
        elif sid:
            get_account_by_sid(sid, attributes, properties)
        elif nt_domain and account_name:
            get_account_by_samaccountname(account_name, attributes, properties)
        else:
            if friendly_name.__contains__('@'):
                get_account_by_upn_or_id(friendly_name, attributes, properties)
            elif friendly_name.__contains__('S-1-'):
                get_account_by_sid(friendly_name, attributes, properties)
            elif friendly_name.__contains__('CN='):
                get_account_by_dn(friendly_name, attributes, properties)
            else:
                get_account_by_samaccountname(friendly_name, attributes, properties)


def enrich_domains(entities):
    domain_entities = list(filter(lambda x: x['kind'].lower() in ('dnsresolution', 'dns'), entities))
    base_object.DomainsCount = len(domain_entities)
    
    for domain in domain_entities:
        domain_name = data.coalesce(domain.get('properties',{}).get('domainName'), domain.get('DomainName'))
        raw_entity = data.coalesce(domain.get('properties'), domain)
        base_object.Domains.append({'Domain': domain_name, 'RawEntity': raw_entity})

def enrich_files(entities):
    file_entities = list(filter(lambda x: x['kind'].lower() == 'file', entities))
    base_object.FilesCount = len(file_entities)

    for file in file_entities:
        raw_entity = data.coalesce(file.get('properties'), file)
        base_object.Files.append({'FileName': data.coalesce(file.get('properties',{}).get('friendlyName'), file.get('Name')),'RawEntity': raw_entity})

def enrich_filehashes(entities):
    filehash_entities = list(filter(lambda x: x['kind'].lower() == 'filehash', entities))
    base_object.FileHashesCount = len(filehash_entities)

    for hash in filehash_entities:
        file_hash = data.coalesce(hash.get('properties',{}).get('hashValue'), hash.get('Value'))
        hash_alg = data.coalesce(hash.get('properties',{}).get('algorithm'), hash.get('Algorithm'))
        raw_entity = data.coalesce(hash.get('properties'), hash)
        base_object.FileHashes.append({'FileHash': file_hash, 'Algorithm': hash_alg, 'RawEntity': raw_entity})

def enrich_urls(entities):
    url_entities = list(filter(lambda x: x['kind'].lower() == 'url', entities))
    base_object.URLsCount = len(url_entities)

    for url in url_entities:
        url_data = data.coalesce(url.get('properties',{}).get('url'), url.get('Url'))
        raw_entity = data.coalesce(url.get('properties'), url)
        base_object.URLs.append({'Url': url_data, 'RawEntity': raw_entity})

def append_other_entities(entities):
    other_entities = list(filter(lambda x: x['kind'].lower() not in ('ip','account','dnsresolution','dns','file','filehash','host','url'), entities))
    base_object.OtherEntitiesCount = len(other_entities)

    for entity in other_entities:
        raw_entity = data.coalesce(entity.get('properties'), entity)
        base_object.OtherEntities.append({'RawEntity': raw_entity})

def get_account_by_upn_or_id(account, attributes, properties):
    try:
        user_info = json.loads(rest.rest_call_get(base_object, api='msgraph', path='/v1.0/users/' + account + '?$select=' + attributes).content)
    except STATError:
        if account.__contains__('@'):
            get_account_by_mail(account, attributes, properties)
        else:
            base_object.add_account_entity({'RawEntity': properties})
    else:
        append_account_details(account, user_info, properties)

def get_account_by_mail(account, attributes, properties):
    try:
        user_info = json.loads(rest.rest_call_get(base_object, api='msgraph', path=f'''/v1.0/users?$filter=(mail%20eq%20'{account}')&$select={attributes}''').content)
    except STATError:
        base_object.add_account_entity({'RawEntity': properties})
    else:
        if user_info['value']:
            append_account_details(account, user_info['value'][0], properties)
        else:
            base_object.add_account_entity({'RawEntity': properties})

def get_account_by_dn(account, attributes, properties):

    query = f'''union isfuzzy=true
(datatable(test:string)[]),
(IdentityInfo
| where OnPremisesDistinguishedName =~ '{account}'
| summarize arg_max(TimeGenerated, *) by OnPremisesDistinguishedName
| project AccountUPN)'''

    results = rest.execute_la_query(base_object, query, 14)
    if results:
        get_account_by_upn_or_id(results[0]['AccountUPN'], attributes, properties)
    else:
        base_object.add_account_entity({'RawEntity': properties})

def get_account_by_sid(account, attributes, properties):
    try:
        user_info = json.loads(rest.rest_call_get(base_object, api='msgraph', path=f'''/v1.0/users?$filter=(onPremisesSecurityIdentifier%20eq%20'{account}')&$select={attributes}''').content)
    except STATError:
        base_object.add_account_entity({'RawEntity': properties})
    else:
        if user_info['value']:
            append_account_details(account, user_info['value'][0], properties)
        else:
            base_object.add_account_entity({'RawEntity': properties})

def get_account_by_samaccountname(account, attributes, properties):
    query = f'''union isfuzzy=true
(datatable(test:string)[]),
(IdentityInfo
| where AccountName =~ '{account}'
| summarize arg_max(TimeGenerated, *) by AccountName
| project AccountUPN)'''

    results = rest.execute_la_query(base_object, query, 14)
    if results:
        get_account_by_upn_or_id(results[0]['AccountUPN'], attributes, properties)
    else:
        base_object.add_account_entity({'RawEntity': properties})

def append_account_details(account, user_info, raw_entity):

    assigned_roles = ['Unavailable']
    security_info = {}
    
    try: 
        assigned_roles = get_account_roles(user_info['id'])
    except:
        pass
    
    try:
        security_info = json.loads(rest.rest_call_get(base_object, api='msgraph', path=f"/v1.0/reports/authenticationMethods/userRegistrationDetails/{user_info['id']}").content)
    except:
        pass

    user_info['AssignedRoles'] = assigned_roles
    user_info['isAADPrivileged'] = bool(list(filter(lambda x: x != 'Unknown', assigned_roles)))
    user_info['isMfaRegistered'] = security_info.get('isMfaRegistered', 'Unknown')
    user_info['isSSPREnabled'] = security_info.get('isSsprEnabled', 'Unknown')
    user_info['isSSPRRegistered'] = security_info.get('isSsprRegistered', 'Unknown')
    user_info['RawEntity'] = raw_entity
    
    base_object.add_account_entity(user_info)

def get_account_roles(id):
    role_info = json.loads(rest.rest_call_get(base_object, api='msgraph', path="/v1.0/roleManagement/directory/roleAssignments?$filter=principalId%20eq%20'" + id + "'&$expand=roleDefinition").content)
    roles = []
    
    for role in role_info['value']:
        roles.append(role['roleDefinition']['displayName'])
    return roles

def enrich_hosts(entities):
    host_entities = list(filter(lambda x: x['kind'].lower() == 'host', entities))
    base_object.HostsCount = len(host_entities)

    for host in host_entities:
        host_name = data.coalesce(host.get('properties',{}).get('hostName'), host.get('HostName'))
        domain_name = data.coalesce(host.get('properties',{}).get('dnsDomain'), host.get('DnsDomain'), '')
        mde_device_id = data.coalesce(host.get('properties',{}).get('additionalData', {}).get('MdatpDeviceId'), host.get('MdatpDeviceId'))
        raw_entity = data.coalesce(host.get('properties'), host)
        base_object.add_host_entity(fqdn=host_name + '.' + domain_name, hostname=host_name, dnsdomain=domain_name, mdedeviceid=mde_device_id, rawentity=raw_entity)

def get_account_comment():
    
    account_list = []
    for account in base_object.Accounts:
        account_id = account.get('id')
        account_upn = account.get('userPrincipalName')
        account_mail = account.get('mail')
        if account_id:    
            upn_data = f'<a href="https://portal.azure.com/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/{account_id}" target="_blank">{account_upn}</a><br>(<a href="mailto:{account_mail}">Contact User</a>)'
        else:
            upn_data = account_upn
            
        account_list.append({'UserPrincipalName': upn_data, 'City': account.get('city'), 'Country': account.get('country'), \
                             'Department': account.get('department'), 'JobTitle': account.get('jobTitle'), 'Office': account.get('officeLocation'), \
                             'AADRoles': account.get('AssignedRoles'), 'ManagerUPN': account.get('manager', {}).get('userPrincipalName'), \
                             'MfaRegistered': account.get('isMfaRegistered'), 'SSPREnabled': account.get('isSSPREnabled'), \
                             'SSPRRegistered': account.get('isSSPRRegistered')})
        
    link_template = f'https://portal.azure.com/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/ed2a76d8-c545-4ada-9f45-8c86667394f4'
        
    return data.list_to_html_table(account_list, 20, 20, escape_html=False)

def get_ip_comment():
    
    ip_list = []
    for ip in base_object.IPs:
        geo = ip.get('GeoData')
        ip_list.append({'IP': ip.get('Address'), 'City': geo.get('city'), 'State': geo.get('state'), 'Country': geo.get('country'), \
                        'Organization': geo.get('organization'), 'OrganizationType': geo.get('organizationType'), 'ASN': geo.get('asn') })
        
    return data.list_to_html_table(ip_list)

def get_stat_version(version_check_type):
    global stat_version

    if stat_version is None:
        with open(pathlib.Path(__file__).parent / 'version.json') as f:
            stat_version = json.loads(f.read())['FunctionVersion']
    
    available_version = base_object.ModuleVersions.get('STATFunction', '1.4.9')
    logging.info(f'STAT Version check info. Current Version: {stat_version}, Available Version: {available_version}')
    version_check_result = data.version_check(stat_version, available_version, version_check_type)
    if version_check_result['UpdateAvailable'] and base_object.IncidentAvailable:
        rest.add_incident_comment(base_object, f'<h4>A Microsoft Sentinel Triage AssistanT update is available</h4>The currently installed version is {stat_version}, the available version is {available_version}.')