from classes import BaseModule, Response, STATError, STATNotFound
from shared import rest, data
import json
import time
import logging
import requests
import ipaddress
import datetime as dt

stat_version = None

def execute_base_module (req_body):
    global base_object
    global enrich_mfa
    global enrich_roles
    global enrich_mde_device
    
    base_object = BaseModule()

    try:
        trigger_type = req_body['Body'].get('objectSchemaType', 'alert')
    except:
        raise STATError('The Base Module Incident or Alert body is missing or invalid. This may be caused by a missing or incorrect input to the module, or by running the logic app manually with no incident context.')

    base_object.MultiTenantConfig = req_body.get('MultiTenantConfig', {})
    enrich_mfa = req_body.get('EnrichAccountsWithMFA', True)
    enrich_roles = req_body.get('EnrichAccountsWithRoles', True)
    enrich_mde_device = req_body.get('EnrichHostsWithMDE', True)

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
    enrich_mail_message(entities)
    append_other_entities(entities)

    base_object.CurrentVersion = data.get_current_version()
    base_object.EntitiesCount = base_object.AccountsCount + base_object.IPsCount + base_object.DomainsCount + base_object.FileHashesCount + base_object.FilesCount + base_object.HostsCount + base_object.OtherEntitiesCount + base_object.URLsCount + base_object.MailMessagesCount

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
    mail_comment = ''

    if req_body.get('AddAccountComments', True) and base_object.AccountsCount > 0:
        account_comment = '<h3>Account Info:</h3>' + get_account_comment()

    if req_body.get('AddIPComments', True) and base_object.check_global_and_local_ips():
        ip_comment = '<h3>IP Info:</h3>' + get_ip_comment()

    if req_body.get('AddMailComments', True) and base_object.MailMessages:
        mail_comment = '<h3>Mail Message Info:</h3>' + get_mail_comment()

    if (req_body.get('AddAccountComments', True) and base_object.AccountsCount > 0) or (req_body.get('AddIPComments', True) and base_object.check_global_and_local_ips()) or (req_body.get('AddMailComments', True) and base_object.MailMessages):
        comment = ''
        if account_comment:
            comment += account_comment + '<br><p>'
        if ip_comment:
            comment += ip_comment + '<br><p>'
        if mail_comment:
            comment += mail_comment
        
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
    workspace_query = json.loads(rest.rest_call_get(base_object, 'arm', f'/subscriptions/{subscription_id}/providers/Microsoft.OperationalInsights/workspaces?api-version=2023-09-01').content)
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

    for ip in ip_entities:
        try:
            ip_data = ipaddress.ip_address(data.coalesce(ip.get('properties', {}).get('address'), ip.get('Address')))
            raw_entity = data.coalesce(ip.get('properties'), ip)
        except:
            #Skip any IPs that cannot be parsed
            continue
        
        if ip_data.is_loopback:
            #Skip any loopback IPs
            continue
        elif ip_data.is_link_local:
            base_object.add_ip_entity(address=ip_data.compressed, ip_type=3, geo_data={}, rawentity=raw_entity)
        elif ip_data.is_private:
            base_object.add_ip_entity(address=ip_data.compressed, ip_type=2, geo_data={}, rawentity=raw_entity)
        elif ip_data.is_global:
            if get_geo:
                path = base_object.SentinelRGARMId + "/providers/Microsoft.SecurityInsights/enrichment/ip/geodata/?api-version=2023-04-01-preview&ipAddress=" + ip_data.compressed
                try:
                    response = rest.rest_call_get(base_object, api='arm', path=path)
                except STATError:
                    base_object.add_ip_entity(address=ip_data.compressed, ip_type=1, geo_data={}, rawentity=raw_entity)
                else:
                    base_object.add_ip_entity(address=ip_data.compressed, ip_type=1, geo_data=json.loads(response.content), rawentity=raw_entity)
            else:
                base_object.add_ip_entity(address=ip_data.compressed, ip_type=1, geo_data={}, rawentity=raw_entity)
        else:
            base_object.add_ip_entity(address=ip_data.compressed, ip_type=8, geo_data={}, rawentity=raw_entity)

    base_object.IPsCount = len(base_object.IPs)

def enrich_accounts(entities):
    account_entities = list(filter(lambda x: x['kind'].lower() == 'account', entities))
    base_object.AccountsCount = len(account_entities)

    attributes = 'userPrincipalName,id,onPremisesSecurityIdentifier,onPremisesDistinguishedName,onPremisesDomainName,onPremisesSamAccountName,onPremisesSyncEnabled,mail,city,state,country,department,jobTitle,officeLocation,accountEnabled&$expand=manager($select=userPrincipalName,mail,id)'

    for account in account_entities:
        aad_id = data.coalesce(account.get('properties',{}).get('aadUserId'), account.get('AadUserId'))
        upn_suffix = data.coalesce(account.get('properties',{}).get('upnSuffix'), account.get('UPNSuffix'))
        account_name = data.coalesce(account.get('properties',{}).get('accountName'), account.get('Name'))
        friendly_name = data.coalesce(account.get('properties',{}).get('friendlyName'), account.get('DisplayName'), account.get('Name'))
        sid = data.coalesce(account.get('properties',{}).get('sid'), account.get('Sid'), account.get('sid'))
        nt_domain = data.coalesce(account.get('properties',{}).get('ntDomain'), account.get('NTDomain'))
        object_guid = data.coalesce(account.get('properties',{}).get('objectGuid'), account.get('ObjectGuid'))
        properties = data.coalesce(account.get('properties'), account)

        if aad_id:
            get_account_by_upn_or_id(aad_id, attributes, properties, 'Id')
        elif upn_suffix:
            get_account_by_upn_or_id(account_name + '@' + upn_suffix, attributes, properties, 'UPN')
        elif sid:
            get_account_by_sid(sid, attributes, properties, 'SID')
        elif nt_domain and account_name:
            get_account_by_samaccountname(account_name, attributes, properties, 'SAMAccountName')
        elif object_guid:
            get_account_by_upn_or_id(object_guid, attributes, properties, 'ObjectGuid')
        else:
            if friendly_name is None:
                base_object.add_account_entity({'EnrichmentMethod': 'FriendlyName - No Match', 'RawEntity': properties})
            elif friendly_name.__contains__('@'):
                get_account_by_upn_or_id(friendly_name, attributes, properties, 'FriendlyName - UPN')
            elif friendly_name.__contains__('S-1-'):
                get_account_by_sid(friendly_name, attributes, properties, 'FriendlyName - SID')
            elif friendly_name.__contains__('CN='):
                get_account_by_dn(friendly_name, attributes, properties, 'FriendlyName - DN')
            else:
                get_account_by_samaccountname(friendly_name, attributes, properties, 'FriendlyName - SAMAccountName')


def enrich_domains(entities):
    domain_entities = list(filter(lambda x: x['kind'].lower() in ('dnsresolution', 'dns'), entities))
    base_object.DomainsCount = len(domain_entities)
    
    for domain in domain_entities:
        domain_name = data.coalesce(domain.get('properties',{}).get('domainName'), domain.get('DomainName'))
        raw_entity = data.coalesce(domain.get('properties'), domain)
        base_object.Domains.append({'Domain': domain_name, 'RawEntity': raw_entity})

def enrich_mail_message(entities):
    mail_entities = list(filter(lambda x: x['kind'].lower() == 'mailmessage', entities))
    base_object.MailMessagesCount = len(mail_entities)
    message_role = rest.check_app_role(base_object, 'msgraph', ['SecurityAnalyzedMessage.Read.All','SecurityAnalyzedMessage.ReadWrite.All'])
    
    for mail in mail_entities:
        recipient = data.coalesce(mail.get('properties',{}).get('recipient'), mail.get('Recipient'))
        network_message_id = data.coalesce(mail.get('properties',{}).get('networkMessageId'), mail.get('NetworkMessageId'))
        receive_date = data.coalesce(mail.get('properties',{}).get('receiveDate'), mail.get('ReceivedDate'))

        if receive_date:
            start_time = (dt.datetime.fromisoformat(receive_date) + dt.timedelta(days=-14)).strftime("%Y-%m-%dT%H:%M:%SZ")
            end_time = (dt.datetime.fromisoformat(receive_date) + dt.timedelta(days=14)).strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            start_time = (dt.datetime.fromisoformat(base_object.CreatedTime) + dt.timedelta(days=-14)).strftime("%Y-%m-%dT%H:%M:%SZ")
            end_time = (dt.datetime.fromisoformat(base_object.CreatedTime) + dt.timedelta(days=14)).strftime("%Y-%m-%dT%H:%M:%SZ")

        raw_entity = data.coalesce(mail.get('properties'), mail)

        if not message_role:
            base_object.MailMessages.append({'networkMessageId': network_message_id, 'recipientEmailAddress': recipient, 'EnrichmentMethod': 'MailMessage - No App Role', 'RawEntity': raw_entity})
            continue

        if recipient and network_message_id:
            try:
                get_message = json.loads(rest.rest_call_get(base_object, api='msgraph', path=f"/beta/security/collaboration/analyzedemails?startTime={start_time}&endTime={end_time}&filter=networkMessageId eq '{network_message_id}' and recipientEmailAddress eq '{recipient}'").content)
                if get_message['value']:
                    message_details = json.loads(rest.rest_call_get(base_object, api='msgraph', path=f"/beta/security/collaboration/analyzedemails/{get_message['value'][0]['id']}").content)
                    message_details['RawEntity'] = raw_entity
                else:
                    message_details = {
                    'networkMessageId': network_message_id,
                    'recipientEmailAddress': recipient,
                    'EnrichmentMethod': 'MailMessage - analyzedMessage could not be found',
                    'RawEntity': raw_entity
                    } 
            except: 
                message_details = {
                    'networkMessageId': network_message_id,
                    'recipientEmailAddress': recipient,
                    'EnrichmentMethod': 'MailMessage - Failed to get analyzedMessage',
                    'RawEntity': raw_entity
                    } 
            
        else:
            message_details = {'EnrichmentMethod': 'MailMessage - No Recipient or NetworkMessageId', 'RawEntity': raw_entity}

        base_object.MailMessages.append(message_details)


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
    other_entities = list(filter(lambda x: x['kind'].lower() not in ('ip','account','dnsresolution','dns','file','filehash','host','url','mailmessage'), entities))
    base_object.OtherEntitiesCount = len(other_entities)

    for entity in other_entities:
        raw_entity = data.coalesce(entity.get('properties'), entity)
        base_object.OtherEntities.append({'RawEntity': raw_entity})

def get_account_by_upn_or_id(account, attributes, properties, enrich_method:str='UPN, Mail or Id'):
    try:
        user_info = json.loads(rest.rest_call_get(base_object, api='msgraph', path='/v1.0/users/' + account + '?$select=' + attributes).content)
    except STATError:
        if account.__contains__('@'):
            get_account_by_mail(account, attributes, properties)
        else:
            base_object.add_account_entity({'EnrichmentMethod': f'{enrich_method} - No Match', 'RawEntity': properties})
    else:
        append_account_details(account, user_info, properties, enrich_method)

def get_account_by_mail(account, attributes, properties, enrich_method:str='Mail'):
    query = f'''union isfuzzy=true
(datatable(userPrincipalName:string)[]),
(IdentityInfo
| where AccountUPN =~ '{account}'
| summarize arg_max(TimeGenerated, *) by AccountUPN
| project userPrincipalName=AccountUPN, id=AccountObjectId, onPremisesSecurityIdentifier=AccountSID, onPremisesDistinguishedName=OnPremisesDistinguishedName, onPremisesDomainName=AccountDomain, onPremisesSamAccountName=AccountName, mail=MailAddress, department=Department, jobTitle=JobTitle, accountEnabled=IsAccountEnabled, manager=Manager)'''
    try:
        user_info = json.loads(rest.rest_call_get(base_object, api='msgraph', path=f'''/v1.0/users?$filter=(mail%20eq%20'{account}')&$select={attributes}''').content)
    except STATError:
        base_object.add_account_entity({'EnrichmentMethod': f'{enrich_method} - No Match', 'RawEntity': properties})
    else:
        if user_info['value']:
            append_account_details(account, user_info['value'][0], properties, enrich_method)
        else:
            results = rest.execute_la_query(base_object, query, 14)
            if results:
                user = results[0]
                user['EnrichmentMethod'] = f'UPN-IdentityInfo'
                base_object.add_onprem_account_entity(user)
            else:
                base_object.add_account_entity({'EnrichmentMethod': f'UPN-IdentityInfo - No Match', 'RawEntity': properties})
            #base_object.add_account_entity({'EnrichmentMethod': f'{enrich_method} - No Match', 'RawEntity': properties})

def get_account_by_dn(account, attributes, properties, enrich_method:str='DN'):

    query = f'''union isfuzzy=true
(datatable(onPremisesDistinguishedName:string)[]),
(IdentityInfo
| where OnPremisesDistinguishedName =~ '{account}'
| summarize arg_max(TimeGenerated, *) by OnPremisesDistinguishedName
| project userPrincipalName=AccountUPN, id=AccountObjectId, onPremisesSecurityIdentifier=AccountSID, onPremisesDistinguishedName=OnPremisesDistinguishedName, onPremisesDomainName=AccountDomain, onPremisesSamAccountName=AccountName, mail=MailAddress, department=Department, jobTitle=JobTitle, accountEnabled=IsAccountEnabled, manager=Manager)'''

    results = rest.execute_la_query(base_object, query, 14)
    if results and results[0]['id']:
        get_account_by_upn_or_id(results[0]['userPrincipalName'], attributes, properties, enrich_method)
    elif results:
        user = results[0]
        user['EnrichmentMethod'] = f'DN-IdentityInfo'
        base_object.add_onprem_account_entity(user)
    else:
        base_object.add_account_entity({'EnrichmentMethod': f'{enrich_method} - No Match', 'RawEntity': properties})

def get_account_by_sid(account, attributes, properties, enrich_method:str='SID'):

    query = f'''union isfuzzy=true
(datatable(onPremisesSecurityIdentifier:string)[]),
(IdentityInfo
| where AccountSID =~ '{account}'
| summarize arg_max(TimeGenerated, *) by AccountSID
| project userPrincipalName=AccountUPN, id=AccountObjectId, onPremisesSecurityIdentifier=AccountSID, onPremisesDistinguishedName=OnPremisesDistinguishedName, onPremisesDomainName=AccountDomain, onPremisesSamAccountName=AccountName, mail=MailAddress, department=Department, jobTitle=JobTitle, accountEnabled=IsAccountEnabled, manager=Manager)'''

    try:
        user_info = json.loads(rest.rest_call_get(base_object, api='msgraph', path=f'''/v1.0/users?$filter=(onPremisesSecurityIdentifier%20eq%20'{account}')&$select={attributes}''').content)
    except STATError:
        base_object.add_account_entity({'EnrichmentMethod': f'{enrich_method} - No Match', 'RawEntity': properties})
    else:
        if user_info['value']:
            append_account_details(account, user_info['value'][0], properties, enrich_method)
        else:
            results = rest.execute_la_query(base_object, query, 14)
            if results:
                user = results[0]
                user['EnrichmentMethod'] = f'SID-IdentityInfo'
                base_object.add_onprem_account_entity(user)
            else:
                base_object.add_account_entity({'EnrichmentMethod': f'SID-IdentityInfo - No Match', 'RawEntity': properties})

def get_account_by_samaccountname(account, attributes, properties, enrich_method:str='SAMAccountName'):
    query = f'''union isfuzzy=true
(datatable(onPremisesSecurityIdentifier:string)[]),
(IdentityInfo
| where AccountName =~ '{account}'
| summarize arg_max(TimeGenerated, *) by AccountSID, AccountObjectId
| project userPrincipalName=AccountUPN, id=AccountObjectId, onPremisesSecurityIdentifier=AccountSID, onPremisesDistinguishedName=OnPremisesDistinguishedName, onPremisesDomainName=AccountDomain, onPremisesSamAccountName=AccountName, mail=MailAddress, department=Department, jobTitle=JobTitle, accountEnabled=IsAccountEnabled, manager=Manager)'''

    results = rest.execute_la_query(base_object, query, 14)
    if len(results) == 1 and results[0].get('id'):
        get_account_by_upn_or_id(results[0]['id'], attributes, properties, enrich_method)
    elif len(results) == 1:
        user = results[0]
        user['EnrichmentMethod'] = f'SAMAccountName-IdentityInfo'
        base_object.add_onprem_account_entity(user)
    elif len(results) > 1:
        base_object.add_account_entity({'EnrichmentMethod': f'{enrich_method} - Multiple Matches', 'RawEntity': properties})
    else:
        base_object.add_account_entity({'EnrichmentMethod': f'{enrich_method} - No Match', 'RawEntity': properties})

def append_account_details(account, user_info, raw_entity, enrich_method:str='Unknown'):

    assigned_roles = ['Unavailable']
    security_info = {}
    
    try: 
        if enrich_roles:
            assigned_roles = get_account_roles(user_info['id'])
    except:
        pass
    
    try:
        if enrich_mfa:
            security_info = json.loads(rest.rest_call_get(base_object, api='msgraph', path=f"/v1.0/reports/authenticationMethods/userRegistrationDetails/{user_info['id']}").content)
    except:
        pass

    user_info['AssignedRoles'] = assigned_roles
    user_info['isAADPrivileged'] = bool(list(filter(lambda x: x != 'Unknown', assigned_roles)))
    user_info['isMfaRegistered'] = security_info.get('isMfaRegistered', 'Unknown')
    user_info['isSSPREnabled'] = security_info.get('isSsprEnabled', 'Unknown')
    user_info['isSSPRRegistered'] = security_info.get('isSsprRegistered', 'Unknown')
    user_info['EnrichmentMethod'] = enrich_method
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
        host_name = data.coalesce(host.get('properties',{}).get('hostName'), host.get('HostName'), host.get('properties',{}).get('netBiosName'), host.get('NetBiosName'), host.get('properties',{}).get('friendlyName', ''))
        domain_name = data.coalesce(host.get('properties',{}).get('dnsDomain'), host.get('DnsDomain'), '')
        mde_device_id = data.coalesce(host.get('properties',{}).get('additionalData', {}).get('MdatpDeviceId'), host.get('MdatpDeviceId'))
        fqdn = data.coalesce(host.get('properties',{}).get('additionalData', {}).get('FQDN'), host.get('FQDN'), f'{host_name}.{domain_name}') 
        mde_enrichment = 'Unknown'

        if mde_device_id:
            mde_enrichment = 'Entity Data'
        elif not(enrich_mde_device):
            mde_enrichment = 'Enrichment Disabled'
        
        if not(mde_device_id) and enrich_mde_device:
            query = f'''DeviceInfo
| where Timestamp > ago(14d)
| where DeviceName =~ '{fqdn}' or DeviceName has '{host_name}'
| extend MatchType = iff(DeviceName =~ '{fqdn}', 'FQDN', 'Hostname')
| summarize arg_max(Timestamp, *) by DeviceId
| project Timestamp, DeviceId, DeviceName, MatchType, AadDeviceId
| summarize DeviceIdCount=dcount(DeviceId), DeviceId=max(DeviceId) by MatchType, bin(Timestamp, 12h)
| sort by Timestamp desc'''
            
            try:
                results = rest.execute_m365d_query(base_object, query)
            except:
                results = []

            if results:
                fqdn_matches = list(filter(lambda x: x['MatchType'] == 'FQDN', results))
                host_matches = list(filter(lambda x: x['MatchType'] == 'Hostname', results))
                if fqdn_matches:
                    if fqdn_matches[0]['DeviceIdCount'] == 1:
                        mde_device_id = fqdn_matches[0]['DeviceId']
                        mde_enrichment = 'FQDN'
                    else:
                        mde_enrichment = 'FQDN - Too many matching devices'
                elif host_matches:
                    if host_matches[0]['DeviceIdCount'] == 1:
                        mde_device_id = host_matches[0]['DeviceId']
                        mde_enrichment = 'Hostname'
                    else:
                        mde_enrichment = 'Hostname - Too many matching devices'
            else:
                mde_enrichment = 'No FQDN or Hostname matches found'

        raw_entity = data.coalesce(host.get('properties'), host)
        base_object.add_host_entity(fqdn=fqdn, hostname=host_name, dnsdomain=domain_name, mdedeviceid=mde_device_id, rawentity=raw_entity, mde_enrichment=mde_enrichment) 

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

        if upn_data:
            account_list.append({
                'User': f"{upn_data}<br><b>JobTitle</b>: {account.get('jobTitle')}", 
                'Location': f"<b>Department</b>: {account.get('department')}<br><b>Office</b>: {account.get('officeLocation')}<br><b>City</b>: {account.get('city')}<br><b>Country</b>: {account.get('country')}",
                'OtherDetails': f"<b>AADRoles:</b> {', '.join(account.get('AssignedRoles', []))}<br><b>Manager</b>: {account.get('manager', {}).get('userPrincipalName')}<br><b>MFA Registered</b>: {account.get('isMfaRegistered')}<br><b>SSPR Enabled</b>: {account.get('isSSPREnabled')}<br><b>SSPR Registered</b>: {account.get('isSSPRRegistered')}<br><b>OnPremSynced</b>: {account.get('onPremisesSyncEnabled')}"
            })
        else:
            account_list.append({
                'User': "Unknown User",
                'OtherDetails': f"Failed to lookup account details for 1 account entity<br><b>Enrichment Method</b>: {account.get('EnrichmentMethod')}",
            })
       
    for onprem_acct in base_object.AccountsOnPrem:
        account_list.append({
                'User': f"{data.coalesce(onprem_acct.get('userPrincipalName'),onprem_acct.get('onPremisesSamAccountName'))}<br><b>JobTitle</b>: {onprem_acct.get('jobTitle')}", 
                'Location': f"<b>Department</b>: {onprem_acct.get('department')}",
                'OtherDetails': f"<b>Manager</b>: {onprem_acct.get('manager')}<br><b>OnPremSynced</b>: On-Prem Only"
            })
        
    return data.list_to_html_table(account_list, 20, 20, escape_html=False)

def get_ip_comment():
    
    ip_list = []
    for ip in base_object.IPs:
        if ip.get('IPType') != 3:
            #Excludes link local addresses from the IP comment
            geo = ip.get('GeoData')

            ip_list.append({
                'IP': ip.get('Address'),
                'Location': f"<b>City</b>: {geo.get('city', 'Unknown')}<br><b>State</b>: {geo.get('state', 'Unknown')}<br><b>Country</b>: {geo.get('country', 'Unknown')}",
                'OtherDetails': f"<b>Organization</b>: {geo.get('organization', 'Unknown')}<br><b>OrganizationType</b>: {geo.get('organizationType', 'Unknown')}<br><b>ASN</b>: {geo.get('asn', 'Unknown')}",
                'IPType': ip.get('IPType')
            })
            
    ip_list = data.sort_list_by_key(ip_list, 'IPType', ascending=True, drop_columns=['IPType'])
        
    return data.list_to_html_table(ip_list, escape_html=False)

def get_mail_comment():
    
    mail_list = []
    for msg in base_object.MailMessages:
        if msg.get('EnrichmentMethod'):
            mail_list.append({
                'MessageDetails': f"<b>NetworkMessageId</b>: {msg.get('networkMessageId')}<br><b>Recipient</b>: {msg.get('recipientEmailAddress', 'Unknown')}",
                'EnrichmentMethod': f"<b>Enrichment Method</b>: {msg.get('EnrichmentMethod')}",
            })
        else:
            mail_list.append({
                'MessageDetails': f"<b>Recipient</b>: {msg.get('recipientEmailAddress')}<br><b>Sender</b>: {msg.get('senderDetail', {}).get('fromAddress')}<br><b>SenderFromAddress</b>: {msg.get('senderDetail', {}).get('mailFromAddress')}<br><b>Subject</b>: {msg.get('subject')}<br><b>AttachmentCount:</b> {len(msg.get('attachments', []))}<br><b>URLCount:</b> {len(msg.get('urls', []))}",
                'Delivery': f"<b>Original Delivery</b>: {msg.get('originalDelivery', {}).get('location')}<br><b>Latest Delivery</b>: {msg.get('latestDelivery', {}).get('location')}",
                'Authentication': f"<b>SPF</b>: {msg.get('authenticationDetails', {}).get('senderPolicyFramework')}<br><b>DKIM</b>: {msg.get('authenticationDetails', {}).get('dkim')}<br><b>DMARC</b>: {msg.get('authenticationDetails', {}).get('dmarc')}",
                'ThreatInfo': f"<b>ThreatTypes</b>: {', '.join(msg.get('threatTypes', []))}<br><b>DetectionMethods</b>: {', '.join(msg.get('detectionMethods', []))}"
            })
        
    return data.list_to_html_table(mail_list, escape_html=False)

def get_stat_version(version_check_type):

    stat_version = data.get_current_version() 
    available_version = base_object.ModuleVersions.get('STATFunction', '1.4.9')
    logging.info(f'STAT Version check info. Current Version: {stat_version}, Available Version: {available_version}')
    version_check_result = data.version_check(stat_version, available_version, version_check_type)
    if version_check_result['UpdateAvailable'] and base_object.IncidentAvailable:
        rest.add_incident_comment(base_object, f'<h4>A Microsoft Sentinel Triage AssistanT update is available</h4>The currently installed version is {stat_version}, the available version is {available_version}.')