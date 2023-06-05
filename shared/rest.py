from azure.identity import DefaultAzureCredential
import requests
import datetime as dt
import json
import os
import uuid
from classes import STATError, BaseModule

stat_token = {}
graph_endpoint = os.getenv('GRAPH_ENDPOINT')
arm_endpoint = os.getenv('ARM_ENDPOINT')
la_endpoint = os.getenv('LOGANALYTICS_ENDPOINT')
m365_endpoint = os.getenv('M365_ENDPOINT')
mde_endpoint = os.getenv('MDE_ENDPOINT')
default_tenant_id = os.getenv('AZURE_TENANT_ID')

def token_cache(base_module:BaseModule, api:str):
    global stat_token

    default_tenant = os.getenv('AZURE_TENANT_ID')

    match api:
        case 'arm':
            tenant = base_module.MultiTenantConfig.get('ARMTenantId', base_module.MultiTenantConfig.get('TenantId', default_tenant))
            token_expiration_check(api, stat_token.get(tenant,{}).get('armtoken'), tenant)
            return stat_token[tenant]['armtoken']
        case 'msgraph':
            tenant = base_module.MultiTenantConfig.get('MSGraphTenantId', base_module.MultiTenantConfig.get('TenantId', default_tenant))
            token_expiration_check(api, stat_token.get(tenant,{}).get('msgraphtoken'), tenant) 
            return stat_token[tenant]['msgraphtoken']
        case 'la':
            tenant = base_module.MultiTenantConfig.get('LogAnalyticsTenantId', base_module.MultiTenantConfig.get('TenantId', default_tenant))
            token_expiration_check(api, stat_token.get(tenant,{}).get('latoken'), tenant)
            return stat_token[tenant]['latoken']
        case 'm365':
            tenant = base_module.MultiTenantConfig.get('M365DTenantId', base_module.MultiTenantConfig.get('TenantId', default_tenant))
            token_expiration_check(api, stat_token.get(tenant,{}).get('m365token'), tenant)
            return stat_token[tenant]['m365token']
        case 'mde':
            tenant = base_module.MultiTenantConfig.get('MDETenantId', base_module.MultiTenantConfig.get('TenantId', default_tenant))
            token_expiration_check(api, stat_token.get(tenant,{}).get('mdetoken'), tenant)
            return stat_token[tenant]['mdetoken']

def token_expiration_check(api:str, token, tenant:str):
    
    if token is None:
        acquire_token(api, tenant)
    else:
        expiration_time = dt.datetime.fromtimestamp(token.expires_on) - dt.timedelta(minutes=5)
        current_time = dt.datetime.now()

        if current_time > expiration_time:
            acquire_token(api, tenant) 

def acquire_token(api:str, tenant:str):
    global stat_token
    
    cred = DefaultAzureCredential(additionally_allowed_tenants='*')

    if not stat_token.get(tenant):
        stat_token[tenant] = {}

    match api:
        case 'arm':
            stat_token[tenant]['armtoken'] = cred.get_token("https://" + arm_endpoint + "/.default", tenant_id=tenant)
        case 'msgraph':
            stat_token[tenant]['msgraphtoken'] = cred.get_token("https://" + graph_endpoint + "/.default", tenant_id=tenant)
        case 'la':
            stat_token[tenant]['latoken'] = cred.get_token("https://" + la_endpoint + "/.default", tenant_id=tenant)
        case 'm365':
            stat_token[tenant]['m365token'] = cred.get_token("https://" + m365_endpoint + "/.default", tenant_id=tenant)
        case 'mde':
            stat_token[tenant]['mdetoken'] = cred.get_token("https://" + mde_endpoint + "/.default", tenant_id=tenant)

def rest_call_get(base_module:BaseModule, api:str, path:str, headers:dict={}):
    token = token_cache(base_module, api)
    url = get_endpoint(api) + path
    headers['Authorization'] = 'Bearer ' + token.token
    response = requests.get(url=url, headers=headers)

    if response.status_code >= 300:
        raise STATError(f'The API call to {api} with path {path} failed with status {response.status_code}', source_error={'status_code': int(response.status_code), 'reason': str(response.reason)})
    
    return response

def rest_call_post(base_module:BaseModule, api:str, path:str, body, headers:dict={}):
    token = token_cache(base_module, api)
    url = get_endpoint(api) + path
    headers['Authorization'] = 'Bearer ' + token.token
    response = requests.post(url=url, json=body, headers=headers)

    if response.status_code >= 300:
        raise STATError(f'The API call to {api} with path {path} failed with status {response.status_code}', source_error={'status_code': int(response.status_code), 'reason': str(response.reason)})
    
    return response

def rest_call_put(base_module:BaseModule, api:str, path:str, body, headers:dict={}):
    token = token_cache(base_module, api)
    url = get_endpoint(api) + path
    headers['Authorization'] = 'Bearer ' + token.token
    response = requests.put(url=url, json=body, headers=headers)

    if response.status_code >= 300:
        raise STATError(f'The API call to {api} with path {path} failed with status {response.status_code}', source_error={'status_code': int(response.status_code), 'reason': str(response.reason)})
    
    return response

def execute_la_query(base_module:BaseModule, query:str, lookbackindays:int):
    token = token_cache(base_module, 'la')
    url = get_endpoint('la') + '/v1/workspaces/' + base_module.WorkspaceId + '/query'
    duration = 'P' + str(lookbackindays) + 'D'
    body = {'query': query, 'timespan': duration}
    response = requests.post(url=url, json=body, headers={"Authorization": "Bearer " + token.token})
    data = json.loads(response.content)

    if response.status_code >= 300:
        raise STATError('Microsoft Sentinel KQL Query failed to execute', data)
 
    columns = data['tables'][0]['columns']
    rows = data['tables'][0]['rows']
    columnlist = []
    query_results = []

    for column in columns:
        columnlist.append(column['name'])

    for row in rows:
        query_results.append(dict(zip(columnlist,row)))

    return query_results

def execute_m365d_query(base_module:BaseModule, query:str):
    token = token_cache(base_module, 'm365')
    url = get_endpoint('m365') + '/api/advancedhunting/run'
    body = {'Query': query}
    response = requests.post(url=url, json=body, headers={"Authorization": "Bearer " + token.token})
    data = json.loads(response.content)

    if response.status_code >= 300:
        raise STATError('Microsoft 365 Advanced Hunting Query failed to execute', data)
    
    return data['Results']

def execute_mde_query(base_module:BaseModule, query:str):
    token = token_cache(base_module, 'mde')
    url = get_endpoint('mde') + '/api/advancedqueries/run'
    body = {'Query': query}
    response = requests.post(url=url, json=body, headers={"Authorization": "Bearer " + token.token})
    return json.loads(response.content)

def get_endpoint(api:str):
    match api:
        case 'arm':
            return 'https://' + arm_endpoint
        case 'msgraph':
            return 'https://' + graph_endpoint
        case 'la':
            return 'https://' + la_endpoint
        case 'm365':
            return 'https://' + m365_endpoint
        case 'mde':
            return 'https://' + mde_endpoint
    
def add_incident_comment(base_module:BaseModule, comment:str):
    token = token_cache(base_module, 'arm')
    endpoint = get_endpoint('arm')
    url = endpoint + base_module.IncidentARMId + '/comments/' + str(uuid.uuid4()) + '?api-version=2023-02-01'
    return requests.put(url=url, json={'properties': {'message': comment[:30000]}}, headers={"Authorization": "Bearer " + token.token})

def add_incident_task(base_module:BaseModule, title:str, description:str, status:str='New'):
    token = token_cache(base_module, 'arm')
    endpoint = get_endpoint('arm')
    url = endpoint + base_module.IncidentARMId + '/tasks/' + str(uuid.uuid4()) + '?api-version=2023-04-01-preview'

    if description is None or description == '':
        return requests.put(url=url, json={'properties': {'title': title, 'status': status}}, headers={"Authorization": "Bearer " + token.token})
    else:
        return requests.put(url=url, json={'properties': {'title': title, 'description': description[:3000], 'status': status}}, headers={"Authorization": "Bearer " + token.token})
    