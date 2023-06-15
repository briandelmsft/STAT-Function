from shared import rest
from classes import BaseModule, STATError
import json
import requests

def test_get_endpoint():
    assert rest.get_endpoint('msgraph') == 'https://graph.microsoft.com'
    assert rest.get_endpoint('la') == 'https://api.loganalytics.io'
    assert rest.get_endpoint('arm') == 'https://management.azure.com'
    assert rest.get_endpoint('m365') == 'https://api.security.microsoft.com'
    assert rest.get_endpoint('mde') == 'https://api.securitycenter.microsoft.com'

def test_rest_get():
    result = rest.rest_call_get(get_base_module_object(), 'msgraph', '/v1.0/organization')
    assert result.status_code == 200

def test_execute_la_query():
    result = rest.execute_la_query(get_base_module_object(), 'SigninLogs | take 5', 7)
    assert len(result) == 5

def test_execute_m365d_query():
    result = rest.execute_m365d_query(get_base_module_object(), 'DeviceInfo | take 5')
    assert len(result) == 5

def test_execute_mde_query():
    result = rest.execute_mde_query(get_base_module_object(), 'DeviceInfo | take 5')
    assert len(result) == 5

def test_add_incident_comment():
    clean_comments()
    result = rest.add_incident_comment(get_base_module_object(), 'Test Comment')

    assert result.status_code == 201

def test_add_incident_task():
    clean_tasks()
    result = rest.add_incident_task(get_base_module_object(), 'Test Comment', 'Test')
    assert result.status_code == 201

def get_base_module_object():
    f = open('.\\tests\\basebody.json')
    base_module_body = json.load(f)
    f.close()
    base_object = BaseModule()
    base_object.load_from_input(base_module_body)
    return base_object

def clean_comments():
    base_module = get_base_module_object()
    path = base_module.IncidentARMId + '/comments?api-version=2023-05-01-preview'
    comments = json.loads(rest.rest_call_get(base_module, 'arm', path).content)
    for comment in comments['value']:
        comm_path = comment['id'] + '?api-version=2023-05-01-preview'
        rest_call_delete(base_module, 'arm', comm_path)

def clean_tasks():
    base_module = get_base_module_object()
    path = base_module.IncidentARMId + '/tasks?api-version=2023-05-01-preview'
    tasks = json.loads(rest.rest_call_get(base_module, 'arm', path).content)
    for task in tasks['value']:
        task_path = task['id'] + '?api-version=2023-05-01-preview'
        rest_call_delete(base_module, 'arm', task_path)
        
def rest_call_delete(base_module:BaseModule, api:str, path:str, headers:dict={}):
    token = rest.token_cache(base_module, api)
    url = rest.get_endpoint(api) + path
    headers['Authorization'] = 'Bearer ' + token.token
    response = requests.delete(url=url, headers=headers)

    if response.status_code >= 300:
        raise STATError(f'The API call to {api} with path {path} failed with status {response.status_code}', source_error={'status_code': int(response.status_code), 'reason': str(response.reason)})
    
    return response