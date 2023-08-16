from shared import rest
from classes import BaseModule
import json, os
import requests

def test_get_endpoint():

    mdca_endpoint = str(rest.get_endpoint('mdca'))
    if mdca_endpoint.startswith('https://') and mdca_endpoint.endswith('portal.cloudappsecurity.com'):
        mdca_valid = True
    else:
        mdca_valid = False

    assert rest.get_endpoint('msgraph') == 'https://graph.microsoft.com'
    assert rest.get_endpoint('la') == 'https://api.loganalytics.io'
    assert rest.get_endpoint('arm') == 'https://management.azure.com'
    assert rest.get_endpoint('m365') == 'https://api.security.microsoft.com'
    assert rest.get_endpoint('mde') == 'https://api.securitycenter.microsoft.com'
    assert mdca_valid == True

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

def get_base_module_object():
    base_module_body = json.loads(requests.get(url=os.getenv('BASEDATA')).content)
    base_object = BaseModule()
    base_object.load_from_input(base_module_body)
    return base_object
