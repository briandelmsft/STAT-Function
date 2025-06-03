from shared import rest
from classes import BaseModule, STATError, STATNotFound, STATTooManyRequests
import json, os
import requests
import pytest

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

def test_rest_response():
    response_429 = requests.Response()
    response_429.status_code = 429
    response_404 = requests.Response()
    response_404.status_code = 404
    response_401 = requests.Response()
    response_401.status_code = 401
    response_200 = requests.Response()
    response_200.status_code = 200

    with pytest.raises(STATTooManyRequests):
        rest.check_rest_response(response_429, 'test', 'test')

    with pytest.raises(STATNotFound):
        rest.check_rest_response(response_404, 'test', 'test')

    with pytest.raises(STATError):
        rest.check_rest_response(response_401, 'test', 'test')

    assert None is rest.check_rest_response(response_200, 'test', 'test')


def get_base_module_object():
    base_module_body = json.loads(requests.get(url=os.getenv('BASEDATA')).content)
    base_object = BaseModule()
    base_object.load_from_input(base_module_body)
    return base_object
