from modules import kql
from classes import Response
import json, os, requests

def test_kql_sentinel():
    kql_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'KQLQuery': 'SigninLogs | take 5 | project UserPrincipalName',
        'RunQueryAgainst': 'Sentinel',
        'QueryDescription': 'Test Query',
        'LookbackInDays': 7,
        'BaseModuleBody': get_base_module_body()
    }
    kql_response:Response = kql.execute_kql_module(kql_input)

    assert kql_response.statuscode == 200
    assert kql_response.body.ResultsCount == 5

def test_kql_sentinel_search():
    kql_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'Endpoint': 'search',
        'KQLQuery': 'CommonSecurityLogAux_CL | take 5',
        'RunQueryAgainst': 'Sentinel',
        'QueryDescription': 'Test Query',
        'LookbackInDays': 7,
        'BaseModuleBody': get_base_module_body()
    }
    kql_response:Response = kql.execute_kql_module(kql_input)

    assert kql_response.statuscode == 200
    assert kql_response.body.ResultsCount == 5

def test_kql_m365():
    kql_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'KQLQuery': 'DeviceInfo | take 5 | project DeviceId',
        'RunQueryAgainst': 'M365',
        'QueryDescription': 'Test Query',
        'LookbackInDays': 7,
        'BaseModuleBody': get_base_module_body()
    }
    kql_response:Response = kql.execute_kql_module(kql_input)

    assert kql_response.statuscode == 200
    assert kql_response.body.ResultsCount == 5

def get_base_module_body():
    base_module_body = json.loads(requests.get(url=os.getenv('BASEDATA')).content)
    return base_module_body