from modules import ti
from classes import Response, STATError
import json, os, requests
import pytest

def test_threat_intel():
    ti_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'IncidentTaskInstructions': '',
        'BaseModuleBody': get_base_module_body(),
    }
    ti_response:Response = ti.execute_ti_module(ti_input)

    assert ti_response.statuscode == 200
    assert ti_response.body.AnyTIFound == True
    assert ti_response.body.IPTIFound == True

def test_threat_intel_custom_options():
    ti_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'CheckDomains': False,
        'CheckFileHashes': False,
        'CheckIPs': False,
        'CheckURLs': False,
        'IncidentTaskInstructions': '',
        'BaseModuleBody': get_base_module_body(),
    }

    with pytest.raises(STATError):
        ti_response:Response = ti.execute_ti_module(ti_input)

def test_threat_intel_custom_options2():
    ti_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'CheckDomains': False,
        'CheckFileHashes': False,
        'CheckIPs': False,
        'CheckURLs': True,
        'IncidentTaskInstructions': '',
        'BaseModuleBody': get_base_module_body(),
    }

    ti_response:Response = ti.execute_ti_module(ti_input)

    assert ti_response.statuscode == 200
    assert ti_response.body.AnyTIFound == False
    assert ti_response.body.IPTIFound == False

def get_base_module_body():
    base_module_body = json.loads(requests.get(url=os.getenv('BASEDATA')).content)
    return base_module_body