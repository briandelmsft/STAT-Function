from modules import aadrisks
from classes import Response
import json, os, requests

def test_aad_risks():
    aad_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'LookbackInDays': 14,
        'BaseModuleBody': get_base_module_body()
    }
    aad_response:Response = aadrisks.execute_aadrisks_module(aad_input)

    assert aad_response.statuscode == 200

def test_aad_risks_custom_options():
    aad_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'LookbackInDays': 14,
        'MFAFailureLookup': False,
        'MFAFraudLookup': False,
        'SuspiciousActivityReportLookup': False,
        'BaseModuleBody': get_base_module_body()
    }
    aad_response:Response = aadrisks.execute_aadrisks_module(aad_input)

    assert aad_response.statuscode == 200

def get_base_module_body():
    base_module_body = json.loads(requests.get(url=os.getenv('BASEDATA')).content)
    return base_module_body