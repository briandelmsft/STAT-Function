from modules import relatedalerts
from classes import Response
import json, os, requests

def test_related_alerts():
    alerts_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'CheckAccountEntityMatches': True,
        'CheckHostEntityMatches': True,
        'CheckIPEntityMatches': True,
        'AlertKQLFilter': None,
        'IncidentTaskInstructions': "",
        'LookbackInDays': 20,
        'BaseModuleBody': get_base_module_body(),
    }
    alerts_response:Response = relatedalerts.execute_relatedalerts_module(alerts_input)

    assert alerts_response.statuscode == 200
    assert alerts_response.body.RelatedAlertsFound == True
    assert alerts_response.body.RelatedAccountAlertsFound == True

def test_related_alerts_custom_options():
    alerts_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'CheckAccountEntityMatches': False,
        'CheckHostEntityMatches': False,
        'CheckIPEntityMatches': False,
        'AlertKQLFilter': '| where 1 == 1',
        'IncidentTaskInstructions': "",
        'LookbackInDays': 20,
        'BaseModuleBody': get_base_module_body(),
    }
    alerts_response:Response = relatedalerts.execute_relatedalerts_module(alerts_input)

    assert alerts_response.statuscode == 200
    assert alerts_response.body.RelatedAlertsFound == False
    assert alerts_response.body.RelatedAccountAlertsFound == False

def get_base_module_body():
    base_module_body = json.loads(requests.get(url=os.getenv('BASEDATA')).content)
    return base_module_body