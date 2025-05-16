from modules import base, exposure_device, exposure_user
from classes import Response
import json, os, requests

def test_user_exposure_module():
    exposure_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'BaseModuleBody': get_base_module_body()
    }
    exp_response:Response = exposure_user.execute_user_exposure_module(exposure_input)

    assert exp_response.statuscode == 200

def test_device_exposure_module():
    exposure_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'BaseModuleBody': get_base_module_body()
    }
    exp_response:Response = exposure_device.execute_device_exposure_module(exposure_input)

    assert exp_response.statuscode == 200

def get_base_module_body():
    base_module_body = json.loads(requests.get(url=os.getenv('BASEDATA')).content)
    return base_module_body