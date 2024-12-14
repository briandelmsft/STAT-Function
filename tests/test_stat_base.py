from modules import base
from classes import Response
import json, os, requests

def test_base_module_incident():
    base_response:Response = base.execute_base_module(get_incident_trigger_data())

    assert base_response.statuscode == 200
    assert base_response.body.AccountsCount == 2
    assert len(base_response.body.Accounts) == base_response.body.AccountsCount
    assert len(base_response.body.Domains) == base_response.body.DomainsCount
    assert len(base_response.body.FileHashes) == base_response.body.FileHashesCount
    assert len(base_response.body.Files) == base_response.body.FilesCount
    assert len(base_response.body.Hosts) == base_response.body.HostsCount
    assert len(base_response.body.IPs) == base_response.body.IPsCount
    assert len(base_response.body.URLs) == base_response.body.URLsCount
    assert len(base_response.body.OtherEntities) == base_response.body.OtherEntitiesCount


def test_base_module_alert():
    base_response:Response = base.execute_base_module(get_alert_trigger_data())

    assert base_response.statuscode == 200
    assert len(base_response.body.Accounts) == base_response.body.AccountsCount
    assert len(base_response.body.Domains) == base_response.body.DomainsCount
    assert len(base_response.body.FileHashes) == base_response.body.FileHashesCount
    assert len(base_response.body.Files) == base_response.body.FilesCount
    assert len(base_response.body.Hosts) == base_response.body.HostsCount
    assert len(base_response.body.IPs) == base_response.body.IPsCount
    assert len(base_response.body.URLs) == base_response.body.URLsCount
    assert len(base_response.body.OtherEntities) == base_response.body.OtherEntitiesCount

def get_incident_trigger_data():
    trigger_data = json.loads(requests.get(url=os.getenv('INCIDENTDATA')).content)
    return trigger_data

def get_alert_trigger_data():
    trigger_data = json.loads(requests.get(url=os.getenv('ALERTDATA')).content)
    return trigger_data