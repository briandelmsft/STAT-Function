from classes import BaseModule
from shared import rest
import json

def execute_base_module (req_body):
    global base_object
    
    base_object = BaseModule()
    base_object.load_incident_trigger(req_body)
    
    entities = req_body['object']['properties']['relatedEntities']
    enrich_ips(entities)
    enrich_accounts(entities)

    return base_object

def enrich_ips (entities):
    ip_entities = list(filter(lambda x: x['kind'].lower() == 'ip', entities))
    base_object.IPsCount = len(ip_entities)

    for ip in ip_entities:
        url = "https://management.azure.com" + base_object.SentinelRGARMId + "/providers/Microsoft.SecurityInsights/enrichment/ip/geodata/?api-version=2023-04-01-preview&ipAddress=" + ip['properties']['address']
        response = rest.rest_call_get(url)
        base_object.add_ip_entity(address=ip['properties']['address'], geo_data=json.loads(response.content), rawentity=ip['properties'])

    return

def enrich_accounts(entities):
    account_entities = list(filter(lambda x: x['kind'].lower() == 'account', entities))
    base_object.AccountsCount = len(account_entities)
