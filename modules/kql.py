from classes import BaseModule, Response, KQLModule
from shared import rest
import json

def execute_kql_module (req_body):

    #Inputs AddIncidentComments, AddIncidentTask, Entities, IncidentTaskInstructions, KQLQuery, LookbackInDays, QueryDescription, RunQueryAgainst

    base_object = BaseModule()
    base_object.load_from_input(req_body['Entities'])

    kql_object = KQLModule()

    arm_id = f'let incidentArmId = "{base_object.IncidentARMId}";\n'
    ip_entities = base_object.get_ip_kql_table()
    account_entities = base_object.get_account_kql_table()
    host_entities = base_object.get_host_kql_table()

    query = arm_id + ip_entities + account_entities + host_entities + req_body['KQLQuery']

    results = rest.execute_la_query(base_object.WorkspaceId, query, req_body['LookbackInDays'])

    kql_object.DetailedResults = results
    kql_object.ResultsCount = len(results)
    kql_object.ResultsFound = bool(results)

    return Response(kql_object)