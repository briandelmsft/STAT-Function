from classes import BaseModule, Response, OOFModule
from shared import rest, data
import json

def execute_oof_module (req_body):

    #Inputs AddIncidentComments, AddIncidentTask, Entities, IncidentTaskInstructions, KQLQuery, LookbackInDays, QueryDescription, RunQueryAgainst

    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])

    oof = OOFModule()

    for account in base_object.Accounts:
        upn = account.get('userPrincipalName')
        if upn:
            path = f'/v1.0/users/{upn}/mailboxSettings/automaticRepliesSetting'
            try:
                results = rest.rest_call_get(api='msgraph', path=path)
                json.loads(results.content)
            except:
                oof.UsersUnknown += 1
        else:
            oof.UsersUnknown += 1

    # if req_body.get('AddIncidentComments', True):
        
    #     html_table = data.list_to_html_table(results)
    #     if req_body.get('QueryDescription'):
    #         query_description = req_body.get('QueryDescription') + '<p>'
    #     else:
    #         query_description = ''

    #     comment = f'''{query_description}A total of {kql_object.ResultsCount} records were found in the {req_body.get('RunQueryAgainst')} search.<br>{html_table}'''
    #     comment_result = rest.add_incident_comment(base_object.IncidentARMId, comment)

    # if req_body.get('AddIncidentTask', False) and kql_object.ResultsFound:
    #     task_result = rest.add_incident_task(base_object.IncidentARMId, req_body.get('QueryDescription', 'Review KQL Query Results'), req_body.get('IncidentTaskInstructions'))

    return Response(oof)