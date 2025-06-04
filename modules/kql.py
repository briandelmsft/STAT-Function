from classes import BaseModule, Response, KQLModule
from shared import rest, data

def execute_kql_module (req_body):

    #Inputs AddIncidentComments, AddIncidentTask, Entities, IncidentTaskInstructions, KQLQuery, LookbackInDays, QueryDescription, RunQueryAgainst

    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])
    endpoint = req_body.get('Endpoint', 'query').lower()

    kql_object = KQLModule()

    arm_id = f'let incidentArmId = "{base_object.IncidentARMId}";\n'
    ip_entities = base_object.get_ip_kql_table()
    account_entities = base_object.get_account_kql_table(include_unsynced=True)
    host_entities = base_object.get_host_kql_table()
    mail_entities = base_object.get_mail_kql_table()

    query = arm_id + ip_entities + account_entities + host_entities + mail_entities + req_body['KQLQuery']

    if req_body.get('RunQueryAgainst') == 'M365':
        results = rest.execute_m365d_query(base_object, query)
    else:
        results = rest.execute_la_query(base_object, query, req_body['LookbackInDays'], endpoint)

    kql_object.DetailedResults = results
    kql_object.ResultsCount = len(results)
    kql_object.ResultsFound = bool(results)

    if req_body.get('AddIncidentComments', True) and base_object.IncidentAvailable:
        
        html_table = data.list_to_html_table(results, index=True)
        if req_body.get('QueryDescription'):
            query_description = req_body.get('QueryDescription') + '<p>'
        else:
            query_description = ''

        comment = f'''{query_description}A total of {kql_object.ResultsCount} records were found in the {req_body.get('RunQueryAgainst')} search.<br>{html_table}'''
        comment_result = rest.add_incident_comment(base_object, comment)

    if req_body.get('AddIncidentTask', False) and kql_object.ResultsFound and base_object.IncidentAvailable:
        task_result = rest.add_incident_task(base_object, req_body.get('QueryDescription', 'Review KQL Query Results'), req_body.get('IncidentTaskInstructions'))

    return Response(kql_object)