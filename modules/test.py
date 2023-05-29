from classes import BaseModule, STATError
from shared import rest, data
import json

def execute_test_module (req_body):
    #base_object = BaseModule()
    #base_object.load_from_input(req_body['BaseModuleBody'])
    #test = base_object.get_ip_list()
    #test2 = base_object.get_account_id_list()
    #test3 = base_object.get_account_upn_list()
    #ip_entities = base_object.get_ip_kql_table()
    #account_entities = base_object.get_account_kql_table()

    list_data = req_body['ListData']
    item_key = req_body['Key']

    if req_body.get('SortOrder'):
        out = data.return_highest_value(list_data, item_key, req_body.get('SortOrder'))
    else:
        out = data.return_highest_value(list_data, item_key)

    test = 1

    # if req_body['AddIncidentComments']:
    #     try:
    #         test = 5 / 0
    #     except:
    #         raise STATError('Cannot divide by zero', {'error': 'division by zero error'}, 400)
    # else:
    #     test = 5 / 0

    # data.list_to_html_table(base_object.IPs)

    #query = ip_entities + account_entities + '''union ipEntities,accountEntities'''

    #results = rest.execute_la_query(base_object.WorkspaceId, query, 7)

    raise STATError(error=f'Test completed successfully: {out}')
