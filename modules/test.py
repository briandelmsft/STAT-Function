from classes import BaseModule, Error
from shared import rest
import json

def execute_test_module (req_body):
    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])
    test = base_object.get_ip_list()
    test2 = base_object.get_account_id_list()
    test3 = base_object.get_account_upn_list()

    testvar = 5
    query = f'''SigninLogs
    | distinct UserPrincipalName, AppDisplayName, IPAddress
    | take {testvar}
    '''

    rest.execute_la_query(base_object.WorkspaceId, query, 7)


    return Error({'Error': 'Test completed successfully'})