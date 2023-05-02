from classes import BaseModule, Error
import json

def execute_test_module (req_body):
    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])
    test = base_object.get_ip_list()
    test2 = base_object.get_account_id_list()
    test3 = base_object.get_account_upn_list()
    return Error({'Error': 'Test completed successfully'})