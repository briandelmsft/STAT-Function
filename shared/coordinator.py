from modules import base, kql, test
from classes import Response, Error

def initiate_module(module_name, req_body):
    '''Call the appropriate STAT Module.'''

    if module_name == 'base':
        return_data = base.execute_base_module(req_body)
    elif module_name == 'kql':
        return_data = kql.execute_kql_module(req_body)
    elif module_name == 'test':
        return_data = Response(body=test.execute_test_module(req_body))
    else:
        return_data = Response(body=Error({'Error': 'Invalid Module'}), statuscode=400)

    return return_data