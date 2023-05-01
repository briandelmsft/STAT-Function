from modules import base
from classes import Response
from classes import Error
import json

def initiate_module(module_name, req_body):
    '''Call the appropriate STAT Module.'''

    if module_name == 'base':
        return_data = Response(body=base.execute_base_module(req_body))
    else:
        return_data = Response(body=Error({'Error': 'Invalid Module'}), statuscode=400)

    return return_data