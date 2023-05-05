from modules import base, kql, watchlist, test
from classes import Response, Error

def initiate_module(module_name, req_body):
    '''Call the appropriate STAT Module.'''

    if module_name == 'base':
        return_data = base.execute_base_module(req_body)
    elif module_name == 'kql':
        return_data = kql.execute_kql_module(req_body)
    elif module_name == 'scoring':
        return_data = Response(body=Error({'Error': 'Module has not yet been migrated to STAT v2'}), statuscode=400)
    elif module_name == 'watchlist':
        return_data = watchlist.execute_watchlist_module(req_body)
    elif module_name == 'relatedalerts':
        return_data = Response(body=Error({'Error': 'Module has not yet been migrated to STAT v2'}), statuscode=400)
    elif module_name == 'threatintel':
        return_data = Response(body=Error({'Error': 'Module has not yet been migrated to STAT v2'}), statuscode=400)
    elif module_name == 'mcas':
        return_data = Response(body=Error({'Error': 'Module has not yet been migrated to STAT v2'}), statuscode=400)
    elif module_name == 'mde':
        return_data = Response(body=Error({'Error': 'Module has not yet been migrated to STAT v2'}), statuscode=400)
    elif module_name == 'file':
        return_data = Response(body=Error({'Error': 'Module has not yet been migrated to STAT v2'}), statuscode=400)
    elif module_name == 'aadrisks':
        return_data = Response(body=Error({'Error': 'Module has not yet been migrated to STAT v2'}), statuscode=400)
    elif module_name == 'ueba':
        return_data = Response(body=Error({'Error': 'Module has not yet been migrated to STAT v2'}), statuscode=400)
    elif module_name == 'oofmodule':
        return_data = Response(body=Error({'Error': 'Module has not yet been migrated to STAT v2'}), statuscode=400)
    elif module_name == 'runplaybook':
        return_data = Response(body=Error({'Error': 'Module has not yet been migrated to STAT v2'}), statuscode=400)
    elif module_name == 'test':
        return_data = Response(body=test.execute_test_module(req_body))
    else:
        return_data = Response(body=Error({'Error': 'Invalid Module'}), statuscode=400)

    return return_data