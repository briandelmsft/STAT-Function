from modules import base, kql, watchlist, ti, relatedalerts, scoring, ueba, playbook, oof, aadrisks, test
from classes import Response, STATError

def initiate_module(module_name, req_body):
    '''Call the appropriate STAT Module.'''

    if module_name == 'base':
        return_data = base.execute_base_module(req_body)
    elif module_name == 'kql':
        return_data = kql.execute_kql_module(req_body)
    elif module_name == 'scoring':
        return_data = scoring.execute_scoring_module(req_body)
    elif module_name == 'watchlist':
        return_data = watchlist.execute_watchlist_module(req_body)
    elif module_name == 'relatedalerts':
        return_data = relatedalerts.execute_relatedalerts_module(req_body)
    elif module_name == 'threatintel':
        return_data = ti.execute_ti_module(req_body)
    elif module_name == 'mcas':
        raise STATError(error='MDCA Module has not yet been migrated to STAT v2', status_code=400)
    elif module_name == 'mde':
        raise STATError(error='MDE Module has not yet been migrated to STAT v2', status_code=400)
    elif module_name == 'file':
        raise STATError(error='File Module has not yet been migrated to STAT v2', status_code=400)
    elif module_name == 'aadrisks':
        return_data = aadrisks.execute_aadrisks_module(req_body)
    elif module_name == 'ueba':
        return_data = ueba.execute_ueba_module(req_body)
    elif module_name == 'oofmodule':
        return_data = oof.execute_oof_module(req_body)
    elif module_name == 'runplaybook':
        return_data = playbook.execute_playbook_module(req_body)
    elif module_name == 'test':
        return_data = Response(body=test.execute_test_module(req_body))
    else:
        raise STATError(error=f'Invalid module name: {module_name}.', status_code=400)

    return return_data