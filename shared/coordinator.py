from modules import base, kql, watchlist, ti, relatedalerts, scoring, ueba, playbook, oof, aadrisks, createincident, test
from classes import Response, STATError

def initiate_module(module_name, req_body):
    '''Call the appropriate STAT Module.'''

    match module_name:
        case 'base':
            return_data = base.execute_base_module(req_body)
        case 'kql':
            return_data = kql.execute_kql_module(req_body)
        case 'scoring':
            return_data = scoring.execute_scoring_module(req_body)
        case 'watchlist':
            return_data = watchlist.execute_watchlist_module(req_body)
        case 'relatedalerts':
            return_data = relatedalerts.execute_relatedalerts_module(req_body)
        case 'threatintel':
            return_data = ti.execute_ti_module(req_body)
        case 'mcas':
            raise STATError(error='MDCA Module has not yet been migrated to STAT v2', status_code=400)
        case 'mde':
            raise STATError(error='MDE Module has not yet been migrated to STAT v2', status_code=400)
        case 'file':
            raise STATError(error='File Module has not yet been migrated to STAT v2', status_code=400)
        case 'aadrisks':
            return_data = aadrisks.execute_aadrisks_module(req_body)
        case 'ueba':
            return_data = ueba.execute_ueba_module(req_body)
        case 'oofmodule':
            return_data = oof.execute_oof_module(req_body)
        case 'runplaybook':
            return_data = playbook.execute_playbook_module(req_body)
        case 'createincident':
            return_data = createincident.execute_create_incident(req_body)
        case 'test':
            return_data = Response(body=test.execute_test_module(req_body))
        case _:
            raise STATError(error=f'Invalid module name: {module_name}.', status_code=400)

    return return_data
