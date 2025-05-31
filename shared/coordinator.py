from modules import base, kql, watchlist, ti, relatedalerts, scoring, ueba, playbook, exchange, aadrisks, file, createincident, mdca, mde, exposure_device, exposure_user
from classes import STATError

def initiate_module(module_name, req_body):
    """Call the appropriate STAT module based on the module name.
    
    This function serves as the main coordinator for routing requests to the
    appropriate STAT module based on the provided module name.
    
    Args:
        module_name (str): Name of the module to execute. Valid values include:
            'base', 'kql', 'scoring', 'watchlist', 'relatedalerts', 'threatintel',
            'mdca', 'mde', 'file', 'aadrisks', 'deviceexposure', 'userexposure',
            'ueba', 'oofmodule', 'exchangemodule', 'runplaybook', 'createincident'.
        req_body (dict): Request body containing module-specific input data.
    
    Returns:
        Response: Response object from the executed module.
        
    Raises:
        STATError: If the module name is invalid or not supported.
    """

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
        case 'mdca': 
            return_data = mdca.execute_mdca_module(req_body)
        case 'mde':
            return_data = mde.execute_mde_module(req_body)
        case 'file':
            return_data = file.execute_file_module(req_body)
        case 'aadrisks':
            return_data = aadrisks.execute_aadrisks_module(req_body)
        case 'deviceexposure':
            return_data = exposure_device.execute_device_exposure_module(req_body)
        case 'userexposure':
            return_data = exposure_user.execute_user_exposure_module(req_body)
        case 'ueba':
            return_data = ueba.execute_ueba_module(req_body)
        case 'oofmodule' | 'exchangemodule':
            return_data = exchange.execute_exchange_module(req_body)
        case 'runplaybook':
            return_data = playbook.execute_playbook_module(req_body)
        case 'createincident':
            return_data = createincident.execute_create_incident(req_body)
        case _:
            raise STATError(error=f'Invalid module name: {module_name}.', status_code=400)

    return return_data
