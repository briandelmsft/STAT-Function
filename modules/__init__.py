import logging
import json
import azure.functions as func
from classes import STATError
from shared import coordinator

def main(req: func.HttpRequest, context: func.Context) -> func.HttpResponse:
    logging.debug('STAT Function started processing a request.')
    module_name = req.route_params.get('modulename')

    try:
        req_body = req.get_json()
    except ValueError:
        logging.error('Could not parse body')
        return func.HttpResponse(json.dumps({'Error': 'Invalid Request Body', 'InvocationId': context.invocation_id}), status_code=400, mimetype='applicaiton/json')

    try:
        return_data = coordinator.initiate_module(module_name=module_name, req_body=req_body)
    except STATError as e:
        return func.HttpResponse(json.dumps({'Error': e.error, 'InvocationId': context.invocation_id, 'SourceError': e.source_error}), status_code=e.status_code, mimetype='applicaiton/json')
    except:
        return func.HttpResponse(json.dumps({'Error': 'Module processing failed, an unknown exception has occurred.', 'InvocationId': context.invocation_id}), status_code=400, mimetype='applicaiton/json')

    return func.HttpResponse(body=json.dumps(return_data.body.__dict__), status_code=return_data.statuscode, mimetype=return_data.contenttype)
