import logging
import json
import azure.functions as func
from shared import coordinator

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.debug('STAT Function started processing a request.')
    module_name = req.route_params.get('modulename')

    try:
        req_body = req.get_json()
    except ValueError:
        logging.error('Could not parse body')
        return func.HttpResponse(json.dumps({'Error': 'Invalid Request Body'}), status_code=400)

    try:
        return_data = coordinator.initiate_module(module_name=module_name, req_body=req_body)
    except:
        return func.HttpResponse(json.dumps({'Error': 'Module processing failed'}), status_code=400)

    return func.HttpResponse(body=json.dumps(return_data.body.__dict__), status_code=return_data.statuscode, mimetype=return_data.contenttype)
