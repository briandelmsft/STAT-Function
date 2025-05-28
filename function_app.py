import logging
import traceback as tb
import json
import uuid
import azure.functions as func
from classes import STATError
from shared import coordinator, data
from debug import debug

# Create the function app instance
app = func.FunctionApp()

@app.function_name("modules_endpoint")
@app.route(
    route="modules/{modulename}",
    methods=["GET", "POST"],
    auth_level=func.AuthLevel.FUNCTION
)
def modules_v2(req: func.HttpRequest) -> func.HttpResponse:
    """HTTP trigger function for processing various STAT modules"""
    logging.debug('STAT Function started processing a request.')
    invocation_id = str(uuid.uuid4())
    module_name = req.route_params.get('modulename')

    try:
        req_body = req.get_json()
    except ValueError:
        logging.error(msg={'Error': 'Invalid Request Body', 'InvocationId': invocation_id})
        return func.HttpResponse(
            json.dumps({'Error': 'Invalid Request Body', 'InvocationId': invocation_id}), 
            status_code=400, 
            mimetype='application/json'
        )

    try:
        return_data = coordinator.initiate_module(module_name=module_name, req_body=req_body)
    except STATError as e:
        trace = tb.format_exception(None, e, e.__traceback__)
        logging.error(msg={'Error': e.error, 'SourceError': e.source_error, 'InvocationId': invocation_id}, exc_info=True)
        return func.HttpResponse(
            json.dumps({
                'Error': e.error, 
                'InvocationId': invocation_id, 
                'SourceError': e.source_error, 
                'STATVersion': data.get_current_version(), 
                'Traceback': trace
            }), 
            status_code=e.status_code, 
            mimetype='application/json'
        )
    except Exception as e:
        trace = tb.format_exception(None, e, e.__traceback__)
        logging.error(e, exc_info=True)
        return func.HttpResponse(
            json.dumps({
                'Error': 'Module processing failed, an unknown exception has occurred.', 
                'InvocationId': invocation_id, 
                'STATVersion': data.get_current_version(), 
                'Traceback': trace
            }), 
            status_code=400, 
            mimetype='application/json'
        )
    except:
        logging.error(msg={'Error': 'Module processing failed, an unknown exception has occurred.', 'InvocationId': invocation_id}, exc_info=True)
        return func.HttpResponse(
            json.dumps({
                'Error': 'Module processing failed, an unknown exception has occurred.', 
                'InvocationId': invocation_id, 
                'STATVersion': data.get_current_version()
            }), 
            status_code=400, 
            mimetype='application/json'
        )
    
    return func.HttpResponse(
        body=json.dumps(return_data.body.__dict__), 
        status_code=return_data.statuscode, 
        mimetype=return_data.contenttype
    )


@app.function_name("debug_endpoint")
@app.route(
    route="debug",
    methods=["GET", "POST"],
    auth_level=func.AuthLevel.FUNCTION
)
def debug_v2(req: func.HttpRequest) -> func.HttpResponse:
    """HTTP trigger function for debug functionality"""
    logging.debug('STAT Debug Function started processing a request.')
    invocation_id = str(uuid.uuid4())

    try:
        req_body = req.get_json()
    except ValueError:
        logging.error(msg={'Error': 'Invalid Request Body', 'InvocationId': invocation_id})
        return func.HttpResponse(
            json.dumps({'Error': 'Invalid Request Body', 'InvocationId': invocation_id}), 
            status_code=400, 
            mimetype='application/json'
        )

    try:
        return_data = debug.debug_module(req_body)
    except STATError as e:
        trace = tb.format_exception(None, e, e.__traceback__)
        logging.error(msg={'Error': e.error, 'SourceError': e.source_error, 'InvocationId': invocation_id}, exc_info=True)
        return func.HttpResponse(
            json.dumps({
                'Error': e.error, 
                'InvocationId': invocation_id, 
                'SourceError': e.source_error, 
                'STATVersion': data.get_current_version(), 
                'Traceback': trace
            }), 
            status_code=e.status_code, 
            mimetype='application/json'
        )
    except Exception as e:
        trace = tb.format_exception(None, e, e.__traceback__)
        logging.error(e, exc_info=True)
        return func.HttpResponse(
            json.dumps({
                'Error': 'Module processing failed, an unknown exception has occurred.', 
                'InvocationId': invocation_id, 
                'STATVersion': data.get_current_version(), 
                'Traceback': trace
            }), 
            status_code=400, 
            mimetype='application/json'
        )
    except:
        logging.error(msg={'Error': 'Module processing failed, an unknown exception has occurred.', 'InvocationId': invocation_id}, exc_info=True)
        return func.HttpResponse(
            json.dumps({
                'Error': 'Module processing failed, an unknown exception has occurred.', 
                'InvocationId': invocation_id, 
                'STATVersion': data.get_current_version()
            }), 
            status_code=400, 
            mimetype='application/json'
        )
    
    return func.HttpResponse(
        body=json.dumps(return_data.body.__dict__), 
        status_code=return_data.statuscode, 
        mimetype=return_data.contenttype
    )