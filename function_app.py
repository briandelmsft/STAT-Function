import azure.functions as func
import logging
import json
import traceback as tb
from classes import STATError
from shared import data, coordinator
from mcp import ti_ip, ra_ip, ra_user, kql
from debug import debug

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

#IP TI MCP Tool
@app.mcp_tool_trigger(
    arg_name="context",
    tool_name="ip_address_ti",
    description="Investigate an IP address for threat intel matches.",
    tool_properties=ti_ip.tool_properties
)
def investigate_ti_ip_tool(context) -> str:
    """Investigate an IP address for threat intel matches."""
    return ti_ip._investigate_ti_ip_tool(context)

#IP Related Alerts MCP Tool
@app.mcp_tool_trigger(
    arg_name="context",
    tool_name="ip_address_related_alerts",
    description="Investigate an IP address for related alerts.",
    tool_properties=ra_ip.tool_properties
)
def investigate_alerts_ip_tool(context) -> str:
    """Investigate an IP address for related alerts."""
    return ra_ip._investigate_alerts_ip_tool(context)

#User Related Alerts MCP Tool
@app.mcp_tool_trigger(
    arg_name="context",
    tool_name="user_related_alerts",
    description="Investigate a user account for related alerts.",
    tool_properties=ra_user.tool_properties
)
def investigate_alerts_user_tool(context) -> str:
    """Investigate a user account for related alerts."""
    return ra_user._investigate_alerts_user_tool(context)

#KQL Query MCP Tool
@app.mcp_tool_trigger(
    arg_name="context",
    tool_name="kql_query",
    description="Execute a KQL query against log analytics.",
    tool_properties=kql.tool_properties
)
def execute_kql_query_tool(context) -> str:
    """Execute a KQL query."""
    return kql._execute_kql_tool(context)

#STAT Core Modules
@app.route(route="modules/{modulename}")
def module_handler(req: func.HttpRequest, context: func.Context) -> func.HttpResponse:

    logging.debug('STAT Function started processing a request.')
    module_name = req.route_params.get('modulename')

    try:
        req_body = req.get_json()
    except ValueError:
        logging.error(msg={'Error': 'Invalid Request Body', 'InvocationId': context.invocation_id})
        return func.HttpResponse(json.dumps({'Error': 'Invalid Request Body', 'InvocationId': context.invocation_id}), status_code=400, mimetype='application/json')

    try:
        return_data = coordinator.initiate_module(module_name=module_name, req_body=req_body)
    except STATError as e:
        trace = tb.format_exception(None, e, e.__traceback__)
        logging.error(msg={'Error': e.error, 'SourceError': e.source_error, 'InvocationId': context.invocation_id}, exc_info=True)
        return func.HttpResponse(json.dumps({'Error': e.error, 'InvocationId': context.invocation_id, 'SourceError': e.source_error, 'STATVersion': data.get_current_version(), 'Traceback': trace}), status_code=e.status_code, mimetype='application/json')
    except Exception as e:
        trace = tb.format_exception(None, e, e.__traceback__)
        logging.error(e, exc_info=True)
        return func.HttpResponse(json.dumps({'Error': 'Module processing failed, an unknown exception has occurred.', 'InvocationId': context.invocation_id, 'STATVersion': data.get_current_version(), 'Traceback': trace}), status_code=400, mimetype='application/json')
    except:
        logging.error(msg={'Error': 'Module processing failed, an unknown exception has occurred.', 'InvocationId': context.invocation_id}, exc_info=True)
        return func.HttpResponse(json.dumps({'Error': 'Module processing failed, an unknown exception has occurred.', 'InvocationId': context.invocation_id, 'STATVersion': data.get_current_version()}), status_code=400, mimetype='application/json')
    
    return func.HttpResponse(body=json.dumps(return_data.body.__dict__), status_code=return_data.statuscode, mimetype=return_data.contenttype)

#STAT Debug Module
@app.route(route="debug")
def debug_handler(req: func.HttpRequest) -> func.HttpResponse:

    logging.debug('STAT Debug Function started processing a request.')

    try:
        req_body = req.get_json()
    except ValueError:
        logging.error(msg={'Error': 'Invalid Request Body', 'InvocationId': 'invocationid'})
        return func.HttpResponse(json.dumps({'Error': 'Invalid Request Body', 'InvocationId': 'invocationid'}), status_code=400, mimetype='application/json')

    try:
        return_data = debug.debug_module(req_body)
    except STATError as e:
        trace = tb.format_exception(None, e, e.__traceback__)
        logging.error(msg={'Error': e.error, 'SourceError': e.source_error, 'InvocationId': 'invocationid'}, exc_info=True)
        return func.HttpResponse(json.dumps({'Error': e.error, 'InvocationId': 'invocationid', 'SourceError': e.source_error, 'STATVersion': data.get_current_version(), 'Traceback': trace}), status_code=e.status_code, mimetype='application/json')
    except Exception as e:
        trace = tb.format_exception(None, e, e.__traceback__)
        logging.error(e, exc_info=True)
        return func.HttpResponse(json.dumps({'Error': 'Module processing failed, an unknown exception has occurred.', 'InvocationId': 'invocationid', 'STATVersion': data.get_current_version(), 'Traceback': trace}), status_code=400, mimetype='application/json')
    except:
        logging.error(msg={'Error': 'Module processing failed, an unknown exception has occurred.', 'InvocationId': 'invocationid'}, exc_info=True)
        return func.HttpResponse(json.dumps({'Error': 'Module processing failed, an unknown exception has occurred.', 'InvocationId': 'invocationid', 'STATVersion': data.get_current_version()}), status_code=400, mimetype='application/json')
    
    return func.HttpResponse(body=json.dumps(return_data.body.__dict__), status_code=return_data.statuscode, mimetype=return_data.contenttype)