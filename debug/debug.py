from classes import Response, STATError, DebugModule, BaseModule
from shared import rest
import os, sys, json, base64
import datetime as dt

def debug_module (req_body):

    #Inputs Test, Params

    if os.getenv('DEBUG_MODE') != "1":
        raise STATError('DEBUG_MODE environment variable must be set to 1 to run this module')

    debug_out = DebugModule(req_body)

    match debug_out.Test.lower():
        case 'token':
            default_debug(debug_out)
            token_debug(debug_out)
        case 'rest':
            default_debug(debug_out)
            rest_debug(debug_out)
        case 'rbac':
            default_debug(debug_out)
            token_debug(debug_out)
            rbac_debug(debug_out)
        case 'exception':
            exception_debug(debug_out)
        case _:
            default_debug(debug_out)

    return Response(debug_out)

def default_debug(debug_out:DebugModule):
    debug_out.GraphEndpoint = os.getenv('GRAPH_ENDPOINT')
    debug_out.ARMEndpoint = os.getenv('ARM_ENDPOINT')
    debug_out.LAEndpoint = os.getenv('LOGANALYTICS_ENDPOINT')
    debug_out.M365Endpoint = os.getenv('M365_ENDPOINT')
    debug_out.MDEEndpoint = os.getenv('MDE_ENDPOINT')
    debug_out.MDCAEndpoint = os.getenv('MDCA_ENDPOINT')
    debug_out.TenantId = os.getenv('AZURE_TENANT_ID')
    debug_out.KVEndpoint = os.getenv('KEYVAULT_ENDPOINT')
    debug_out.KVSecretName = os.getenv('KEYVAULT_SECRET_NAME')
    debug_out.KVClientId = os.getenv('KEYVAULT_CLIENT_ID')
    debug_out.PackageUrl = os.getenv('WEBSITE_RUN_FROM_PACKAGE')
    debug_out.PythonVersion = sys.version

def token_debug(debug_out:DebugModule):
    base_module = BaseModule()
    base_module.MultiTenantConfig = debug_out.Params.get('MultiTenantConfig', {})
    token_type = debug_out.Params.get('TokenType', 'msgraph')
    token = rest.token_cache(base_module, token_type)

    content = token.token.split('.')[1] + '=='
    b64_decoded = base64.urlsafe_b64decode(content)
    decoded_token = json.loads(b64_decoded) 

    debug_out.Audience = decoded_token.get('aud')
    debug_out.Issuer = decoded_token.get('iss')
    debug_out.Expiration = dt.datetime.fromtimestamp(token.expires_on).isoformat()
    debug_out.AppDisplayName = decoded_token.get('app_displayname')
    debug_out.AppId = decoded_token.get('appid')
    debug_out.ObjectId = decoded_token.get('oid')
    debug_out.Idp = decoded_token.get('idp')
    debug_out.AppRoles = decoded_token.get('roles')
    debug_out.TenantId = decoded_token.get('tid')

def rest_debug(debug_out:DebugModule):
    base_module = BaseModule()
    base_module.MultiTenantConfig = debug_out.Params.get('MultiTenantConfig', {})
    token_type = debug_out.Params.get('TokenType', 'msgraph')
    rest_call_method = debug_out.Params.get('Method').lower()
    rest_call_path = debug_out.Params.get('Path')
    rest_call_body = debug_out.Params.get('Body')

    match rest_call_method:
        case 'get':
            response = rest.rest_call_get(base_module, token_type, rest_call_path)
            parse_response(debug_out, response)
        case 'put':
            response = rest.rest_call_put(base_module, token_type, rest_call_path, rest_call_body)
            parse_response(debug_out, response)
        case 'post':
            response = rest.rest_call_post(base_module, token_type, rest_call_path, rest_call_body)
            parse_response(debug_out, response)
        case _:
            raise STATError(error=f'Invalid Method sent to debug module: {rest_call_method}.', status_code=400)
        
def rbac_debug(debug_out:DebugModule):
    base_module = BaseModule()
    base_module.MultiTenantConfig = debug_out.Params.get('MultiTenantConfig', {})
    token_type = 'arm'
    sub_id = debug_out.Params.get('SubscriptionId')
    rg_name = debug_out.Params.get('RGName')
    scope = f'/subscriptions/{sub_id}/resourceGroups/{rg_name}'
    rbac_info = json.loads(rest.rest_call_get(base_module, token_type, f"{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()+and+assignedTo('{debug_out.ObjectId}')").content)

    debug_out.RBACAssignedRoles = []
    debug_out.RBACAssignedRoleIds = []

    for role in rbac_info.get('value'):
        role_id = role['properties']['roleDefinitionId']
        result = json.loads(rest.rest_call_get(base_module, token_type, f"{role_id}?api-version=2022-04-01").content)
        debug_out.RBACAssignedRoles.append(result['properties']['roleName'])
        debug_out.RBACAssignedRoleIds.append(result['name'])


def exception_debug(debug_out:DebugModule):
    exception_type = debug_out.Params.get('ExceptionType', 'STATError')
    match exception_type:
        case 'STATError':
            raise STATError('STATError raised from debug module.')
        case 'Exception':
            raise Exception()
        case 'BaseException':
            raise BaseException()
        case _:
            raise STATError(error=f'Invalid exception type sent to debug module: {exception_type}.', status_code=400)
        
def parse_response(debug_out:DebugModule, response):
    try:
        debug_out.JSONContent = json.loads(response.content)
    except:
        debug_out.JSONContent = {'Status': 'Failed to load JSON content'}

    debug_out.StatusCode = response.status_code
    debug_out.Url = response.url
    debug_out.TextContent = response.text