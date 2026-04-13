from classes import BaseModule
from shared import rest
from modules import relatedalerts
import json
import os

tool_properties = json.dumps([{
    'propertyName': 'username',
    'description': 'A common separated list of UserPrincipalNames or object IDs',
    'propertyType': 'string',
    'isRequired': True
},
{
    'propertyName': 'workspace_id',
    'description': 'Log Analytics Workspace ID',
    'propertyType': 'string',
    'isRequired': False
}])

def _investigate_alerts_user_tool(context) -> str:
    """Investigate a user for related alerts."""
    base = BaseModule()
    mcp_req = json.loads(context)['arguments']
    base.WorkspaceId = mcp_req.get('workspace_id', os.getenv('WORKSPACE_ID'))
    user_list = [user.strip() for user in mcp_req.get('username', '').split(',')]
    for user in user_list:
        lookup_account(base, user)

    module_payload = {
        'BaseModuleBody': base.__dict__,
        'CheckAccountEntityMatches': True,
        'CheckIPEntityMatches': False,
        'CheckHostEntityMatches': False,
        'LookbackInDays': 14
    }
    ra_data = relatedalerts.execute_relatedalerts_module(module_payload)
    return str(ra_data.body.__dict__)

def lookup_account(base:BaseModule, id:str):
    attributes = 'userPrincipalName,id,onPremisesSecurityIdentifier,onPremisesDistinguishedName,onPremisesDomainName,onPremisesSamAccountName,onPremisesSyncEnabled,mail,city,state,country,department,jobTitle,officeLocation,accountEnabled&$expand=manager($select=userPrincipalName,mail,id)'
    user_info = json.loads(rest.rest_call_get(base, api='msgraph', path='/v1.0/users/' + id + '?$select=' + attributes).content)
    base.add_account_entity(user_info)