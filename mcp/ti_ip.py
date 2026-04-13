from classes import BaseModule
from modules import ti
import json
import os

tool_properties = json.dumps([{
    'propertyName': 'ip_address',
    'description': 'A common separated list of IP addresses',
    'propertyType': 'string',
    'isRequired': True
},
{
    'propertyName': 'workspace_id',
    'description': 'Log Analytics Workspace ID',
    'propertyType': 'string',
    'isRequired': False
}])

def _investigate_ti_ip_tool(context) -> str:
    base = BaseModule()
    mcp_req = json.loads(context)['arguments']
    base.WorkspaceId = mcp_req.get('workspace_id', os.getenv('WORKSPACE_ID'))
    ip_list = [ip.strip() for ip in mcp_req.get('ip_address', '').split(',')]
    for ip in ip_list:
        base.add_ip_entity(address=ip, geo_data={}, rawentity={})
    module_payload = {
        'BaseModuleBody': base.__dict__,
        'CheckDomains': False,
        'CheckFileHashes': False,
        'CheckIPs': True,
        'CheckURLs': False
    }
    ti_data = ti.execute_ti_module(module_payload)
    return str(ti_data.body.__dict__)