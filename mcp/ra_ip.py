from classes import BaseModule
from modules import relatedalerts
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

def _investigate_alerts_ip_tool(context) -> str:
    """Investigate an IP address for related alerts."""
    base = BaseModule()
    mcp_req = json.loads(context)['arguments']
    base.WorkspaceId = mcp_req.get('workspace_id', os.getenv('WORKSPACE_ID'))
    ip_list = [ip.strip() for ip in mcp_req.get('ip_address', '').split(',')]
    for ip in ip_list:
        base.add_ip_entity(address=ip, geo_data={}, rawentity={})

    module_payload = {
        'BaseModuleBody': base.__dict__,
        'CheckAccountEntityMatches': False,
        'CheckIPEntityMatches': True,
        'CheckHostEntityMatches': False,
        'LookbackInDays': 14
    }
    ra_data = relatedalerts.execute_relatedalerts_module(module_payload)
    return str(ra_data.body.__dict__)