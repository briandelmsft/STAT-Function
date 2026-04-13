from shared import rest
from classes import BaseModule
import json
import os

tool_properties = json.dumps([{
    'propertyName': 'kql_query',
    'description': 'A KQL query string to execute',
    'propertyType': 'string',
    'isRequired': True
},
{
    'propertyName': 'workspace_id',
    'description': 'Log Analytics Workspace ID',
    'propertyType': 'string',
    'isRequired': False
}])

def _execute_kql_tool(context) -> str:
    base = BaseModule()
    mcp_req = json.loads(context)['arguments']
    base.WorkspaceId = mcp_req.get('workspace_id', os.getenv('WORKSPACE_ID'))
    query = mcp_req.get('kql_query')
    results = rest.execute_la_query(base, query, 14, 'query')
    return str(results)