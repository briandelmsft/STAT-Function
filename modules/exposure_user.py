from classes import BaseModule, Response, UserExposureModule
from shared import rest, data
import json

def execute_user_exposure_module (req_body):
    """Execute the user exposure module to analyze user risk and exposure.
    
    This module analyzes user accounts to assess their exposure levels, criticality,
    and elevated rights. It queries user exposure data from Microsoft Defender
    and optionally adds comments, tags, and tasks to incidents.
    
    Args:
        req_body (dict): Request body containing:
            - BaseModuleBody: Base module data with user entities
            - LookbackInDays (int, optional): Days to look back for data. Defaults to 14.
            - AddIncidentComments (bool, optional): Whether to add comments. Defaults to True.
            - AddIncidentTags (bool, optional): Whether to add tags. Defaults to True.
            - AddIncidentTask (bool, optional): Whether to add tasks. Defaults to False.
            - IncidentTaskInstructions (str, optional): Custom task instructions.
    
    Returns:
        Response: Response object containing UserExposureModule with analysis results.
    """

    #Inputs AddIncidentComments, AddIncidentTask, BaseModuleBody, IncidentTaskInstructions, AddIncidentTags

    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])
    lookback = req_body.get('LookbackInDays', 14)
    exp_object = UserExposureModule()

    user_ids = base_object.get_account_id_and_sid_list()

    if user_ids:
        exp_object.AnalyzedEntities = len(user_ids)
        query = data.load_text_from_file('exposure-user.kql', user_id_list=user_ids)
        response = rest.execute_m365d_query(base_object, query)

        exp_object.Nodes = list(filter(lambda x: x['NodeType'] == 'Node', response))
        exp_object.Paths = list(filter(lambda x: x['NodeType'] == 'Path', response))

    if req_body.get('AddIncidentComments', True) and base_object.IncidentAvailable:
        add_comment_to_incident(base_object, exp_object)

    if req_body.get('AddIncidentTags', True) and base_object.IncidentAvailable:
        add_tags_to_incident(base_object, exp_object)

    if req_body.get('AddIncidentTask', False) and len(exp_object.Nodes) > 0 and base_object.IncidentAvailable:
        rest.add_incident_task(base_object, 'Review User Exposure Information', data.coalesce(req_body.get('IncidentTaskInstructions'), 'Review the output of the User Exposure Module in the incident comments.'))

    return Response(exp_object)

def add_comment_to_incident (base_object, exp_object):
    """Add user exposure analysis comment to the incident.
    
    Creates a detailed HTML comment showing user exposure information including
    criticality levels, asset rules, and elevated rights information. The comment
    is formatted as an HTML table for easy viewing in Microsoft Sentinel.
    
    Args:
        base_object (BaseModule): Base module containing incident information.
        exp_object (UserExposureModule): User exposure module with analysis results.
    """
    crit_level = {
        0: 'Very High<br />🟥🟥🟥🟥',
        1: 'High<br />🟥🟥🟥⬜ ',
        2: 'Medium<br />🟥🟥⬜⬜',
        3: 'Low<br />🟥⬜⬜⬜'
    }

    out = []

    for x in exp_object.Paths:
        out.append({
            'User': get_user_link(x),
            'User Details': f"{crit_level[x['UserCriticality']]}<br /><p><b>Asset Rules:</b> {data.list_to_string(x['UserCriticalityRules'])}<br /><p><b>User Tags:</b> {data.list_to_string(x['UserTags'])}",
            'ElevatedRightsOn (Top 5)': f"{data.list_to_string(x['ElevatedRightsOn'])}<p><b>Elevated Rights to Computers:</b> {x['ElevatedRightsOnCount']}<br /><b>Local Admin to Computers:</b> {x['LocalAdminCount']}",
            "HighestComputerCriticality": f"{crit_level[x['HighestComputerCriticality']]}<br /><p><b>Combined Asset Rules:</b> {data.list_to_string(x['ComputerCriticalityRules'])}"
        })

    for x in exp_object.nodes_without_paths():
        out.append({
            'User': get_user_link(x),
            'User Details': f"{crit_level[x['UserCriticality']]}<br /><p><b>Asset Rules:</b> {data.list_to_string(x['UserCriticalityRules'])}<br /><p><b>User Tags:</b> {data.list_to_string(x['UserTags'])}",
            'ElevatedRightsOn (Top 5)': "None Detected"
        })

    comment = f'<h3>User Exposure Module</h3>'
    if out:
        html_table = data.list_to_html_table(out, index=False, max_cols=20, escape_html=False)
        comment += html_table
    else:
        comment += f'No User Exposure Results Detected'
    
    comment_result = rest.add_incident_comment(base_object, comment)

def add_tags_to_incident (base_object, exp_object):
    tags = []
    for x in exp_object.Nodes:
        if x['UserCriticalityRules']:
            tags += x['UserCriticalityRules']
    rest.add_incident_tags(base_object, tags)

def get_user_link(x):
    sid = None
    entra_sid = None
    aadid = None

    for acct_id in x.get('UserEntityIds', []):
        if acct_id['type'] == 'SecurityIdentifier':
            if acct_id.get('id').startswith('S-1-12-'):
                entra_sid = acct_id['id']
            else:
                sid = acct_id['id']
        elif acct_id['type'] == 'AadObjectId':
            aadid = data.parse_kv_string(acct_id['id']).get('objectid')

    if aadid:
        return f"<a href=\"https://security.microsoft.com/user?aad={aadid}&tab=overview\" target=\"_blank\">{x['User']}</a><br />(<a href=\"https://security.microsoft.com/security-graph?id={aadid}&assetType=AadObjectId\">Exposure Map</a>)"
    elif sid:
        return f"<a href=\"https://security.microsoft.com/user?sid={sid}&tab=overview\" target=\"_blank\">{x['User']}</a><br />(<a href=\"https://security.microsoft.com/security-graph?id={sid}&assetType=SecurityIdentifier\">Exposure Map</a>)"
    else:
        return x['User']
