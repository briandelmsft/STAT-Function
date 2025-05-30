from classes import BaseModule, Response, DeviceExposureModule
from shared import rest, data
import json

def execute_device_exposure_module (req_body):
    """Execute the device exposure module to analyze device risk and exposure.
    
    This module analyzes devices from Microsoft Defender for Endpoint to assess
    their exposure levels, criticality, and associated users. It queries device
    exposure data and optionally adds comments, tags, and tasks to incidents.
    
    Args:
        req_body (dict): Request body containing:
            - BaseModuleBody: Base module data with device entities
            - LookbackInDays (int, optional): Days to look back for data. Defaults to 14.
            - AddIncidentComments (bool, optional): Whether to add comments. Defaults to True.
            - AddIncidentTags (bool, optional): Whether to add tags. Defaults to True.
            - AddIncidentTask (bool, optional): Whether to add tasks. Defaults to False.
            - IncidentTaskInstructions (str, optional): Custom task instructions.
    
    Returns:
        Response: Response object containing DeviceExposureModule with analysis results.
    """

    #Inputs AddIncidentComments, AddIncidentTask, BaseModuleBody, IncidentTaskInstructions, AddIncidentTags

    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])
    lookback = req_body.get('LookbackInDays', 14)
    exp_object = DeviceExposureModule()

    mde_ids = base_object.get_host_mdeid_list()

    if mde_ids:
        exp_object.AnalyzedEntities = len(mde_ids)
        query = data.load_text_from_file('exposure-device.kql', mde_id_list=mde_ids)
        response = rest.execute_m365d_query(base_object, query)

        exp_object.Nodes = list(filter(lambda x: x['NodeType'] == 'Node', response))
        exp_object.Paths = list(filter(lambda x: x['NodeType'] == 'Path', response))

    if req_body.get('AddIncidentComments', True) and base_object.IncidentAvailable:
        add_comment_to_incident(base_object, exp_object)

    if req_body.get('AddIncidentTags', True) and base_object.IncidentAvailable:
        add_tags_to_incident(base_object, exp_object)

    if req_body.get('AddIncidentTask', False) and len(exp_object.Nodes) > 0 and base_object.IncidentAvailable:
        rest.add_incident_task(base_object, 'Review Device Exposure Information', data.coalesce(req_body.get('IncidentTaskInstructions'), 'Review the output of the Device Exposure Module in the incident comments.'))

    return Response(exp_object)


def add_tags_to_incident (base_object, exp_object):
    """Add device criticality rule tags to the incident.
    
    Extracts computer criticality rules from the device exposure analysis
    and adds them as tags to the Microsoft Sentinel incident.
    
    Args:
        base_object (BaseModule): Base module containing incident information.
        exp_object (DeviceExposureModule): Device exposure module with analysis results.
    """
    tags = []
    for x in exp_object.Nodes:
        if x['ComputerCriticalityRules']:
            tags += x['ComputerCriticalityRules']
    rest.add_incident_tags(base_object, tags)

def add_comment_to_incident (base_object, exp_object):
    """Add device exposure analysis comment to the incident.
    
    Creates a detailed HTML comment showing device exposure information including
    criticality levels, asset rules, risk scores, and associated users. The comment
    is formatted as an HTML table for easy viewing in Microsoft Sentinel.
    
    Args:
        base_object (BaseModule): Base module containing incident information.
        exp_object (DeviceExposureModule): Device exposure module with analysis results.
    """
    crit_level = {
        0: 'Very High<br />🟥🟥🟥🟥',
        1: 'High<br />🟥🟥🟥⬜ ',
        2: 'Medium<br />🟥🟥⬜⬜',
        3: 'Low<br />🟥⬜⬜⬜'
    }

    out = []

    for x in exp_object.Paths:

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
            user_on_device = f"<a href=\"https://security.microsoft.com/user?aad={aadid}&tab=overview\" target=\"_blank\">{x['UsersOnDevice']}</a>"
        elif sid:
            user_on_device = f"<a href=\"https://security.microsoft.com/user?sid={sid}&tab=overview\" target=\"_blank\">{x['UsersOnDevice']}</a>"
        else:
            user_on_device = x['UsersOnDevice']

        if x['UserNodeLabel'] == 'managedidentity':
            user_on_device += f"<br />(Managed Identity)"

        out.append({
            'Computer': get_device_link(x),
            'Computer Details': f"<b>Criticality:</b><br /> {crit_level[x['ComputerCrit']]}<br /><p><b>Asset Rules:</b> {data.list_to_string(x['ComputerCriticalityRules'])}<br /><b>Computer Tags:</b> {data.list_to_string(x['ComputerTags'])}<p><b>Risk Level:</b> {x['ComputerRiskScore']}<br /><b>Exposure Level:</b> {x['ComputerExposureScore']}<br /><b>Max CVSS Score:</b> {x['ComputerMaxCVSSScore']}<br /><b>Onboarding:</b> {x['ComputerOnboarding']}<br /><b>Sensor:</b> {x['ComputerSensorHealth']}",
            'UsersOnDevice': user_on_device,
            'UserCriticality': f"{crit_level[x['UserCrit']]}<br /><p><b>Asset Rules:</b> {data.list_to_string(x['UserCriticalityRules'])}<br /><b>User Tags:</b> {data.list_to_string(x['UserTags'])}"
        })

    for x in exp_object.nodes_without_paths():
        out.append({
            'Computer': get_device_link(x),
            'Computer Details': f"<b>Criticality:</b><br /> {crit_level[x['ComputerCrit']]}<br /><p><b>Asset Rules:</b> {data.list_to_string(x['ComputerCriticalityRules'])}<br /><b>Computer Tags:</b> {data.list_to_string(x['ComputerTags'])}<p><b>Risk Level:</b> {x['ComputerRiskScore']}<br /><b>Exposure Level:</b> {x['ComputerExposureScore']}<br /><b>Max CVSS Score:</b> {x['ComputerMaxCVSSScore']}<br /><b>Onboarding:</b> {x['ComputerOnboarding']}<br /><b>Sensor:</b> {x['ComputerSensorHealth']}",
            'UsersOnDevice': "None Detected"
        })

    comment = f'<h3>Device Exposure Module</h3>'
    if out:
        html_table = data.list_to_html_table(out, index=False, max_cols=20, escape_html=False)
        comment += html_table
    else:
        comment += f'No Device Exposure Results Detected'
    
    comment_result = rest.add_incident_comment(base_object, comment)

def get_device_link(x):
    device_id = None
    for dev_id in x.get('ComputerEntityIds', []):
        if dev_id['type'] == 'DeviceInventoryId':
            device_id = dev_id['id']
            break

    if device_id:
        return f"<a href=\"https://security.microsoft.com/machines/v2/{device_id}/overview\" target=\"_blank\">{x['Computer']}</a><br />(<a href=\"https://security.microsoft.com/security-graph?id={device_id}&assetType=DeviceInventoryId\">Exposure Map</a>)"
    else:
        return x['Computer']