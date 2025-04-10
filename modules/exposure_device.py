from classes import BaseModule, Response, DeviceExposureModule
from shared import rest, data
import json

def execute_device_exposure_module (req_body):

    #Inputs AddIncidentComments, AddIncidentTask, Entities, IncidentTaskInstructions

    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])
    lookback = req_body.get('LookbackInDays', 14)
    exp_object = DeviceExposureModule()

    mde_ids = base_object.get_host_mdeid_list()

    if mde_ids:
        query = data.load_text_from_file('exposure-device.kql', mde_id_list=mde_ids)
        response = rest.execute_m365d_query(base_object, query)

        exp_object.Nodes = list(filter(lambda x: x['NodeType'] == 'Node', response))
        exp_object.Paths = list(filter(lambda x: x['NodeType'] == 'Path', response))

    crit_level = {
        0: 'Very High<br />🟥🟥🟥🟥',
        1: 'High<br />🟥🟥🟥⬜ ',
        2: 'Medium<br />🟥🟥⬜⬜',
        3: 'Low<br />🟥⬜⬜⬜'
    }

    if req_body.get('AddIncidentComments', True):

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
                'Computer Details': f"<b>Criticality:</b><br /> {crit_level[x['ComputerCrit']]}<br /><p><b>Asset Rules:</b> {data.list_to_string(x['ComputerCriticalityRules'])}<br /><b>Computer Tags:</b> {data.list_to_string(x['ComputerTags'])}<p><b>Risk Level:</b> {x['ComputerRiskScore']}<br /><b>Exposure Level:</b> {x['ComputerExposureScore']}<br /><b>Max CVSS Score:</b> {x['ComputerMaxCVSSScore']}<br /><b>Onboarding:</b> {x['ComputerOnboarding']}<br /><b>Sensor:</b> {x['ComputerSensorHealth']}"
            })

        comment = f'<h3>Device Exposure Module</h3>'
        if out:
            html_table = data.list_to_html_table(out, index=False, max_cols=20, escape_html=False)
            comment += html_table
        else:
            comment += f'No Device Exposure Results Detected'
        
        comment_result = rest.add_incident_comment(base_object, comment)

    return Response(exp_object)

def get_device_link(x):
    for dev_id in x.get('ComputerEntityIds', []):
        if dev_id['type'] == 'DeviceInventoryId':
            device_id = dev_id['id']
            break

    if device_id:
        return f"<a href=\"https://security.microsoft.com/machines/v2/{device_id}/overview\" target=\"_blank\">{x['Computer']}</a><br />(<a href=\"https://security.microsoft.com/security-graph?id={device_id}&assetType=DeviceInventoryId\">Exposure Map</a>)"
    else:
        return x['Computer']