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

        exp_object.DetailedResults = response

    crit_level = {
        0: 'Very High<br />🟥🟥🟥🟥',
        1: 'High<br />🟥🟥🟥⬜ ',
        2: 'Medium<br />🟥🟥⬜⬜',
        3: 'Low<br />🟥⬜⬜⬜'
    }

    if req_body.get('AddIncidentComments', True):

        out = []

        for x in exp_object.DetailedResults:
            out.append({
                'Computer': x['Computer'],
                'ComputerCriticality': f"{crit_level[x['ComputerCrit']]}<br /><p><b>Rules:</b> {data.list_to_string(x['ComputerCriticalityRules'])}",
                'ComputerInfo': f"<b>Risk Level:</b> {x['ComputerRiskScore']}<br /><b>Exposure Level:</b> {x['ComputerExposureScore']}<br /><b>Max CVSS Score:</b> {x['ComputerMaxCVSSScore']}<br /><b>Onboarding:</b> {x['ComputerOnboarding']}<br /><b>Sensor:</b> {x['ComputerSensorHealth']}",
                'ComputerTags': data.list_to_string(x['ComputerTags']),
                'UsersOnDevice': x['UsersOnDevice'],
                'UserCriticality': f"{crit_level[x['UserCrit']]}<br /><p><b>Rules:</b> {data.list_to_string(x['UserCriticalityRules'])}",
                'UserTags': data.list_to_string(x['UserTags']),
            })

        html_table = data.list_to_html_table(out, index=False, max_cols=20, escape_html=False)

        comment = f'<h3>Device Exposure Module</h3>{html_table}<br />'
        comment_result = rest.add_incident_comment(base_object, comment)

    return Response(exp_object)
