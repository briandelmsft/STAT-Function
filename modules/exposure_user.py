from classes import BaseModule, Response, UserExposureModule
from shared import rest, data
import json

def execute_user_exposure_module (req_body):

    #Inputs AddIncidentComments, AddIncidentTask, Entities, IncidentTaskInstructions

    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])
    lookback = req_body.get('LookbackInDays', 14)
    exp_object = UserExposureModule()

    user_ids = base_object.get_account_id_and_sid_list()

    if user_ids:
        query = data.load_text_from_file('exposure-user.kql', user_id_list=user_ids)
        response = rest.execute_m365d_query(base_object, query)

        exp_object.DetailedResults = response

    if req_body.get('AddIncidentComments', True):

        crit_level = {
            0: 'Very High<br />🟥🟥🟥🟥',
            1: 'High<br />🟥🟥🟥⬜ ',
            2: 'Medium<br />🟥🟥⬜⬜',
            3: 'Low<br />🟥⬜⬜⬜'
        }

        out =[]

        for x in exp_object.DetailedResults:
            out.append({
                'User': x['User'],
                'UserCriticality': f"{crit_level[x['UserCriticality']]}<br /><p><b>Rules:</b> {data.list_to_string(x['UserCriticalityRules'])}",
                'UserTags': data.list_to_string(x['UserTags']),
                'ElevatedRightsOn (Top 5)': data.list_to_string(x['ElevatedRightsOn']),
                "HighestComputerCriticality": f"{crit_level[x['HighestComputerCriticality']]}<br /><p><b>Rules: </b> {data.list_to_string(x['ComputerCriticalityRules'])}",
                "LocalAdminCount": x['LocalAdminCount']
            })

            try:
                test = ', '.join(x['UserCriticalityRules'])
                None
            except:
                pass


        html_table = data.list_to_html_table(out, index=False, max_cols=20, escape_html=False)

        comment = f'<h3>User Exposure Module</h3>{html_table}<br />'
        comment_result = rest.add_incident_comment(base_object, comment)

    return Response(exp_object)
