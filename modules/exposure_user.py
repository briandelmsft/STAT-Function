from classes import BaseModule, Response, UserExposureModule
from shared import rest, data
import json

def execute_user_exposure_module (req_body):

    #Inputs AddIncidentComments, AddIncidentTask, Entities, IncidentTaskInstructions

    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])
    lookback = req_body.get('LookbackInDays', 14)
    exp_object = UserExposureModule()

    user_ids = base_object.get_account_id_list()

    if user_ids:
        query = data.load_text_from_file('exposure-user.kql', user_id_list=user_ids)
        response = rest.execute_m365d_query(base_object, query)

        exp_object.DetailedResults = response

    if req_body.get('AddIncidentComments', True):
        html_table = data.list_to_html_table(exp_object.DetailedResults, index=False, max_cols=20)

        comment = f'{html_table}<br />'
        comment_result = rest.add_incident_comment(base_object, comment)

    return Response(exp_object)
