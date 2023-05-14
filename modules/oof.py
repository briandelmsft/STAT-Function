from classes import BaseModule, Response, OOFModule
from shared import rest, data
import json
import re
import datetime

def execute_oof_module (req_body):

    #Inputs AddIncidentComments, AddIncidentTask, Entities, IncidentTaskInstructions, KQLQuery, LookbackInDays, QueryDescription, RunQueryAgainst

    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])

    oof = OOFModule()

    for account in base_object.Accounts:
        upn = account.get('userPrincipalName')
        if upn:
            path = f'/v1.0/users/{upn}/mailboxSettings/automaticRepliesSetting'
            try:
                results = json.loads(rest.rest_call_get(api='msgraph', path=path).content)
            except:
                oof.UsersUnknown += 1
                append_unknown(oof, upn)

            else:
                current_time = datetime.datetime.utcnow()
                if results['status'].lower() == 'disabled':
                    oof.UsersInOffice += 1
                    append_disabled(oof, upn)
                elif results['status'].lower() == 'enabled' or results['status'].lower() == 'alwaysenabled':
                    oof.UsersOutOfOffice += 1
                    append_enabled(oof, upn, results['internalReplyMessage'], results['externalReplyMessage'])
                elif results['status'].lower() == 'scheduled' and current_time >= results['scheduledStartDateTime']['dateTime'] \
                        and current_time <= results['scheduledEndDateTime']['dateTime']:
                    oof.UsersOutOfOffice += 1
                    append_enabled(oof, upn, results['internalReplyMessage'], results['externalReplyMessage'])
                else:
                    oof.UsersInOffice += 1
                    append_disabled(oof, upn)

        else:
            oof.UsersUnknown += 1

    if oof.UsersOutOfOffice == 0 and oof.UsersUnknown == 0:
        oof.AllUsersInOffice = True
        oof.AllUsersOutOfOffice = False
    elif oof.UsersOutOfOffice > 0 and oof.UsersInOffice == 0 and oof.UsersUnknown == 0:
        oof.AllUsersInOffice = False
        oof.AllUsersOutOfOffice = True 
    else:
        oof.AllUsersInOffice = False
        oof.AllUsersOutOfOffice = False

    if req_body.get('AddIncidentComments', True):
        
        html_table = data.list_to_html_table(oof.DetailedResults)

        comment = f'''A total of {oof.AllUsersOutOfOffice} users have out of office messages set.<br>{html_table}'''
        comment_result = rest.add_incident_comment(base_object.IncidentARMId, comment)

    if req_body.get('AddIncidentTask', False) and oof.UsersOutOfOffice > 0:
        task_result = rest.add_incident_task(base_object.IncidentARMId, req_body.get('QueryDescription', 'Review User Out of Office messages'), req_body.get('IncidentTaskInstructions'))

    return Response(oof)

def append_disabled(oof, upn):
    oof.DetailedResults.append({'ExternalMessage': '', 'InternalMessage': '', 'OOFStatus': 'disabled', 'UPN': upn})

def append_unknown(oof, upn):
    oof.DetailedResults.append({'ExternalMessage': '', 'InternalMessage': '', 'OOFStatus': 'unknown', 'UPN': upn})

def append_enabled(oof, upn, internal, external):
    clean_html = re.compile('<.*?>')
    int_msg = re.sub(clean_html, '', internal)
    ext_msg = re.sub(clean_html, '', external)
    oof.DetailedResults.append({'ExternalMessage': ext_msg, 'InternalMessage': int_msg, 'OOFStatus': 'enabled', 'UPN': upn})