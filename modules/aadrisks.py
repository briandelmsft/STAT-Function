from classes import BaseModule, Response, AADModule, STATError
from shared import rest, data
import json

def execute_aadrisks_module (req_body):

    #Inputs AddIncidentComments, AddIncidentTask, Entities, IncidentTaskInstructions, LookbackInDays, MFAFailureLookup, MFAFraudLookup

    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])

    aadrisks_object = AADModule()

    for account in base_object.Accounts:
        userid = account.get('id')
        if userid:
            upn = account.get('userPrincipalName')
            current_account = {
                'UserFailedMFACount': 0,
                'UserMFAFraudCount': 0,
                'UserId': f'{userid}',
                'UserPrincipalName': f'{upn}',
                'UserRiskLevel': 'unknown'
            }
            path = f'/v1.0/identityProtection/riskyUsers/{userid}'
            current_account.UserRiskLevel = json.loads(rest.rest_call_get(api='msgraph', path=path).content)['riskLevel']
            if req_body.get('MFAFailureLookup', True):
                MFAFailureLookup_query = f'SigninLogs\n| where ResultType == \"500121\"\n| where UserId== \"{userid}\"\n| summarize Count=count() by UserPrincipalName'
                MFAFailureLookup = json.loads(rest.execute_la_query(base_object.WorkspaceId, MFAFailureLookup_query, req_body.get('LookbackInDays')).content)
                if MFAFailureLookup:
                    current_account.UserFailedMFACount = MFAFailureLookup['Count']
                else:
                    current_account.UserFailedMFACount = 0
            if req_body.get('MFAFraudLookup', True):
                MFAFraudLookup_query = f'AuditLogs \n| where OperationName in (\"Fraud reported - user is blocked for MFA\",\"Fraud reported - no action taken\")\n| where ResultDescription == \"Successfully reported fraud\"\n| extend Id= tostring(parse_json(tostring(InitiatedBy.user)).id)\n| where Id == \"{userid}\"\n| summarize Count=count() by Id'
                MFAFraudLookup = json.loads(rest.execute_la_query(base_object.WorkspaceId, MFAFraudLookup_query, req_body.get('LookbackInDays')).content)
                if MFAFraudLookup:
                    current_account.UserMFAFraudCount = MFAFraudLookup['Count']
                else:
                    current_account.UserMFAFraudCount = 0
        aadrisks_object.DetailedResults.append(json.dumps(current_account))

    entities_nb = len(aadrisks_object.DetailedResults)
    if entities_nb != 0:
        aadrisks_object.AnalyzedEntities = entities_nb
        aadrisks_object.FailedMFATotalCount = sum(total['UserFailedMFACount'] for total in aadrisks_object.DetailedResults)
        aadrisks_object.MFAFraudTotalCount = sum(total['UserMFAFraudCount'] for total in aadrisks_object.DetailedResults)
        aadrisks_object.HighestRiskLevel = data.return_highest_value(aadrisks_object.DetailedResults,'UserRiskLevel')

    if req_body.get('AddIncidentComments', True):
        html_table = data.list_to_html_table(aadrisks_object.DetailedResults)
        comment = f'A total of {aadrisks_object.AnalyzedEntities} entites were analyzed.<br />'
        comment += f'<ul><li>Highest risk detected: {aadrisks_object.HighestRiskLevel}</li>'
        comment += f'<li>Total MFA failures: {aadrisks_object.FailedMFATotalCount} </li>'
        comment += f'<li>Total MFA Fraud: {aadrisks_object.MFAFraudTotalCount} </li></ul><br />'
        comment += f'{html_table}'
        comment_result = rest.add_incident_comment(base_object.IncidentARMId, comment)

    if req_body.get('AddIncidentTask', True) and aadrisks_object.FailedMFATotalCount > 0 or aadrisks_object.MFAFraudTotalCount > 0 or ( aadrisks_object.HighestRiskLevel != 'None' and aadrisks_object.HighestRiskLevel != 'Unknown'):
        task_result = rest.add_incident_task(base_object.IncidentARMId, req_body.get('QueryDescription', 'Review users Azure AD risks level and MFA results'), req_body.get('IncidentTaskInstructions'))

    return Response(aadrisks_object)