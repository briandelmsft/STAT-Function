from classes import BaseModule, Response, AADModule, STATError, STATNotFound
from shared import rest, data
import json, datetime

def execute_aadrisks_module (req_body):

    #Inputs AddIncidentComments, AddIncidentTask, Entities, IncidentTaskInstructions, LookbackInDays, MFAFailureLookup, MFAFraudLookup, SuspiciousActivityReportLookup

    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])

    aadrisks_object = AADModule()
    all_risk_detections = []

    for account in base_object.Accounts:
        userid = account.get('id')
        if userid:
            upn = account.get('userPrincipalName')
            current_account = {
                'UserFailedMFACount': None,
                'UserMFAFraudCount': None,
                'SuspiciousActivityReportCount' : None,
                'UserId': f'{userid}',
                'UserPrincipalName': f'{upn}',
                'UserRiskLevel': 'unknown'
            }

            #Get User Risk level
            path = f'/v1.0/identityProtection/riskyUsers/{userid}'
            try:
                user_risk_level = json.loads(rest.rest_call_get(base_object, api='msgraph', path=path).content)['riskLevel']
            except STATNotFound:
                pass
            else:
                current_account['UserRiskLevel'] = user_risk_level

            #Get related risk detections
            start_time = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=req_body.get('LookbackInDays', 30))).strftime("%Y-%m-%dT%H:%M:%SZ")
            select_attributes = "riskEventType,riskState,riskLevel,riskDetail,detectionTimingType,ipAddress,activityDateTime,userPrincipalName,additionalInfo"
            path = f"/v1.0/identityProtection/riskDetections?$filter=userId eq '{userid}' and activityDateTime ge {start_time}&$select={select_attributes}"
            
            try:
                user_risk_level:dict = json.loads(rest.rest_call_get(base_object, api='msgraph', path=path).content)
            except STATError:
                pass
            else:
                event:dict
                for event in user_risk_level.get('value', []):
                    add_info:list = json.loads(event.pop('additionalInfo', None))
                    risk_reasons = [x.get('Value',[]) for x in add_info if x.get('Key') == 'riskReasons'][0]
                    event['RiskReasons'] = ', '.join(risk_reasons)

                current_account['RiskDetections'] = user_risk_level.get('value', [])
                current_account['UserRiskDetectionCount'] = len(current_account['RiskDetections'])
                all_risk_detections = all_risk_detections + user_risk_level.get('value', [])

            if req_body.get('MFAFailureLookup', True):
                MFAFailureLookup_query = f'SigninLogs\n| where ResultType == \"500121\"\n| where UserId== \"{userid}\"\n| summarize Count=count() by UserPrincipalName'
                MFAFailureLookup_results = rest.execute_la_query(base_object, MFAFailureLookup_query, req_body.get('LookbackInDays'))
                if MFAFailureLookup_results:
                    current_account['UserFailedMFACount'] = MFAFailureLookup_results[0]['Count']
                else:
                    current_account['UserFailedMFACount'] = 0
            if req_body.get('MFAFraudLookup', True):
                MFAFraudLookup_query = f'AuditLogs \n| where OperationName in (\"Fraud reported - user is blocked for MFA\",\"Fraud reported - no action taken\")\n| where ResultDescription == \"Successfully reported fraud\"\n| extend Id= tostring(parse_json(tostring(InitiatedBy.user)).id)\n| where Id == \"{userid}\"\n| summarize Count=count() by Id'
                MFAFraudLookup_results = rest.execute_la_query(base_object, MFAFraudLookup_query, req_body.get('LookbackInDays'))
                if MFAFraudLookup_results:
                    current_account['UserMFAFraudCount'] = MFAFraudLookup_results[0]['Count']
                else:
                    current_account['UserMFAFraudCount'] = 0
            if req_body.get('SuspiciousActivityReportLookup', True):
                SuspiciousActivityReportLookup_query = f'AuditLogs \n| where OperationName == \"Suspicious activity reported\"\n| where ResultDescription == \"Successfully reported suspicious activity\"\n| extend Id= tostring(parse_json(tostring(InitiatedBy.user)).id)\n| where Id == \"{userid}\"\n| summarize Count=count() by Id'
                SuspiciousActivityReportLookup_results = rest.execute_la_query(base_object, SuspiciousActivityReportLookup_query, req_body.get('LookbackInDays'))
                if SuspiciousActivityReportLookup_results:
                    current_account['SuspiciousActivityReportCount'] = SuspiciousActivityReportLookup_results[0]['Count']
                else:
                    current_account['SuspiciousActivityReportCount'] = 0
            aadrisks_object.DetailedResults.append(current_account)

    entities_nb = len(aadrisks_object.DetailedResults)
    if entities_nb != 0:
        aadrisks_object.AnalyzedEntities = entities_nb
        aadrisks_object.FailedMFATotalCount = sum(total['UserFailedMFACount'] for total in aadrisks_object.DetailedResults)
        aadrisks_object.MFAFraudTotalCount = sum(total['UserMFAFraudCount'] for total in aadrisks_object.DetailedResults)
        aadrisks_object.RiskDetectionTotalCount = sum(total['UserRiskDetectionCount'] for total in aadrisks_object.DetailedResults)
        aadrisks_object.SuspiciousActivityReportTotalCount = sum(total['SuspiciousActivityReportCount'] for total in aadrisks_object.DetailedResults)
        aadrisks_object.HighestRiskLevel = data.return_highest_value(aadrisks_object.DetailedResults,'UserRiskLevel')

    if req_body.get('AddIncidentComments', True):
        html_table = data.list_to_html_table(aadrisks_object.DetailedResults, index=False, columns=['UserPrincipalName','UserRiskLevel','UserFailedMFACount','UserMFAFraudCount','SuspiciousActivityReportCount','UserRiskDetectionCount']) if aadrisks_object.DetailedResults else 'No user details available<br />'
        risks_table = data.list_to_html_table(all_risk_detections, index=False, columns=['userPrincipalName','activityDateTime','ipAddress','riskLevel','riskEventType','riskState','riskDetail','detectionTimingType','RiskReasons']) if all_risk_detections else 'No risk detections found<br />'
        comment = f'<h3>Entra ID Risks Module</h3>'
        comment += f'A total of {aadrisks_object.AnalyzedEntities} entities were analyzed.<br />'
        comment += f'<ul><li>Highest risk detected: {aadrisks_object.HighestRiskLevel}</li>'
        comment += f'<li>Total MFA failures: {aadrisks_object.FailedMFATotalCount} </li>'
        comment += f'<li>Total MFA frauds: {aadrisks_object.MFAFraudTotalCount} </li>'
        comment += f'<li>Total Risk detections: {aadrisks_object.RiskDetectionTotalCount} </li>'
        comment += f'<li>Total Suspicious Activity reports: {aadrisks_object.SuspiciousActivityReportTotalCount} </li></ul><br />'
        comment += f'Details by User<br />'
        comment += f'{html_table}<br />'
        comment += f'Entra ID Risk Detections<br />'
        comment += f'{risks_table}'
        comment_result = rest.add_incident_comment(base_object, comment)

    if req_body.get('AddIncidentTask', False) and (data.coalesce(aadrisks_object.FailedMFATotalCount,0) > 0 or data.coalesce(aadrisks_object.MFAFraudTotalCount,0) > 0 or data.coalesce(aadrisks_object.SuspiciousActivityReportTotalCount,0) > 0 or data.coalesce(aadrisks_object.RiskDetectionTotalCount,0) > 0 or ( aadrisks_object.HighestRiskLevel != 'None' and aadrisks_object.HighestRiskLevel != 'Unknown')):
        task_result = rest.add_incident_task(base_object, req_body.get('QueryDescription', 'Review users Entra ID risk level, MFA failures and fraud reports.'), req_body.get('IncidentTaskInstructions'))

    return Response(aadrisks_object)