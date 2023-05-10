from classes import BaseModule, Response, UEBAModule
from shared import rest, data
import ast

def execute_ueba_module (req_body):

    #Inputs AddIncidentComments, AddIncidentTask, BaseModuleBody, IncidentTaskInstructions
    #LookbackInDays, MinimumInvestigationPriority

    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])

    ueba_object = UEBAModule()

    lookback = req_body.get('LookbackInDays', 14)
    min_priority = req_body.get('MinimumInvestigationPriority', 3)

    query = f'''let minPriority = {min_priority};
let lookback = {lookback}d;
{base_object.get_account_kql_table()}let accountIds = accountEntities
| summarize UserNames=make_set(SamAccountName), UPNs=make_set(UserPrincipalName)
| extend ids = array_concat(UserNames, UPNs);
let userDetails = BehaviorAnalytics
| where TimeGenerated > ago(lookback)
| join kind=inner (accountEntities) on UserPrincipalName
| where InvestigationPriority >= minPriority or isnotnull(DevicesInsights.ThreatIntelIndicatorType) 
| summarize InvestigationPrioritySum=sum(InvestigationPriority), InvestigationPriorityAverage=avg(InvestigationPriority), InvestigationPriorityMax=max(InvestigationPriority), ThreatIntelMatches=countif(isnotnull(DevicesInsights.ThreatIntelIndicatorType)), EventCount=count() by UserPrincipalName;
let userAnomalies = Anomalies
| where TimeGenerated > ago(lookback)
| where UserPrincipalName in~ (accountIds) or UserName in~ (accountIds)
| mv-expand todynamic(Tactics)
| summarize AnomalyTactics=make_set(Tactics), AnomalyCount=dcount(Id, 4)
| extend UserPrincipalName="Total";
userDetails
| summarize InvestigationPrioritySum=sum(InvestigationPrioritySum), InvestigationPriorityAverage=avg(InvestigationPriorityAverage), InvestigationPriorityMax=max(InvestigationPriorityMax), ThreatIntelMatches=sum(ThreatIntelMatches), EventCount=sum(EventCount)
| extend UserPrincipalName="Total"
| join kind=leftouter userAnomalies on UserPrincipalName
| extend AnomalyTacticsCount = toint(array_length(AnomalyTactics))
| union userDetails
| project-away UserPrincipalName1
| extend InvestigationPriorityAverage=iff(isnan(InvestigationPriorityAverage), toreal(0), round(toreal(InvestigationPriorityAverage),2))'''

    results = rest.execute_la_query(base_object.WorkspaceId, query, lookback)

    details = list(filter(lambda x: x['UserPrincipalName'] != 'Total', results))

    for detail in details:
        detail.pop('AnomalyTactics')
        detail.pop('AnomalyCount')
        detail.pop('AnomalyTacticsCount')

    total = list(filter(lambda x: x['UserPrincipalName'] == 'Total', results))[0]

    ueba_object.AllEntityEventCount = total['EventCount']
    ueba_object.AllEntityInvestigationPriorityAverage = total['InvestigationPriorityAverage']
    ueba_object.AllEntityInvestigationPriorityMax = total['InvestigationPriorityMax']
    ueba_object.AllEntityInvestigationPrioritySum = total['InvestigationPrioritySum']
    ueba_object.AnomaliesFound = bool(total['AnomalyCount'])
    ueba_object.AnomalyCount = total['AnomalyCount']
    ueba_object.AnomalyTactics = ast.literal_eval(total['AnomalyTactics'])
    ueba_object.AnomalyTacticsCount = len(ueba_object.AnomalyTactics)
    ueba_object.DetailedResults = details
    ueba_object.InvestigationPrioritiesFound = bool(total['EventCount'])
    ueba_object.ThreatIntelFound = bool(total['ThreatIntelMatches'])
    ueba_object.ThreatIntelMatchCount = total['ThreatIntelMatches']

    if req_body.get('AddIncidentComments', True):
        
        html_table = data.list_to_html_table(results)

        comment = f'A total of {ueba_object.AllEntityEventCount} matching UEBA events, {ueba_object.ThreatIntelMatchCount} \
            UEBA Threat Intellgience matches and {ueba_object.AnomalyCount} anomalies were found.<br>{html_table}'
        
        comment_result = rest.add_incident_comment(base_object.IncidentARMId, comment)

    if req_body.get('AddIncidentTask', False) and (ueba_object.InvestigationPrioritiesFound or ueba_object.ThreatIntelFound or ueba_object.AnomaliesFound):
        task_result = rest.add_incident_task(base_object.IncidentARMId, 'Review UEBA Matches', req_body.get('IncidentTaskInstructions'))

    return Response(ueba_object)
