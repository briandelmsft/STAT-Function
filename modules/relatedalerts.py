from classes import BaseModule, Response, RelatedAlertsModule
from shared import rest, data

def execute_relatedalerts_module (req_body):

    #Inputs AddIncidentComments, AddIncidentTask, BaseModuleBody, IncidentTaskInstructions
    #LookbackInDays, CheckAccountEntityMatches, CheckHostEntityMatches, CheckIPEntityMatches, AlertKQLFilter

    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])

    related_alerts = RelatedAlertsModule()

    check_accounts = req_body.get('CheckAccountEntityMatches', True)
    check_ips = req_body.get('CheckIPEntityMatches', True)
    check_hosts = req_body.get('CheckHostEntityMatches', True)
    alert_filter = req_body.get('AlertKQLFilter')
    lookback = req_body.get('LookbackInDays', 14)

    if alert_filter is None:
        alert_filter = '// No Custom Alert Filter Provided'

    related_alerts.FusionIncident = str(base_object.RelatedAnalyticRuleIds).lower().__contains__('builtinfusion')


    query = f'''let lookback = {str(lookback)}d;
let currentIncidentAlerts = dynamic({str(base_object.get_alert_ids())});
let isFusionIncident = {related_alerts.FusionIncident};
let severityOrder = datatable (AlertSeverity:string, Order:int)['Informational', 1, 'Low', 2, 'Medium', 3, 'High', 4];
{base_object.get_account_kql_table()}let accounts = toscalar(accountEntities
| where {check_accounts}
| extend UPNName = split(UserPrincipalName,'@')[0]
| extend EntityData = pack_array(UserPrincipalName, SamAccountName, ObjectSID, AADUserId, UPNName)
| mv-apply EntityData on (where isnotempty(EntityData))
| summarize EntityData=make_set(EntityData));
{base_object.get_ip_kql_table()}let ips = toscalar(ipEntities
| where {check_ips}
| project IPAddress
| summarize EntityData=make_set(IPAddress));
{base_object.get_host_kql_table()}let hosts = toscalar(hostEntities
| where {check_hosts}
| project FQDN, Hostname
| extend EntityData = pack_array(FQDN, Hostname)
| mv-apply EntityData on (where isnotempty(EntityData))
| summarize EntityData=make_set(EntityData));
SecurityAlert 
| where TimeGenerated > ago(lookback) 
| summarize arg_max(TimeGenerated, *) by SystemAlertId 
| where SystemAlertId !in (currentIncidentAlerts) or isFusionIncident
| mv-expand todynamic(Entities) 
{alert_filter}
| where Entities has_any (accounts) or ( Entities has_any (ips) and Entities.Type == "ip") or Entities has_any (hosts) or (SystemAlertId in (currentIncidentAlerts) and isFusionIncident)
| extend AccountEntityMatch = iff(Entities has_any (accounts), true, false), HostEntityMatch = iff(Entities has_any (hosts), true, false), IPEntityMatch = iff(Entities has_any (ips) , true, false) 
| summarize AccountEntityMatch = max(AccountEntityMatch), IPEntityMatch=max(IPEntityMatch),HostEntityMatch=max(HostEntityMatch) by StartTime, DisplayName, AlertSeverity, SystemAlertId, ProviderName, Tactics
| join kind=leftouter severityOrder on AlertSeverity
| sort by Order desc
| project-away Order, AlertSeverity1'''

    results = rest.execute_la_query(base_object.WorkspaceId, query, lookback)

    account_matches = filter_alerts(results, 'AccountEntityMatch')
    ip_matches = filter_alerts(results, 'IPEntityMatch')
    host_matches = filter_alerts(results, 'HostEntityMatch')

    tactics_list = []
    for alert in results:
        tactics = alert.get('Tactics').split(',')
        for tactic in tactics:
            tactics_list.append(tactic.strip().replace(' ', ''))

    tactics_list = list(set(tactics_list))

    related_alerts.AllTactics =  tactics_list
    related_alerts.AllTacticsCount = len(tactics_list)
    related_alerts.DetailedResults = results
    related_alerts.HighestSeverityAlert = data.return_highest_value(results, 'AlertSeverity')
    related_alerts.RelatedAccountAlertsCount = len(account_matches)
    related_alerts.RelatedAccountAlertsFound = bool(account_matches)
    related_alerts.RelatedAlertsCount = len(results)
    related_alerts.RelatedAlertsFound = bool(results)
    related_alerts.RelatedHostAlertsCount = len(host_matches)
    related_alerts.RelatedHostAlertsFound = bool(host_matches)
    related_alerts.RelatedIPAlertsCount = len(ip_matches)
    related_alerts.RelatedIPAlertsFound = bool(ip_matches)

    if req_body.get('AddIncidentComments', True):
        
        html_table = data.list_to_html_table(results)

        comment = f'''A total of {related_alerts.RelatedAlertsCount} related alerts were found.<br>{html_table}'''
        comment_result = rest.add_incident_comment(base_object.IncidentARMId, comment)

    if req_body.get('AddIncidentTask', False) and related_alerts.RelatedAlertsFound:
        task_result = rest.add_incident_task(base_object.IncidentARMId, 'Review Related Alerts', req_body.get('IncidentTaskInstructions'))

    return Response(related_alerts)

def filter_alerts(results, match_key):
    return list(filter(lambda x: x[match_key], results))
