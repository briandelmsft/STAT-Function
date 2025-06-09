from classes import *
from shared import data, rest
import logging

def execute_scoring_module (req_body):

    # Log module invocation with parameters (excluding BaseModuleBody, ScoringData)
    log_params = {k: v for k, v in req_body.items() if k != 'BaseModuleBody' and k != 'ScoringData'}
    logging.info(f'Scoring Module invoked with parameters: {log_params}')

    #Inputs AddIncidentComments, AddIncidentTask, BaseModuleBody, IncidentTaskInstructions, ScoringData

    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])

    score = ScoringModule()

    score_base_module(score, base_object)

    for input_module in req_body['ScoringData']:
        module_body = input_module['ModuleBody']
        module = module_body.get('ModuleName')
        label = input_module.get('ScoreLabel', module)
        multiplier = float(input_module.get('ScoreMultiplier', 1))
        per_item = input_module.get('ScorePerItem', True)

        try:
            score_module(score, module, module_body, per_item, multiplier, label)
        except BaseException as e:
            raise STATError(f'Failed to score the module {module} with label {label}', {'Error': str(e)})

    score.DetailedResults = data.sort_list_by_key(score.DetailedResults, 'Score')

    if req_body.get('AddIncidentComments', True) and base_object.IncidentAvailable:
        
        html_table = data.list_to_html_table(score.DetailedResults)

        comment = f'''The total calculated risk score is {score.TotalScore}.<br>{html_table}'''
        comment_result = rest.add_incident_comment(base_object, comment)

    if req_body.get('AddIncidentTask', False) and score.TotalScore > 0 and base_object.IncidentAvailable:
        task_result = rest.add_incident_task(base_object, 'Review Incident Risk Score', req_body.get('IncidentTaskInstructions')) 

    return Response(score)

def score_base_module(score:ScoringModule, base_object:BaseModule):
    #Priv User Check
    high_priv = data.load_json_from_file('privileged-roles.json')
    for acct in base_object.Accounts:
        upn = acct.get('userPrincipalName')
        assigned_roles = acct.get('AssignedRoles', [])
        if set(assigned_roles).intersection(high_priv):
            score.append_score(25, f'Base Module - User {upn} is assigned to sensitive privileged role')
        elif 'Unavailable' in assigned_roles and len(assigned_roles) == 1:
            score.append_score(5, f'Base Module - Role assignments for {upn} are unavailable')
        elif assigned_roles:
            score.append_score(10, f'Base Module - User {upn} is assigned to a privileged role')

def score_module(score:ScoringModule, module:str, module_body:dict, per_item:bool, multiplier:int, label:str):

    mitre_list = data.load_json_from_file('mitre-tactics.json')

    match module:
        case 'WatchlistModule':
            score_watchlist(score, module_body, per_item, multiplier, label)
        case 'AADRisksModule':
            score_aad(score, module_body, per_item, multiplier, label)
        case 'FileModule':
            score_file(score, module_body, multiplier, label)
        case 'KQLModule':
            score_kql(score, module_body, per_item, multiplier, label)
        case 'MDCAModule' | 'MCASModule':
            score_mdca(score, module_body, per_item, multiplier, label)
        case 'MDEModule':
            score_mde(score, module_body, per_item, multiplier, label)
        case 'RelatedAlerts':
            score_alerts(score, module_body, per_item, multiplier, label, mitre_list)
        case 'TIModule':
            score_ti(score, module_body, per_item, multiplier, label)
        case 'UEBAModule':
            score_ueba(score, module_body, per_item, multiplier, label, mitre_list)
        case 'ExchangeModule':
            score_exchange(score, module_body, per_item, multiplier)
        case 'Custom':
            score_custom(score, module_body, multiplier)
        case _:
            raise STATError(f'Incorrectly formatted data or data from an unsupported module was passed to the Scoring Module, module name: {module}')

def score_kql(score:ScoringModule, module_body, per_item, multiplier, label):
    kql = KQLModule()
    kql.load_from_input(module_body)
         
    if per_item and kql.ResultsCount > 0:
        module_score = 5 * kql.ResultsCount * multiplier
    elif kql.ResultsCount > 0:
        module_score = 5 * multiplier
    else:
        module_score = 0

    score.append_score(score=module_score, label=label)

def score_watchlist(score:ScoringModule, module_body, per_item, multiplier, label):
    watchlist = WatchlistModule()
    watchlist.load_from_input(module_body)
         
    if per_item and watchlist.EntitiesOnWatchlist:
        module_score = 10 * watchlist.EntitiesOnWatchlistCount * multiplier
    elif watchlist.EntitiesOnWatchlist:
        module_score = 10 * multiplier
    else:
        module_score = 0

    score.append_score(score=module_score, label=label)

def score_ti(score:ScoringModule, module_body, per_item, multiplier, label):
    ti = TIModule()
    ti.load_from_input(module_body)
         
    if per_item and ti.AnyTIFound:
        module_score = 10 * ti.TotalTIMatchCount * multiplier
    elif ti.AnyTIFound:
        module_score = 10 * multiplier
    else:
        module_score = 0

    score.append_score(score=module_score, label=label)

def score_alerts(score:ScoringModule, module_body, per_item, multiplier, label, mitre_list):
    alerts = RelatedAlertsModule()
    alerts.load_from_input(module_body)

    alert_list = [
        {'AlertSeverity': 'High', 'Score': 10},
        {'AlertSeverity': 'Medium', 'Score': 5},
        {'AlertSeverity': 'Low', 'Score': 3},
        {'AlertSeverity': 'Informational', 'Score': 1}
    ]
         
    if per_item and alerts.RelatedAlertsFound:
        scored_alerts = data.join_lists(left_list=alerts.DetailedResults, right_list=alert_list, left_key='AlertSeverity', right_key='AlertSeverity', kind='left', fill_nan=5)
        module_score = data.sum_column_by_key(scored_alerts, 'Score') * multiplier
    elif alerts.RelatedAlertsFound:
        scored_alerts = data.join_lists(left_list=alerts.DetailedResults, right_list=alert_list, left_key='AlertSeverity', right_key='AlertSeverity', kind='left', fill_nan=1)
        module_score = data.max_column_by_key(scored_alerts, 'Score') * multiplier
    else:
        module_score = 0

    score.append_score(score=module_score, label=label)

    if alerts.AllTacticsCount > 0:
        scored_tactics = data.join_lists(left_list={'Tactic': alerts.AllTactics}, right_list=mitre_list, left_key='Tactic', right_key='Tactic', kind='left', fill_nan=8)
        mitre_score = data.sum_column_by_key(scored_tactics, 'Score') * multiplier
        mitre_join = ', '
        score.append_score(score=mitre_score, label=f'{label} - {alerts.AllTacticsCount} MITRE Tactics ({mitre_join.join(alerts.AllTactics)})')
    
def score_ueba(score:ScoringModule, module_body, per_item, multiplier, label, mitre_list):
    ueba = UEBAModule()
    ueba.load_from_input(module_body)

    module_score = 0
         
    if per_item and ueba.DetailedResults:
        module_score = data.sum_column_by_key(ueba.DetailedResults, 'InvestigationPriorityMax') * multiplier
    else:
        module_score = ueba.AllEntityInvestigationPriorityMax * multiplier

    module_score += 10 * ueba.ThreatIntelMatchCount * multiplier

    score.append_score(score=module_score, label=label)    

    if ueba.AnomalyTactics:
        ueba_mitre = data.join_lists(left_list={'Tactic': ueba.AnomalyTactics}, right_list=mitre_list, left_key='Tactic', right_key='Tactic', kind='left', fill_nan=8)
        ueba_mitre_score = int((data.sum_column_by_key(ueba_mitre, 'Score') / 2) * multiplier)
        mitre_join = ', '
        score.append_score(score=ueba_mitre_score, label=f'{label} - {ueba.AnomalyTacticsCount} Anomaly MITRE Tactics ({mitre_join.join(ueba.AnomalyTactics)})')

def score_aad(score:ScoringModule, module_body, per_item, multiplier, label):
    aad = AADModule()
    aad.load_from_input(module_body)

    score_key = {
        'high': 10,
        'medium': 5,
        'low': 3
    }

    event_types = data.load_json_from_file('entra-risk-events.json')

    event_scores = []
    for user in aad.DetailedResults:
        for event in user.get('RiskDetections', []):
            event_scores.append(event_types.get(event['riskEventType'], 10))

    if per_item and event_scores:
        score.append_score(sum(event_scores) * multiplier, f'{label} - Risk Events Score')
    elif event_scores:
        score.append_score(max(event_scores) * multiplier, f'{label} - Risk Events Score')
         
    if per_item and aad.DetailedResults:
        for user in aad.DetailedResults:
            module_score = score_key.get(user['UserRiskLevel'].lower(), 0) * multiplier
            upn = user['UserPrincipalName']
            score.append_score(score=module_score, label=f'{label} - {upn}')
    elif aad.DetailedResults:
        module_score = score_key.get(aad.HighestRiskLevel.lower(), 0) * multiplier
        score.append_score(score=module_score, label=label)
    else:
        score.append_score(score=0, label=f'{label} - No User Entities')

def score_file(score:ScoringModule, module_body, multiplier, label):
    file = FileModule()
    file.load_from_input(module_body)

    if file.HashesLinkedToThreatCount > 0:
        score.append_score((file.HashesLinkedToThreatCount * 10 * multiplier), f'{label} - Hash linked to threat')

    if file.HashesLinkedToThreatCount == 0:
        score.append_score(0, f'{label} - No File threats found')

def score_mdca(score:ScoringModule, module_body, per_item, multiplier, label):
    score.append_score(0, 'WARNING: MDCA Module was included in scoring, however this module has been deprecated.')

def score_exchange(score:ScoringModule, module_body, per_item, multiplier):
    exch = ExchangeModule()
    exch.load_from_input(module_body)

    recent_rules = len(list(filter(lambda x: x.get('Operation') in ('New-InboxRule', 'Set-InboxRule'), exch.AuditEvents)))
    if per_item:
        if (exch.RulesDelete + exch.RulesMove) > 0:
            score.append_score(2 * (exch.RulesDelete + exch.RulesMove) * multiplier, 'Exchange Module - Deletion and/or move rules found')
        if exch.RulesForward > 0:
            score.append_score(25 * exch.RulesForward * multiplier, 'Exchange Module - Mail forwarding configuration found')
        if exch.DelegationsFound > 0:
            score.append_score(25 * exch.DelegationsFound * multiplier, 'Exchange Module - Recent mailbox or folder delegations added')
        if recent_rules > 0:
            score.append_score(10 * recent_rules * multiplier, 'Exchange Module - Recent modification to delete/move/forward mailbox rules')
        if exch.PrivilegedUsersWithMailbox > 0:
            score.append_score(25 * exch.PrivilegedUsersWithMailbox * multiplier, 'Exchange Module - Privileged Users with Mailbox')

    else:
        if exch.RulesDelete + exch.RulesMove > 0:
            score.append_score(2 * multiplier, 'Exchange Module - Deletion and/or move rules found')
        if exch.RulesForward > 0:
            score.append_score(25 * multiplier, 'Exchange Module - Mail forwarding configuration found')
        if exch.DelegationsFound > 0:
            score.append_score(25 * multiplier, 'Exchange Module - Recent mailbox or folder delegations added')
        if recent_rules > 0:
            score.append_score(10 * multiplier, 'Exchange Module - Recent modification to delete/move/forward mailbox rules')
        if exch.PrivilegedUsersWithMailbox > 0:
            score.append_score(25 * multiplier, 'Exchange Module - Privileged Users with Mailbox')
    
    
def score_mde(score:ScoringModule, module_body, per_item, multiplier, label):
    mde = MDEModule()
    mde.load_from_input(module_body)

    score_key = {
        'high': 10,
        'medium': 5,
        'low': 3,
        'informational': 1,
    }

    user_score = score_key.get(mde.UsersHighestRiskScore.lower(), 0)
    host_score = score_key.get(mde.HostsHighestRiskScore.lower(), 0)
    ip_score = score_key.get(mde.IPsHighestRiskScore.lower(), 0)

    if per_item:
        total_score = (user_score + host_score + ip_score) * multiplier
    else:
        total_score = max(user_score, host_score, ip_score) * multiplier

    score.append_score(total_score, label)

def score_custom(score:ScoringModule, module_body, multiplier):

    for score_item in module_body['ScoringData']:
        item_score = score_item['Score'] * multiplier
        score.append_score(score=item_score, label=score_item['ScoreLabel'])
