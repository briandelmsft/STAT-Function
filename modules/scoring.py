from classes import *
from shared import data, rest

def execute_scoring_module (req_body):

    #Inputs AddIncidentComments, AddIncidentTask, BaseModuleBody, IncidentTaskInstructions, ScoringData

    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])

    score = ScoringModule()

    for input_module in req_body['ScoringData']:
        module_body = input_module['ModuleBody']
        module = module_body.get('ModuleName')
        label = input_module.get('ScoreLabel', module)
        multiplier = input_module.get('ScoreMultiplier', 1)
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

def score_module(score:ScoringModule, module:str, module_body:dict, per_item:bool, multiplier:int, label:str):

    mitre_list = [
        {'Tactic': 'Reconnaissance', 'Score': 2},
        {'Tactic': 'ResourceDevelopment', 'Score': 3},
        {'Tactic': 'InitialAccess', 'Score': 5},
        {'Tactic': 'Execution', 'Score': 5},
        {'Tactic': 'Persistence', 'Score': 6},
        {'Tactic': 'PrivilegeEscalation', 'Score': 8},
        {'Tactic': 'DefenseEvasion', 'Score': 8},
        {'Tactic': 'CredentialAccess', 'Score': 8},
        {'Tactic': 'Discovery', 'Score': 8},
        {'Tactic': 'LateralMovement', 'Score': 9},
        {'Tactic': 'Collection', 'Score': 9},
        {'Tactic': 'CommandAndControl', 'Score': 10},
        {'Tactic': 'Exfiltration', 'Score': 12},
        {'Tactic': 'Impact', 'Score': 12},
        {'Tactic': 'InhibitResponseFunction', 'Score': 12},
        {'Tactic': 'ImpairProcessControl', 'Score': 12}
    ]

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

    if file.HashesInvalidSignatureCount > 0:
        score.append_score((file.HashesInvalidSignatureCount * 5 * multiplier), f'{label} - Invalid Signatures')

    if file.HashesLinkedToThreatCount == 0 and file.HashesInvalidSignatureCount == 0:
        score.append_score(0, f'{label} - No File threats found')

def score_mdca(score:ScoringModule, module_body, per_item, multiplier, label):
    mdca = MDCAModule()
    mdca.load_from_input(module_body)
    
    if per_item:
        score.append_score((mdca.AboveThresholdCount * 10 * multiplier), label)
    elif mdca.AboveThresholdCount > 0:
        score.append_score((10 * multiplier), label)
    else:
        score.append_score(0, label)

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
