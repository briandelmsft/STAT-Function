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

    if req_body.get('AddIncidentComments', True):
        
        html_table = data.list_to_html_table(score.DetailedResults)

        comment = f'''The total calculated risk score is {score.TotalScore}.<br>{html_table}'''
        comment_result = rest.add_incident_comment(base_object.IncidentARMId, comment)

    if req_body.get('AddIncidentTask', False) and score.TotalScore > 0:
        task_result = rest.add_incident_task(base_object.IncidentARMId, 'Review Incident Risk Score', req_body.get('IncidentTaskInstructions')) 

    return Response(score)

def score_module(score:object, module:str, module_body:dict, per_item:bool, multiplier:int, label:str):

    mitre_list = [
        {'Tactic': 'Reconnaissance', 'Score': 2},
        {'Tactic': 'ResourceDevelopment', 'Score': 3},
        {'Tactic': 'InitialAccess', 'Score': 5},
        {'Tactic': 'Execution', 'Score': 5},
        {'Tactic': 'Persistence', 'Score': 8},
        {'Tactic': 'PrivilegeEscalation', 'Score': 10},
        {'Tactic': 'DefenseEvasion', 'Score': 10},
        {'Tactic': 'CredentialAccess', 'Score': 10},
        {'Tactic': 'Discovery', 'Score': 8},
        {'Tactic': 'LateralMovement', 'Score': 10},
        {'Tactic': 'Collection', 'Score': 10},
        {'Tactic': 'CommandAndControl', 'Score': 10},
        {'Tactic': 'Exfiltration', 'Score': 15},
        {'Tactic': 'Impact', 'Score': 15},
        {'Tactic': 'InhibitResponseFunction', 'Score': 15},
        {'Tactic': 'ImpairProcessControl', 'Score': 15}
    ]

    if module == 'WatchlistModule':
        score_watchlist(score, module_body, per_item, multiplier, label)
    elif module == 'AADRisksModule':
        raise STATError(f'Module name: {module} is not presently supported by the scoring module in STAT v2.')
    elif module == 'FileModule':
        raise STATError(f'Module name: {module} is not presently supported by the scoring module in STAT v2.')
    elif module == 'KQLModule':
        score_kql(score, module_body, per_item, multiplier, label)
    elif module == 'MCASModule':
        raise STATError(f'Module name: {module} is not presently supported by the scoring module in STAT v2.')
    elif module == 'MDEModule':
        raise STATError(f'Module name: {module} is not presently supported by the scoring module in STAT v2.')
    elif module == 'RelatedAlerts':
        score_alerts(score, module_body, per_item, multiplier, label, mitre_list)
    elif module == 'TIModule':
        score_ti(score, module_body, per_item, multiplier, label)
    elif module == 'UEBAModule':
        score_ueba(score, module_body, per_item, multiplier, label, mitre_list)
    elif module == 'Custom':
        raise STATError(f'Module name: {module} is not presently supported by the scoring module in STAT v2.')
    else:
        raise STATError(f'Incorrectly formatted data or data from an unsupported module was passed to the Scoring Module, module name: {module}')

def score_kql(score, module_body, per_item, multiplier, label):
    kql = KQLModule()
    kql.load_from_input(module_body)
         
    if per_item and kql.ResultsCount > 0:
        module_score = 5 * kql.ResultsCount * multiplier
    elif kql.ResultsCount > 0:
        module_score = 5 * multiplier
    else:
        module_score = 0

    score.DetailedResults.append({'Score': module_score, 'ScoreSource': label})
    score.add(module_score)

def score_watchlist(score, module_body, per_item, multiplier, label):
    watchlist = WatchlistModule()
    watchlist.load_from_input(module_body)
         
    if per_item and watchlist.EntitiesOnWatchlist:
        module_score = 10 * watchlist.EntitiesOnWatchlistCount * multiplier
    elif watchlist.EntitiesOnWatchlist:
        module_score = 10 * multiplier
    else:
        module_score = 0

    score.DetailedResults.append({'Score': module_score, 'ScoreSource': label})
    score.add(module_score)

def score_ti(score, module_body, per_item, multiplier, label):
    ti = TIModule()
    ti.load_from_input(module_body)
         
    if per_item and ti.AnyTIFound:
        module_score = 10 * ti.TotalTIMatchCount * multiplier
    elif ti.AnyTIFound:
        module_score = 10 * multiplier
    else:
        module_score = 0

    score.DetailedResults.append({'Score': module_score, 'ScoreSource': label})
    score.add(module_score)

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

    score.DetailedResults.append({'Score': module_score, 'ScoreSource': label})
    score.add(module_score)

    if alerts.AllTacticsCount > 0:
        scored_tactics = data.join_lists(left_list={'Tactic': alerts.AllTactics}, right_list=mitre_list, left_key='Tactic', right_key='Tactic', kind='left', fill_nan=8)
        mitre_score = data.sum_column_by_key(scored_tactics, 'Score') * multiplier
        mitre_join = ', '
        score.DetailedResults.append({'Score': mitre_score, 'ScoreSource': f'{label} - {alerts.AllTacticsCount} MITRE Tactics ({mitre_join.join(alerts.AllTactics)})'})
        score.add(mitre_score)
    
def score_ueba(score, module_body, per_item, multiplier, label, mitre_list):
    ueba = UEBAModule()
    ueba.load_from_input(module_body)

    module_score = 0
         
    if per_item:
        module_score = data.sum_column_by_key(ueba.DetailedResults, 'InvestigationPriorityMax') * multiplier
    else:
        module_score = ueba.AllEntityInvestigationPriorityMax * multiplier

    module_score += 10 * ueba.ThreatIntelMatchCount * multiplier

    score.DetailedResults.append({'Score': module_score, 'ScoreSource': label})
    score.add(module_score)

    if ueba.AnomalyTactics:
        ueba_mitre = data.join_lists(left_list={'Tactic': ueba.AnomalyTactics}, right_list=mitre_list, left_key='Tactic', right_key='Tactic', kind='left', fill_nan=8)
        ueba_mitre_score = int((data.sum_column_by_key(ueba_mitre, 'Score') / 2) * multiplier)
        mitre_join = ', '
        score.DetailedResults.append({'Score': ueba_mitre_score, 'ScoreSource': f'{label} - {ueba.AnomalyTacticsCount} Anomaly MITRE Tactics ({mitre_join.join(ueba.AnomalyTactics)})'})
        score.add(ueba_mitre_score)
