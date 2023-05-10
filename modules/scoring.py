from classes import BaseModule, Response, ScoringModule, STATError
from shared import data

def execute_scoring_module (req_body):

    #Inputs AddIncidentComments, AddIncidentTask, BaseModuleBody, IncidentTaskInstructions, ScoringData

    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])

    score = ScoringModule()

    for input_module in req_body['ScoringData']:
        module = input_module['ModuleBody'].get('ModuleName')
        if module == 'WatchlistModule':
            None
        elif module == 'AADRisksModule':
            None
        elif module == 'FileModule':
            None
        elif module == 'KQLModule':
            None
        elif module == 'MCASModule':
            None
        elif module == 'MDEModule':
            None
        elif module == 'RelatedAlerts':
            None
        elif module == 'TIModule':
            None
        elif module == 'UEBAModule':
            None
        elif module == 'Custom':
            None
        else:
            raise STATError(f'Incorrectly formatted data or data from an unsupported module was passed to the Scoring Module, module name: {module}')

   

    # if req_body.get('AddIncidentComments', True):
        
    #     html_table = data.list_to_html_table(results)

    #     comment = f'''A total of {watchlist_object.EntitiesOnWatchlistCount} records were found on the {watchlist_object.WatchlistName} watchlist.<br>{html_table}'''
    #     comment_result = rest.add_incident_comment(base_object.IncidentARMId, comment)

    # if req_body.get('AddIncidentTask', False) and watchlist_object.EntitiesOnWatchlist:
    #     task_result = rest.add_incident_task(base_object.IncidentARMId, 'Review Watchlist Matches', req_body.get('IncidentTaskInstructions'))


    return Response(score)