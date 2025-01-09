from modules import ueba, exchange, scoring, mdca, mde, file
from classes import Response
import json, os, requests

def test_ueba():
    ueba_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'MinimumInvestigationPriority': 2,
        'LookbackInDays': 60,
        'BaseModuleBody': get_base_module_body()
    }
    ueba_response:Response = ueba.execute_ueba_module(ueba_input)

    assert ueba_response.statuscode == 200
    assert ueba_response.body.InvestigationPrioritiesFound in (True, False)

def test_exchange():
    exch_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'BaseModuleBody': get_base_module_body()
    }
    exch_response:Response = exchange.execute_exchange_module(exch_input)

    assert exch_response.statuscode == 200

def test_mde_module():
    aad_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'LookbackInDays': 14,
        'BaseModuleBody': get_base_module_body()
    }
    mde_response:Response = mde.execute_mde_module(aad_input)

    assert mde_response.statuscode == 200

def test_mdca_module():
    mdca_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'ScoreThreshold': 1,
        'BaseModuleBody': get_base_module_body()
    }
    mdca_response:Response = mdca.execute_mdca_module(mdca_input)

    assert mdca_response.statuscode == 200

def test_file_module():
    file_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'BaseModuleBody': get_base_module_body()
    }
    file_response:Response = file.execute_file_module(file_input)

    assert file_response.statuscode == 200
    assert file_response.body.HashesLinkedToThreatCount > 0

def test_scoring():
    scoring_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'ScoringData': get_scoring_data(),
        'BaseModuleBody': get_base_module_body()
    }
    scoring_response:Response = scoring.execute_scoring_module(scoring_input)

    assert scoring_response.statuscode == 200
    assert scoring_response.body.TotalScore == 532

def get_base_module_body():
    base_module_body = json.loads(requests.get(url=os.getenv('BASEDATA')).content)
    return base_module_body

def get_scoring_data():
    scoring_data = json.loads(requests.get(url=os.getenv('SCORINGDATA')).content)
    return scoring_data
