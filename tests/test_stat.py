from modules import base, relatedalerts, watchlist, kql, ti, ueba, oof, scoring, aadrisks, mdca, mde, file
from classes import Response
import json, os, requests


def test_base_module_incident():
    base_response:Response = base.execute_base_module(get_incident_trigger_data())

    assert base_response.statuscode == 200
    assert base_response.body.AccountsCount == 2
    assert len(base_response.body.Accounts) == base_response.body.AccountsCount
    assert len(base_response.body.Domains) == base_response.body.DomainsCount
    assert len(base_response.body.FileHashes) == base_response.body.FileHashesCount
    assert len(base_response.body.Files) == base_response.body.FilesCount
    assert len(base_response.body.Hosts) == base_response.body.HostsCount
    assert len(base_response.body.IPs) == base_response.body.IPsCount
    assert len(base_response.body.URLs) == base_response.body.URLsCount
    assert len(base_response.body.OtherEntities) == base_response.body.OtherEntitiesCount


def test_base_module_alert():
    base_response:Response = base.execute_base_module(get_alert_trigger_data())

    assert base_response.statuscode == 200
    assert len(base_response.body.Accounts) == base_response.body.AccountsCount
    assert len(base_response.body.Domains) == base_response.body.DomainsCount
    assert len(base_response.body.FileHashes) == base_response.body.FileHashesCount
    assert len(base_response.body.Files) == base_response.body.FilesCount
    assert len(base_response.body.Hosts) == base_response.body.HostsCount
    assert len(base_response.body.IPs) == base_response.body.IPsCount
    assert len(base_response.body.URLs) == base_response.body.URLsCount
    assert len(base_response.body.OtherEntities) == base_response.body.OtherEntitiesCount

def test_related_alerts():
    alerts_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'CheckAccountEntityMatches': True,
        'CheckHostEntityMatches': True,
        'CheckIPEntityMatches': True,
        'AlertKQLFilter': None,
        'IncidentTaskInstructions': "",
        'LookbackInDays': 20,
        'BaseModuleBody': get_base_module_body(),
    }
    alerts_response:Response = relatedalerts.execute_relatedalerts_module(alerts_input)

    assert alerts_response.statuscode == 200
    assert alerts_response.body.RelatedAlertsFound == True
    assert alerts_response.body.RelatedAccountAlertsFound == True

def test_threat_intel():
    ti_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'IncidentTaskInstructions': '',
        'BaseModuleBody': get_base_module_body(),
    }
    ti_response:Response = ti.execute_ti_module(ti_input)

    assert ti_response.statuscode == 200
    assert ti_response.body.AnyTIFound == True
    assert ti_response.body.IPTIFound == True

def test_watchlist_upn():
    watchlist_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'WatchlistName': 'VIPUsers',
        'WatchlistKey': 'SearchKey',
        'WatchlistKeyDataType': 'UPN',
        'BaseModuleBody': get_base_module_body()
    }
    watchlist_response:Response = watchlist.execute_watchlist_module(watchlist_input)

    assert watchlist_response.statuscode == 200
    assert watchlist_response.body.EntitiesOnWatchlist == True
    assert watchlist_response.body.EntitiesOnWatchlistCount == 1

def test_watchlist_ip():
    watchlist_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'WatchlistName': 'IPWatchlist',
        'WatchlistKey': 'SearchKey',
        'WatchlistKeyDataType': 'IP',
        'BaseModuleBody': get_base_module_body()
    }
    watchlist_response:Response = watchlist.execute_watchlist_module(watchlist_input)

    assert watchlist_response.statuscode == 200
    assert watchlist_response.body.EntitiesOnWatchlist == True
    assert watchlist_response.body.EntitiesOnWatchlistCount == 1

def test_watchlist_cidr():
    watchlist_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'WatchlistName': 'NetworkAddresses',
        'WatchlistKey': 'SearchKey',
        'WatchlistKeyDataType': 'CIDR',
        'BaseModuleBody': get_base_module_body()
    }
    watchlist_response:Response = watchlist.execute_watchlist_module(watchlist_input)

    assert watchlist_response.statuscode == 200
    assert watchlist_response.body.EntitiesOnWatchlist == True
    assert watchlist_response.body.EntitiesOnWatchlistCount == 1

def test_watchlist_fqdn():
    watchlist_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'WatchlistName': 'HighValueAssets',
        'WatchlistKey': 'SearchKey',
        'WatchlistKeyDataType': 'FQDN',
        'BaseModuleBody': get_base_module_body()
    }
    watchlist_response:Response = watchlist.execute_watchlist_module(watchlist_input)

    assert watchlist_response.statuscode == 200
    assert watchlist_response.body.EntitiesOnWatchlist == True
    assert watchlist_response.body.EntitiesOnWatchlistCount == 1

def test_kql_sentinel():
    kql_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'KQLQuery': 'SigninLogs | take 5 | project UserPrincipalName',
        'RunQueryAgainst': 'Sentinel',
        'QueryDescription': 'Test Query',
        'LookbackInDays': 30,
        'BaseModuleBody': get_base_module_body()
    }
    kql_response:Response = kql.execute_kql_module(kql_input)

    assert kql_response.statuscode == 200
    assert kql_response.body.ResultsCount == 5

def test_kql_m365():
    kql_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'KQLQuery': 'DeviceInfo | take 5 | project DeviceId',
        'RunQueryAgainst': 'M365',
        'QueryDescription': 'Test Query',
        'LookbackInDays': 30,
        'BaseModuleBody': get_base_module_body()
    }
    kql_response:Response = kql.execute_kql_module(kql_input)

    assert kql_response.statuscode == 200
    assert kql_response.body.ResultsCount == 5

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

def test_oof():
    oof_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'BaseModuleBody': get_base_module_body()
    }
    oof_response:Response = oof.execute_oof_module(oof_input)

    assert oof_response.statuscode == 200

def test_aad_risks():
    aad_input = {
        'AddIncidentComments': False,
        'AddIncidentTask': False,
        'LookbackInDays': 14,
        'BaseModuleBody': get_base_module_body()
    }
    aad_response:Response = aadrisks.execute_aadrisks_module(aad_input)

    assert aad_response.statuscode == 200

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

def get_incident_trigger_data():
    trigger_data = json.loads(requests.get(url=os.getenv('INCIDENTDATA')).content)
    return trigger_data

def get_alert_trigger_data():
    trigger_data = json.loads(requests.get(url=os.getenv('ALERTDATA')).content)
    return trigger_data

def get_scoring_data():
    scoring_data = json.loads(requests.get(url=os.getenv('SCORINGDATA')).content)
    return scoring_data
