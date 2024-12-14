from modules import watchlist
from classes import Response
import json, os, requests

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

def get_base_module_body():
    base_module_body = json.loads(requests.get(url=os.getenv('BASEDATA')).content)
    return base_module_body