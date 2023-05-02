from azure.identity import DefaultAzureCredential
import requests
import datetime as dt
import json
import os

armtoken = None
msgraphtoken = None
latoken = None
graph_endpoint = os.getenv('GRAPH_ENDPOINT')
arm_endpoint = os.getenv('ARM_ENDPOINT')
la_endpoint = os.getenv('LOGANALYTICS_ENDPOINT')

def token_cache(api):
    global armtoken
    global msgraphtoken
    global latoken

    if api == 'arm':
        token_expiration_check(api, armtoken)
        return armtoken
    elif api == 'msgraph':
        token_expiration_check(api, msgraphtoken) 
        return msgraphtoken
    elif api == 'la':
        token_expiration_check(api, latoken)
        return latoken

def token_expiration_check(api, token):
    
    if token is None:
        acquire_token(api)
    else:
        expiration_time = dt.datetime.fromtimestamp(token.expires_on) - dt.timedelta(minutes=5)
        current_time = dt.datetime.now()

        if current_time > expiration_time:
            acquire_token(api) 

def acquire_token(api):
    global armtoken
    global msgraphtoken
    global latoken
    
    cred = DefaultAzureCredential()

    if api == 'arm':
        armtoken = cred.get_token("https://" + arm_endpoint + "/.default")
    elif api == 'msgraph':
        msgraphtoken = cred.get_token("https://" + graph_endpoint + "/.default")
    elif api == 'la':
        latoken = cred.get_token("https://" + la_endpoint + "/.default")


def rest_call_get(api, path):
    token = token_cache(api)
    url = get_endpoint(api) + path
    return requests.get(url=url, headers={"Authorization": "Bearer " + token.token})

def rest_call_post(api, path, body):
    token = token_cache(api)
    url = get_endpoint(api) + path
    return requests.post(url=url, json=body, headers={"Authorization": "Bearer " + token.token})

def execute_la_query(workspaceid, query, lookbackindays):
    token = token_cache('la')
    url = get_endpoint('la') + '/v1/workspaces/' + workspaceid + '/query'
    duration = 'P' + str(lookbackindays) + 'D'
    body = {'query': query, 'timespan': duration}
    response = requests.post(url=url, json=body, headers={"Authorization": "Bearer " + token.token})
    data = json.loads(response.content)
 
    columns = data['tables'][0]['columns']
    rows = data['tables'][0]['rows']
    columnlist = []
    query_results = []

    for column in columns:
        columnlist.append(column['name'])

    for row in rows:
        query_results.append(dict(zip(columnlist,row)))

    return query_results

def get_endpoint(api):
    if api == 'arm':
        return 'https://' + arm_endpoint
    elif api == 'msgraph':
        return 'https://' + graph_endpoint
    elif api == 'la':
        return 'https://' + la_endpoint
    