from azure.identity import DefaultAzureCredential
import requests
import datetime as dt
import json
import os
import uuid

armtoken = None
msgraphtoken = None
latoken = None
m365token = None
mdetoken = None
graph_endpoint = os.getenv('GRAPH_ENDPOINT')
arm_endpoint = os.getenv('ARM_ENDPOINT')
la_endpoint = os.getenv('LOGANALYTICS_ENDPOINT')
m365_endpoint = os.getenv('M365_ENDPOINT')
mde_endpoint = os.getenv('MDE_ENDPOINT')

def token_cache(api):
    global armtoken
    global msgraphtoken
    global latoken
    global m365token
    global mdetoken

    if api == 'arm':
        token_expiration_check(api, armtoken)
        return armtoken
    elif api == 'msgraph':
        token_expiration_check(api, msgraphtoken) 
        return msgraphtoken
    elif api == 'la':
        token_expiration_check(api, latoken)
        return latoken
    elif api == 'm365':
        token_expiration_check(api, m365token)
        return m365token
    elif api == 'mde':
        token_expiration_check(api, mdetoken)
        return mdetoken

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
    global m365token
    global mdetoken
    
    cred = DefaultAzureCredential()

    if api == 'arm':
        armtoken = cred.get_token("https://" + arm_endpoint + "/.default")
    elif api == 'msgraph':
        msgraphtoken = cred.get_token("https://" + graph_endpoint + "/.default")
    elif api == 'la':
        latoken = cred.get_token("https://" + la_endpoint + "/.default")
    elif api == 'm365':
        m365token = cred.get_token("https://" + m365_endpoint + "/.default")
    elif api == 'mde':
        mdetoken = cred.get_token("https://" + mde_endpoint + "/.default")

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

def execute_m365d_query(query):
    token = token_cache('m365')
    url = get_endpoint('m365') + '/api/advancedhunting/run'
    body = {'Query': query}
    response = requests.post(url=url, json=body, headers={"Authorization": "Bearer " + token.token})
    return json.loads(response.content)['Results']

def execute_mde_query(query):
    token = token_cache('mde')
    url = get_endpoint('mde') + '/api/advancedqueries/run'
    body = {'Query': query}
    response = requests.post(url=url, json=body, headers={"Authorization": "Bearer " + token.token})
    return json.loads(response.content)

def get_endpoint(api):
    if api == 'arm':
        return 'https://' + arm_endpoint
    elif api == 'msgraph':
        return 'https://' + graph_endpoint
    elif api == 'la':
        return 'https://' + la_endpoint
    elif api == 'm365':
        return 'https://' + m365_endpoint
    elif api == 'mde':
        return 'https://' + mde_endpoint
    
def add_incident_comment(incident_armid, comment):
    token = token_cache('arm')
    endpoint = get_endpoint('arm')
    url = endpoint + incident_armid + '/comments/' + str(uuid.uuid4()) + '?api-version=2023-02-01'
    return requests.put(url=url, json={'properties': {'message': comment[:30000]}}, headers={"Authorization": "Bearer " + token.token})

def add_incident_task(incident_armid, title, description, status='New'):
    token = token_cache('arm')
    endpoint = get_endpoint('arm')
    url = endpoint + incident_armid + '/tasks/' + str(uuid.uuid4()) + '?api-version=2023-04-01-preview'

    if description is None or description == '':
        return requests.put(url=url, json={'properties': {'title': title, 'status': status}}, headers={"Authorization": "Bearer " + token.token})
    else:
        return requests.put(url=url, json={'properties': {'title': title, 'description': description[:3000], 'status': status}}, headers={"Authorization": "Bearer " + token.token})
    