from azure.identity import DefaultAzureCredential
import requests
import datetime as dt
import os

armtoken = None
msgraphtoken = None
graph_endpoint = os.getenv('GRAPH_ENDPOINT')
arm_endpoint = os.getenv('ARM_ENDPOINT')

def token_cache(api):
    global armtoken
    global msgraphtoken

    if api == 'arm':
        token_expiration_check(api, armtoken)
        return armtoken
    elif api == 'msgraph':
        token_expiration_check(api, msgraphtoken) 
        return msgraphtoken

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
    
    cred = DefaultAzureCredential()

    if api == 'arm':
        armtoken = cred.get_token("https://" + arm_endpoint + "/.default")
    elif api == 'msgraph':
        msgraphtoken = cred.get_token("https://" + graph_endpoint + "/.default")


def rest_call_get(api, path):
    token = token_cache(api)
    url = get_endpoint(api) + path
    return requests.get(url=url, headers={"Authorization": "Bearer " + token.token})

def get_endpoint(api):
    if api == 'arm':
        return 'https://' + arm_endpoint
    elif api == 'msgraph':
        return 'https://' + graph_endpoint
    