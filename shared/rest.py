from azure.identity import DefaultAzureCredential
import requests
import datetime as dt

token = None

def token_cache():
    global token

    if token is None:
        acquire_token()
    else:
        expiration_time = dt.datetime.fromtimestamp(token.expires_on) - dt.timedelta(minutes=5)
        current_time = dt.datetime.now()

        if current_time > expiration_time:
            acquire_token()      

def acquire_token():
    global token
    
    cred = DefaultAzureCredential()
    token = cred.get_token("https://management.azure.com/.default")
      

def rest_call_get(url):
    token_cache()
    return requests.get(url=url, headers={"Authorization": "Bearer " + token.token})
    