from classes import BaseModule, Response, AADInsightsModule, STATError, STATNotFound
from shared import rest, data
from datetime import datetime
import json

def execute_aadinsights_module (req_body):

    #Inputs NewThresholdInDays, LookbackInDays, AddIncidentComments, AddIncidentTask, Entities, IncidentTaskInstructions, LookbackInDays, NewThresholdInDays

    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])

    aadinsights_object = AADInsightsModule()
    new_threshold = req_body.get('NewThresholdInDays', 7)
    lookback = req_body.get('LookbackInDays', 30)

    
    people_top = 10
    for account in base_object.Accounts:
        userid = account.get('id')

        if userid:
            upn = account.get('userPrincipalName')
            current_account = {
                'UserId': f'{userid}',
                'UserPrincipalName': f'{upn}',
                'IsNewUser': False,
                'CommonLocations': [],
                'CommonIPs' : [],
                'CommonDevices': '[]]',
                'RecentActivities': [],
                'UserCreationTime': None,
                'People': []
            }
            # Build related people list
            path = f'/v1.0/users/{userid}/people/?$select=id,userPrincipalName&$top={people_top}'
            try:
                people_list = json.loads(rest.rest_call_get(base_object, api='msgraph', path=path).content)
                current_account['People'] = [item["id"] for item in people_list["value"]]
            except STATNotFound:
                pass
            # to do - handle permission error?

            # Check if the user is new
            try:
                user_creation_time = datetime.strptime(account.get('createdDateTime'), "%Y-%m-%dT%H:%M:%SZ")
                current_account['UserCreationTime'] = account.get('createdDateTime')
                if (datetime.now() - user_creation_time ).days > new_threshold:
                    current_account['IsNewUser'] = False
                else:
                    current_account['IsNewUser'] = True
            except:
                current_account['IsNewUser'] = False

            CommonLocations_query = f'''
            let TopIPs = materialize( SigninLogs
            | where TimeGenerated > ago({lookback}d)
            | where UserId == "{userid}"
            | where ResultType == 0
            | extend CommonLocation = strcat( LocationDetails.city, ", ", LocationDetails.state, ", ", LocationDetails.countryOrRegion)
            | extend CommonLocation = iif(CommonLocation == ", , ", "Unknown", CommonLocation)
            | summarize TotalUser = count() by CommonLocation
            | join kind=leftouter(
                SigninLogs
                | where TimeGenerated > ago({lookback}d)
                | where UserId != "{userid}"
                | where ResultType == 0
                | extend CommonLocation = strcat( LocationDetails.city, ", ", LocationDetails.state, ", ", LocationDetails.countryOrRegion)
                | extend CommonLocation = iif(CommonLocation == ", , ", "Unknown", CommonLocation)
                | summarize TotalTenant = count() by CommonLocation
            ) on CommonLocation
            | project-away CommonLocation1
            | extend TotalTenant = iif( isempty(TotalTenant), 0, TotalTenant)
            | order by TotalUser desc
            | serialize Top = row_number()
            );
            let TopOthers = TopIPs | where Top > 9 | summarize TotalUser = sum(TotalUser) | extend CommonLocation = "Others", Top = 10;
            TopIPs | where Top <= 9
            | union TopOthers
            | where TotalUser != 0
            | order by Top asc
            | project-reorder Top, CommonLocation, TotalUser'''
            CommonLocations_results = rest.execute_la_query(base_object, CommonLocations_query, lookback)
            if CommonLocations_results:
                current_account['CommonLocations'] = CommonLocations_results
            
            CommonIPs_query = f'''
            let TopIPs = materialize( SigninLogs
            | where TimeGenerated > ago({lookback}d)
            | where UserId == "{userid}"
            | where ResultType == 0
            | summarize TotalUser = count() by IPAddress
            | join kind=leftouter(
                SigninLogs
                | where TimeGenerated > ago({lookback}d)
                | where UserId != "{userid}"
                | where ResultType == 0
                | summarize TotalTenant = count() by IPAddress
            ) on IPAddress
            | project-away IPAddress1
            | extend TotalTenant = iif( isempty(TotalTenant), 0, TotalTenant)
            | order by TotalUser desc
            | serialize Top = row_number()
            );
            let TopOthers = TopIPs | where Top > 9 | summarize TotalUser = sum(TotalUser) | extend IPAddress = "Others", Top = 10;
            TopIPs | where Top <= 9
            | union TopOthers
            | where TotalUser != 0
            | order by Top asc
            | project-reorder Top, IPAddress, TotalUser'''
            CommonIPs_results = rest.execute_la_query(base_object, CommonIPs_query, lookback)
            if CommonIPs_results:
                current_account['CommonIPs'] = CommonIPs_results
            
            CommonDevices_query = f'''
            SigninLogs
            | where TimeGenerated > ago({lookback}d)
            | where ResultType == 0
            | where UserId == "{userid}"
            | where isnotempty(DeviceDetail.deviceId)
            | distinct DeviceName = tostring(DeviceDetail.displayName), DeviceOS = tostring(DeviceDetail.operatingSystem)'''
            CommonDevices_results = rest.execute_la_query(base_object, CommonDevices_query, lookback)
            if CommonDevices_results:
                current_account['CommonDevices'] = CommonDevices_results
            
            RecentActivities_query = f'''
            AuditLogs
            | where TimeGenerated > ago({lookback}d)
            | where Result =~ "success"
            | where OperationName has_any ("Consent to application","Reset user password","Change password (self-service)","Reset password (self-service)","User registered security info","Register device","User deleted security info","User changed default security info","Add service principal credentials","Update StsRefreshTokenValidFrom Timestamp")
            | mv-apply TargetResources on (
                where TargetResources.id == "{userid}"
            )
            | project TimeGenerated, OperationName
            | order by TimeGenerated desc'''
            RecentActivities_results = rest.execute_la_query(base_object, RecentActivities_query, lookback)
            if RecentActivities_results:
                current_account['RecentActivities'] = RecentActivities_results
                    
            aadinsights_object.DetailedResults.append(current_account)

    for account in base_object.Accounts:
        userid = account.get('id')
        if userid in [person for item in aadinsights_object.DetailedResults for person in item.get("People", [])]:
            aadinsights_object.RelatedUsers = True
            break #don't to continue if we already found a related user

    for ip in base_object.IPs:
        ipaddress = ip.get('Address')
        current_ip = {
                'IPAddress': f'{ipaddress}',
                'IPPrevelanceSuccess': 0,
                'IPPrevelanceWrongPassword': 0,
                'IPPrevelanceFirstTimeSeenInScope': None,
                'IPType': ip.get('IPType')
            }
        #Need to handle case where the IP is a private IP RFC1918
        IPPrevelance_query = f'''
        SigninLogs
        | where TimeGenerated > ago({lookback}d)
        | where IPAddress == "{ipaddress}"
        | where ResultType in (0, 50126)
        | summarize IPSuccess = countif(ResultType == 0), IPWrongPassword = countif(ResultType == 50126), FirstTimeSeenInScope = min(TimeGenerated)'''
        IPPrevelance_results = rest.execute_la_query(base_object, IPPrevelance_query, lookback)
        if IPPrevelance_results:
            current_ip['IPPrevelanceSuccess'] = IPPrevelance_results[0]['IPSuccess']
            current_ip['IPPrevelanceWrongPassword'] = IPPrevelance_results[0]['IPWrongPassword']
            current_ip['IPPrevelanceFirstTimeSeenInScope'] = IPPrevelance_results[0]['FirstTimeSeenInScope']
        
        aadinsights_object.IPDetails.append(current_ip)

    for host in base_object.Hosts:
        hostaadid = host.get('RawEntity', {}).get('additionalData', {}).get('AadDeviceId')
        hostname = host.get("FQDN", "Unknown")
        if hostaadid:
            current_host = {
                'HostAadId': f'{hostaadid}',
                'HostName': f'{hostname}',
                'HostCreationTime': None,
                'IsNewHost': False
            }
            path = f'/v1.0/devices/{hostaadid}'
            try:
                host_creation_time = json.loads(rest.rest_call_get(base_object, api='msgraph', path=path).content)['createdDateTime']
                current_host['HostCreationTime'] = datetime.strptime(host_creation_time, "%Y-%m-%dT%H:%M:%SZ")
                if (datetime.now() - host_creation_time ).days > new_threshold:
                    current_host['IsNewHost'] = False
                else:
                    current_host['IsNewHost'] = True
            except STATNotFound:
                pass
            else:
                current_host['IsNewHost'] = False

            aadinsights_object.HostDetails.append(current_host)

    entities_nb = len(aadinsights_object.DetailedResults) + len(aadinsights_object.IPDetails) + len(aadinsights_object.HostDetails)
    if entities_nb != 0:
        aadinsights_object.AnalyzedEntities = entities_nb
        aadinsights_object.NewUsersCount = sum(1 for item in aadinsights_object.DetailedResults if item.get("IsNewUser") == True)
        aadinsights_object.NewDevicesCount = sum(1 for item in aadinsights_object.HostDetails if item.get("IsNewUser") == True)
    
    if req_body.get('AddIncidentComments', True):
        comment = f'<h3>Entra ID Insights Module - (Last {lookback} days)</h3>'
        for item in aadinsights_object.DetailedResults:
            comment += f'<h4>👤 {item.get("UserPrincipalName", item.get("UserId", "Unknown"))}</h4>'
            comment += f'<ul><li>Creation Time: {item.get("UserCreationTime","Unknown")} '
            if item.get("IsNewUser", True):
                comment += f' 🆕 (created within {new_threshold})'
            comment += f'</li>'
            #Common Locations
            html_table = data.list_to_html_table(item.get('CommonLocations'), index=False, columns=['Top','CommonLocation','TotalUser','TotalTenant']) if item.get('CommonLocations') else 'No location details available<br />'
            comment += f'<h4>Common Locations</h4>{html_table}'
            #Common IPs
            html_table = data.list_to_html_table(item.get('CommonIPs'), index=False, columns=['Top','IPAddress','TotalUser','TotalTenant']) if item.get('CommonIPs') else 'No IP details available<br />'
            comment += f'<h4>Common IPs</h4>{html_table}'
            #Common Devices
            html_table = data.list_to_html_table(item.get('CommonDevices'), index=False, columns=['DeviceName','DeviceOS']) if item.get('CommonDevices') else 'No IP details available<br />'
            comment += f'<h4>Common Devices</h4>{html_table}'
            #Recent Ativities
            html_table = data.list_to_html_table(item.get('RecentActivities'), index=False, columns=['TimeGenerated','OperationName']) if item.get('RecentActivities') else 'No activity found<br />'
            comment += f'<h4>Recent Activities</h4>{html_table}</ul>'

        for item in aadinsights_object.IPDetails:
            comment += f'<h4>🌐 {item.get("IPAddress")}</h4>'
            if item.get('IPType') != 2:
                comment += f'<ul><li>Number of successes in the tenant: {item.get("IPPrevelanceSuccess")} </li>'
                comment += f'<li>Number of failed password attempts in the tenant: {item.get("IPPrevelanceWrongPassword")} </li>' 
                comment += f'<li>Last time we saw this IP: {item.get("IPPrevelanceWrongPassword")} (within the last {lookback} days)</li></ul>' 
            else:
                comment += f'<ul><li>IP type: Private IP (RFC1918)</li></ul>'

        for item in aadinsights_object.HostDetails:
            comment += f'<h4>💻 {item.get("HostName")}</h4>'
            comment += f'<ul><li>Creation Time: {item.get("HostCreationTime","Unknown")} '
            if item.get("IsNewHost", True):
                comment += f' 🆕 (created within {new_threshold})'
            comment += f'</li></ul>'

        comment_result = rest.add_incident_comment(base_object, comment)
        
        if req_body.get('AddIncidentTask', False):
            if aadinsights_object.NewUsersCount > 0 or aadinsights_object.NewDevicesCount > 0 or aadinsights_object.RelatedUsers:
                ask_result = rest.add_incident_task(base_object, req_body.get('QueryDescription', 'Review new users and devices, and take in consideration related users'), req_body.get('IncidentTaskInstructions'))

    return Response(aadinsights_object)
