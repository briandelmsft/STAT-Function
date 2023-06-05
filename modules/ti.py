from classes import BaseModule, Response, TIModule, STATError
from shared import rest, data

def execute_ti_module (req_body):

    #Inputs AddIncidentComments, AddIncidentTask, BaseModuleBody, IncidentTaskInstructions, CheckDomains, CheckFileHashes, CheckIPs, CheckURLs

    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])

    ti_object = TIModule()

    check_domains = req_body.get('CheckDomains', True)
    check_filehashes = req_body.get('CheckFileHashes', True)
    check_ips = req_body.get('CheckIPs', True)
    check_urls = req_body.get('CheckURLs', True)

    if check_domains and base_object.Domains:
        query = base_object.get_domain_kql_table() + '''domainEntities
| extend DomainName = tolower(Domain)
| join kind=inner (ThreatIntelligenceIndicator
| extend DomainName = coalesce(DomainName, EmailSourceDomain)
| where isnotempty(DomainName)
| summarize arg_max(TimeGenerated, *) by IndicatorId
| where Active
| extend DomainName = tolower(DomainName)) on DomainName
| project TIType="Domain", TIData=Domain, SourceSystem, Description, ThreatType, ConfidenceScore, IndicatorId'''
        results = rest.execute_la_query(base_object, query, 14)
        ti_object.DetailedResults = ti_object.DetailedResults + results
        ti_object.DomainEntitiesCount = len(base_object.get_domain_list())
        ti_object.DomainEntitiesWithTI = len(results)
        ti_object.DomainTIFound = bool(results)
    
    if check_filehashes and base_object.FileHashes:
        query = base_object.get_filehash_kql_table() + '''hashEntities
| extend FileHash = tolower(FileHash)
| join kind=inner (ThreatIntelligenceIndicator
| where isnotempty(FileHashValue)
| summarize arg_max(TimeGenerated, *) by IndicatorId
| where Active
| extend FileHash = tolower(FileHashValue)) on FileHash
| project TIType="FileHash", TIData=FileHash, SourceSystem, Description, ThreatType, ConfidenceScore, IndicatorId'''
        results = rest.execute_la_query(base_object, query, 14)
        ti_object.DetailedResults = ti_object.DetailedResults + results
        ti_object.FileHashEntitiesCount = len(base_object.get_filehash_list())
        ti_object.FileHashEntitiesWithTI = len(results)
        ti_object.FileHashTIFound = bool(results)

    if check_ips and base_object.IPs:
        query = base_object.get_ip_kql_table() + '''ipEntities
| join kind=inner (ThreatIntelligenceIndicator
| extend tiIP = coalesce(NetworkIP, NetworkSourceIP, NetworkDestinationIP, EmailSourceIpAddress)
| where isnotempty(tiIP)
| summarize arg_max(TimeGenerated, *) by IndicatorId
| where Active) on $left.IPAddress == $right.tiIP
| project TIType="IP", TIData=IPAddress, SourceSystem, Description, ThreatType, ConfidenceScore, IndicatorId'''
        results = rest.execute_la_query(base_object, query, 14)
        ti_object.DetailedResults = ti_object.DetailedResults + results
        ti_object.IPEntitiesCount = len(base_object.get_ip_list())
        ti_object.IPEntitiesWithTI = len(results)
        ti_object.IPTIFound = bool(results)

    if check_urls and base_object.URLs:
        query = base_object.get_url_kql_table() + '''urlEntities
| extend Url = tolower(Url)
| join kind=inner (ThreatIntelligenceIndicator
| where isnotempty(Url)
| summarize arg_max(TimeGenerated, *) by IndicatorId
| where Active
| extend Url = tolower(Url)) on Url
| extend Url = strcat('[', tostring(split(Url, '//')[0]), ']//', tostring(split(Url, '//')[1]))
| project TIType="URL", TIData=Url, SourceSystem, Description, ThreatType, ConfidenceScore, IndicatorId'''
        results = rest.execute_la_query(base_object, query, 14)
        ti_object.DetailedResults = ti_object.DetailedResults + results
        ti_object.URLEntitiesCount = len(base_object.get_url_list())
        ti_object.URLEntitiesWithTI = len(results)
        ti_object.URLTIFound = bool(results)

    ti_object.AnyTIFound = bool(ti_object.DetailedResults)
    ti_object.TotalTIMatchCount = len(ti_object.DetailedResults)

    if req_body.get('AddIncidentComments', True) and base_object.IncidentAvailable:
        
        html_table = data.list_to_html_table(ti_object.DetailedResults)

        comment = f'''A total of {ti_object.TotalTIMatchCount} records were found with matching Threat Intelligence data.<br>{html_table}'''
        comment_result = rest.add_incident_comment(base_object, comment)

    if req_body.get('AddIncidentTask', False) and ti_object.AnyTIFound and base_object.IncidentAvailable:
        task_result = rest.add_incident_task(base_object, 'Review Threat Intelligence Matches', req_body.get('IncidentTaskInstructions'))

    return Response(ti_object)