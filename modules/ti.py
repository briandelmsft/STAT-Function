from classes import BaseModule, Response, TIModule, STATError
from shared import rest, data
import logging

def execute_ti_module (req_body):
    
    # Log module invocation with parameters (excluding BaseModuleBody)
    log_params = {k: v for k, v in req_body.items() if k != 'BaseModuleBody'}
    logging.info(f'Threat Intelligence Module invoked with parameters: {log_params}')

    #Inputs AddIncidentComments, AddIncidentTask, BaseModuleBody, IncidentTaskInstructions, CheckDomains, CheckFileHashes, CheckIPs, CheckURLs

    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])

    ti_object = TIModule()

    check_domains = req_body.get('CheckDomains', True)
    check_filehashes = req_body.get('CheckFileHashes', True)
    check_ips = req_body.get('CheckIPs', True)
    check_urls = req_body.get('CheckURLs', True)

    if all((not(check_domains), not(check_filehashes), not(check_ips), not(check_urls))):
        raise STATError('The Threat Intelligence module was excuted, but all TI checks were disabled.')

    if check_domains and base_object.Domains:
        query = base_object.get_domain_kql_table() + '''domainEntities
| extend DomainName = tolower(Domain)
| join kind=inner (ThreatIntelIndicators
| where ObservableKey =~ "domain-name:value"
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by Id, ObservableValue
| where IsActive and (ValidUntil > now() or isempty(ValidUntil))
| extend DomainName = tolower(ObservableValue)) on DomainName
| project TIType="Domain", TIData=DomainName, SourceSystem, Description=tostring(Data.description), ThreatType=tostring(array_strcat(Data.indicator_types, ', ')), ConfidenceScore=Confidence, IndicatorId=Id'''
        results = rest.execute_la_query(base_object, query, 14)
        ti_object.DetailedResults = ti_object.DetailedResults + results
        ti_object.DomainEntitiesCount = len(base_object.get_domain_list())
        ti_object.DomainEntitiesWithTI = len(results)
        ti_object.DomainTIFound = bool(results)
    
    if check_filehashes and base_object.FileHashes:
        query = base_object.get_filehash_kql_table() + '''hashEntities
| extend FileHash = tolower(FileHash)
| join kind=inner (ThreatIntelIndicators
| where ObservableKey in~ ("file:hashes.'SHA-1'","file:hashes.'SHA-256'","file:hashes.MD5","file:hashes.'MD5'")
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by Id, ObservableValue
| where IsActive and (ValidUntil > now() or isempty(ValidUntil))
| extend FileHash = tolower(ObservableValue)) on FileHash
| project TIType="FileHash", TIData=FileHash, SourceSystem, Description=tostring(Data.description), ThreatType=tostring(array_strcat(Data.indicator_types, ', ')), ConfidenceScore=Confidence, IndicatorId=Id'''
        results = rest.execute_la_query(base_object, query, 14)
        ti_object.DetailedResults = ti_object.DetailedResults + results
        ti_object.FileHashEntitiesCount = len(base_object.get_filehash_list())
        ti_object.FileHashEntitiesWithTI = len(results)
        ti_object.FileHashTIFound = bool(results)

    if check_ips and base_object.IPs:
        query = base_object.get_ip_kql_table() + '''ipEntities
| join kind=inner (ThreatIntelIndicators
| where ObservableKey in~ ("network-traffic:src_ref.value","network-traffic:dst_ref.value","ipv4-addr:value","ipv6-addr:value")
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by Id, ObservableValue
| where IsActive and (ValidUntil > now() or isempty(ValidUntil))
| extend IPAddress = tolower(ObservableValue)
) on IPAddress
| project TIType="IP", TIData=IPAddress, SourceSystem, Description=tostring(Data.description), ThreatType=tostring(array_strcat(Data.indicator_types, ', ')), ConfidenceScore=Confidence, IndicatorId=Id'''
        results = rest.execute_la_query(base_object, query, 14)
        ti_object.DetailedResults = ti_object.DetailedResults + results
        ti_object.IPEntitiesCount = len(base_object.get_ip_list())
        ti_object.IPEntitiesWithTI = len(results)
        ti_object.IPTIFound = bool(results)

    if check_urls and base_object.URLs:
        query = base_object.get_url_kql_table() + '''let entities = urlEntities
| extend Url = tolower(Url)
| extend DomainName = parse_url(Url)
| extend DomainName = coalesce(DomainName.Host, Url);
union isfuzzy=true
(entities
| join kind=inner (ThreatIntelIndicators
| where ObservableKey =~ "url:value"
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by Id, ObservableValue
| where IsActive and (ValidUntil > now() or isempty(ValidUntil))
| extend Url = tolower(ObservableValue)) on Url
| extend Url = strcat('[', tostring(split(Url, '//')[0]), ']//', tostring(split(Url, '//')[1]))
| project TIType="URL", TIData=Url, SourceSystem, Description=tostring(Data.description), ThreatType=tostring(array_strcat(Data.indicator_types, ', ')), ConfidenceScore=Confidence, IndicatorId=Id),
(entities
| join kind=inner (ThreatIntelIndicators
| where ObservableKey =~ "domain-name:value"
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by Id, ObservableValue
| where IsActive and (ValidUntil > now() or isempty(ValidUntil))
| extend DomainName = tolower(ObservableValue)) on DomainName
| project TIType="Domain", TIData=DomainName, SourceSystem, Description=tostring(Data.description), ThreatType=tostring(array_strcat(Data.indicator_types, ', ')), ConfidenceScore=Confidence, IndicatorId=Id)'''
        results = rest.execute_la_query(base_object, query, 14)
        ti_object.DetailedResults = ti_object.DetailedResults + results
        ti_object.URLEntitiesCount = len(base_object.get_url_list())
        ti_object.URLEntitiesWithTI = len(results)
        ti_object.URLTIFound = bool(results)

    ti_object.AnyTIFound = bool(ti_object.DetailedResults)
    ti_object.TotalTIMatchCount = len(ti_object.DetailedResults)

    if ti_object.DetailedResults:
        try:
            ti_object.DetailedResults = data.replace_column_value_in_list(ti_object.DetailedResults, 'Description', '[', '(')
            ti_object.DetailedResults = data.replace_column_value_in_list(ti_object.DetailedResults, 'Description', ']', ')')
        except:
            pass

    if req_body.get('AddIncidentComments', True) and base_object.IncidentAvailable:
        
        html_table = data.list_to_html_table(ti_object.DetailedResults)

        comment = f'''A total of {ti_object.TotalTIMatchCount} records were found with matching Threat Intelligence data.<br>{html_table}'''
        comment_result = rest.add_incident_comment(base_object, comment)

    if req_body.get('AddIncidentTask', False) and ti_object.AnyTIFound and base_object.IncidentAvailable:
        task_result = rest.add_incident_task(base_object, 'Review Threat Intelligence Matches', req_body.get('IncidentTaskInstructions'))

    return Response(ti_object)