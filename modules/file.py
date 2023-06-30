from classes import BaseModule, Response, FileModule, STATError
from shared import rest, data
import json

def execute_file_module (req_body):

    #Inputs AddIncidentComments, AddIncidentTask, BaseModuleBody, IncidentTaskInstructions

    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])

    file_object = FileModule()


#data.return_property_as_list(hash_list, 'FileHash')

    sha1_hashes = data.return_property_as_list(list(filter(lambda x: x['Algorithm'].lower() == 'sha1', base_object.FileHashes)), 'FileHash')
    sha256_hashes = data.return_property_as_list(list(filter(lambda x: x['Algorithm'].lower() == 'sha256', base_object.FileHashes)), 'FileHash')
    #sha1_hashes = list(filter(lambda x: x['Algorithm'].lower() == 'sha1', base_object.FileHashes))
    #sha256_hashes = list(filter(lambda x: x['Algorithm'].lower() == 'sha256', base_object.FileHashes))

    #file_object.AnalyzedEntities = len(hash_entities)

#     hash_string = "('" + "','".join(data.return_property_as_list(sha256_hashes, 'FileHash')) + "')"

#     email_hash_query = f'''EmailAttachmentInfo
# | where Timestamp > ago(30d)
# | where SHA256 in~ {hash_string}
# | summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Count=count() by FileName,SHA256, FileSize'''
    
    #sha256_hash_string = "','".join(data.return_property_as_list(sha256_hashes, 'FileHash')).lower()
    #sha1_hash_string = "','".join(data.return_property_as_list(sha1_hashes, 'FileHash')).lower()

    #result_index = {}
    results_data = {}
    #matching_sha1_sha256 = {}

    device_file_query = f'''let sha1Hashes = datatable(SHA1:string)['{get_hashes_as_string(sha1_hashes)}'];
let sha256Hashes = datatable(SHA256:string)['{get_hashes_as_string(sha256_hashes)}'];
union
(DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA1 in~ (sha1Hashes) or SHA256 in~ (sha256Hashes)
| project FileName, SHA1, SHA256, DeviceId),
(DeviceProcessEvents
| where Timestamp > ago(30d)
| where SHA1 in~ (sha1Hashes) or SHA256 in~ (sha256Hashes)
| project FileName, SHA1, SHA256, DeviceId)
| summarize DeviceUniqueDeviceCount=dcount(DeviceId), Files=make_set(FileName), FileName=min(FileName), Count=count() by SHA1, SHA256
| extend DeviceUniqueFileNameCount = array_length(Files)'''
    
    device_file_results = rest.execute_m365d_query(base_object, device_file_query)

    for file in device_file_results:
        sha256_hashes.append(file['SHA256'])
        try:
            sha1_hashes.remove(file['SHA1'])
        except:
            pass
        results_data[file['SHA256']] = {
            'DeviceUniqueDeviceCount': file['DeviceUniqueDeviceCount'],
            'DeviceUniqueFileNameCount': file['DeviceUniqueFileNameCount'],
            'DeviceFileActionCount': file['Count'],
            'FileName': file['FileName'],
            'SHA1': file['SHA1'],
            'SHA256': file['SHA256']
        }

    for hash in sha256_hashes:
        result = call_file_api(base_object, hash)
        if result:
            add_file_api_result(result, results_data)
        #     if not results_data.get(result['sha256']):
        #         results_data[result['sha256']] = {
        #             'SHA1': result['sha1'],
        #             'SHA256': result['sha256']
        #         }
        #     results_data[result['sha256']]['GlobalFirstSeen'] = result['globalFirstObserved']
        #     results_data[result['sha256']]['GlobalLastSeen'] = result['globalLastObserved']
        #     results_data[result['sha256']]['GlobalPrevalence'] = result['globalPrevalence']
        #     results_data[result['sha256']]['Publisher'] = result['filePublisher']
        #     results_data[result['sha256']]['Signer'] = result['signer']
        #     results_data[result['sha256']]['IsCertificateValid'] = result['isValidCertificate']
        #     results_data[result['sha256']]['FileSize'] = result['size']
        #     results_data[result['sha256']]['ThreatName'] = result['determinationValue']

            try:
                sha1_hashes.remove(result['sha1'])
            except:
                pass

    for hash in sha1_hashes:
        result = call_file_api(base_object, hash)
        if result:
            add_file_api_result(result, results_data)
            sha256_hashes.append(result['sha256'])
            
            try:
                sha1_hashes.remove(result['sha1'])
            except:
                pass
       

    email_hash_query = f'''datatable(SHA256:string)['{get_hashes_as_string(sha256_hashes)}']
| join (EmailAttachmentInfo | where Timestamp > ago(30d)) on SHA256
| summarize AttachmentCount=countif(isnotempty(NetworkMessageId)), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), FileName=min(FileName), FileSize=max(FileSize) by SHA256'''
    
    email_attachments_by_hash = rest.execute_m365d_query(base_object, email_hash_query)

    for attachment in email_attachments_by_hash:
        if not results_data.get(attachment['SHA256']):
            results_data[attachment['SHA256']] = {
                'SHA256': attachment['SHA256']
            }
        results_data[attachment['SHA256']]['EmailAttachmentCount'] = attachment['AttachmentCount']
        results_data[attachment['SHA256']]['EmailAttachmentFileSize'] = attachment['FileSize']
        results_data[attachment['SHA256']]['EmailAttachmentFirstSeen'] = attachment['FirstSeen']
        results_data[attachment['SHA256']]['EmailAttachmentLastSeen'] = attachment['LastSeen']
        if not results_data[attachment['SHA256']].get('FileName'):
            results_data[attachment['SHA256']]['FileName'] = attachment['FileName']


    for key in results_data:
        file_object.DetailedResults.append(results_data[key])


    # if req_body.get('AddIncidentComments', True) and base_object.IncidentAvailable:
        
    #     html_table = data.list_to_html_table(ti_object.DetailedResults)

    #     comment = f'''A total of {ti_object.TotalTIMatchCount} records were found with matching Threat Intelligence data.<br>{html_table}'''
    #     comment_result = rest.add_incident_comment(base_object, comment)

    # if req_body.get('AddIncidentTask', False) and ti_object.AnyTIFound and base_object.IncidentAvailable:
    #     task_result = rest.add_incident_task(base_object, 'Review Threat Intelligence Matches', req_body.get('IncidentTaskInstructions'))

    return Response(file_object)

def get_hashes_as_string(hash_list:list, ):
    return "','".join(list(set(hash_list))).lower()

def call_file_api(base_object, hash):
    path = f'/api/files/{hash}'
    try:
        file_data = json.loads(rest.rest_call_get(base_object, 'mde', path).content)
         
    except STATError as e:
        if e.source_error['status_code'] == 404:
            return None
        else:
            raise STATError(e.error, e.source_error, e.status_code)
        
    return file_data

def add_file_api_result(result, results_data):
    if not results_data.get(result['sha256']):
        results_data[result['sha256']] = {
            'SHA1': result['sha1'],
            'SHA256': result['sha256']
        }
    results_data[result['sha256']]['GlobalFirstSeen'] = result['globalFirstObserved']
    results_data[result['sha256']]['GlobalLastSeen'] = result['globalLastObserved']
    results_data[result['sha256']]['GlobalPrevalence'] = result['globalPrevalence']
    results_data[result['sha256']]['Publisher'] = result['filePublisher']
    results_data[result['sha256']]['Signer'] = result['signer']
    results_data[result['sha256']]['IsCertificateValid'] = result['isValidCertificate']
    results_data[result['sha256']]['FileSize'] = result['size']
    results_data[result['sha256']]['ThreatName'] = result['determinationValue']