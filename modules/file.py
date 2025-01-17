from classes import BaseModule, Response, FileModule, STATError, STATNotFound
from shared import rest, data
import json

def execute_file_module (req_body):

    #Inputs AddIncidentComments, AddIncidentTask, BaseModuleBody, IncidentTaskInstructions

    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])

    file_object = FileModule()

    file_names = data.return_property_as_list(base_object.Files, 'FileName')
    sha1_hashes = data.return_property_as_list(list(filter(lambda x: x['Algorithm'].lower() == 'sha1', base_object.FileHashes)), 'FileHash')
    sha256_hashes = data.return_property_as_list(list(filter(lambda x: x['Algorithm'].lower() == 'sha256', base_object.FileHashes)), 'FileHash')

    file_object.AnalyzedEntities = len(sha1_hashes) + len(sha256_hashes) + len(base_object.Files)

    results_data = {}

    if file_names:
        email_file_query = f'''EmailAttachmentInfo
| where Timestamp > ago(30d)
| where FileName in~ ({convert_list_to_string(file_names)})
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), AttachmentCount=count() by FileName,SHA256, FileSize'''
        file_results = rest.execute_m365d_query(base_object, email_file_query)

        for file in file_results:
            if not results_data.get(file['SHA256']):
                results_data[file['SHA256']] = {
                    'SHA256': file['SHA256']
                }
            results_data[file['SHA256']]['EmailAttachmentCount'] = file['AttachmentCount']
            results_data[file['SHA256']]['EmailAttachmentFileSize'] = file['FileSize']
            results_data[file['SHA256']]['EmailAttachmentFirstSeen'] = file['FirstSeen']
            results_data[file['SHA256']]['EmailAttachmentLastSeen'] = file['LastSeen']
            results_data[file['SHA256']]['FileName'] = file['FileName']
            file_object.EntitiesAttachmentCount += file['AttachmentCount']

    device_file_query = f'''let sha1Hashes = datatable(SHA1:string)[{convert_list_to_string(sha1_hashes)}];
let sha256Hashes = datatable(SHA256:string)[{convert_list_to_string(sha256_hashes)}];
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
        if file['SHA256'] not in sha256_hashes:
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
            add_file_api_result(result, results_data, file_object)

            try:
                sha1_hashes.remove(result['sha1'])
            except:
                pass

    for hash in sha1_hashes:
        result = call_file_api(base_object, hash)
        if result:
            add_file_api_result(result, results_data, file_object)
            sha256_hashes.append(result['sha256'])
            
            try:
                sha1_hashes.remove(result['sha1'])
            except:
                pass
       
    if sha256_hashes:
        email_hash_query = f'''datatable(SHA256:string)[{convert_list_to_string(sha256_hashes)}]
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
            file_object.EntitiesAttachmentCount += attachment['AttachmentCount']
            if not results_data[attachment['SHA256']].get('FileName'):
                results_data[attachment['SHA256']]['FileName'] = attachment['FileName']

    for key in results_data:
        file_object.DetailedResults.append(results_data[key])

    file_object.EntitiesAttachmentCount = data.sum_column_by_key(file_object.DetailedResults, 'EmailAttachmentCount')
    file_object.DeviceFileActionTotalCount = data.sum_column_by_key(file_object.DetailedResults, 'DeviceFileActionCount')
    file_object.DeviceUniqueDeviceTotalCount = data.sum_column_by_key(file_object.DetailedResults, 'DeviceUniqueDeviceCount')
    file_object.DeviceUniqueFileNameTotalCount = data.sum_column_by_key(file_object.DetailedResults, 'DeviceUniqueFileNameCount')
    file_object.HashesLinkedToThreatCount = len(file_object.HashesThreatList)
    file_object.MaximumGlobalPrevalence = data.max_column_by_key(file_object.DetailedResults, 'GlobalPrevalence')
    file_object.MinimumGlobalPrevalence = data.min_column_by_key(file_object.DetailedResults, 'GlobalPrevalence')


    if req_body.get('AddIncidentComments', True) and base_object.IncidentAvailable:
        
        html_table = data.list_to_html_table(file_object.DetailedResults)

        comment = f'''<h3>File Module</h3>A total of {file_object.AnalyzedEntities} entities were analyzed with data from the last 30 days.<br>{html_table}'''
        comment_result = rest.add_incident_comment(base_object, comment)

    if req_body.get('AddIncidentTask', False) and file_object.AnalyzedEntities > 0 and base_object.IncidentAvailable:
        task_result = rest.add_incident_task(base_object, 'Review File Module Results', req_body.get('IncidentTaskInstructions'))

    return Response(file_object)

def convert_list_to_string(hash_list:list):
    if hash_list:
        return "'" + "','".join(list(set(hash_list))).lower() + "'"
    else:
        return ''

def call_file_api(base_object, hash):
    path = f'/api/files/{hash}'
    try:
        file_data = json.loads(rest.rest_call_get(base_object, 'mde', path).content)   
    except STATNotFound:
        return None
        
    return file_data

def add_file_api_result(result, results_data, file_object:FileModule):
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

    if results_data[result['sha256']]['Publisher'] != 'Microsoft Corporation':
        file_object.HashesNotMicrosoftSignedCount += 1

    if results_data[result['sha256']]['ThreatName'] != '' and results_data[result['sha256']]['ThreatName'] is not None:
        file_object.HashesThreatList.append(results_data[result['sha256']]['ThreatName'])
        file_object.HashesLinkedToThreatCount += 1