from classes import BaseModule, Response, FileModule, STATError
from shared import rest, data
import json

def execute_file_module (req_body):

    #Inputs AddIncidentComments, AddIncidentTask, BaseModuleBody, IncidentTaskInstructions

    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])

    file_object = FileModule()

    hash_entities = list(filter(lambda x: x['Algorithm'].lower() in ('sha1', 'sha256', 'md5'), base_object.FileHashes))
    sha256_hashes = list(filter(lambda x: x['Algorithm'].lower() == 'sha256', base_object.FileHashes))

    file_object.AnalyzedEntities = len(hash_entities)

    hash_string = "('" + "','".join(data.return_property_as_list(sha256_hashes, 'FileHash')) + "')"

    email_hash_query = f'''EmailAttachmentInfo
| where Timestamp > ago(30d)
| where SHA256 in~ {hash_string}
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Count=count() by FileName,SHA256, FileSize'''
    
    if sha256_hashes:
        email_attachments_by_hash = rest.execute_m365d_query(base_object, email_hash_query)

    for hash in hash_entities:
        current_hash = hash['FileHash']
        path = f'/api/files/{current_hash}'
        try:
            file_api_results = json.loads(rest.rest_call_get(base_object, 'mde', path).content)
            test = file_api_results
        except:
            pass



    # if req_body.get('AddIncidentComments', True) and base_object.IncidentAvailable:
        
    #     html_table = data.list_to_html_table(ti_object.DetailedResults)

    #     comment = f'''A total of {ti_object.TotalTIMatchCount} records were found with matching Threat Intelligence data.<br>{html_table}'''
    #     comment_result = rest.add_incident_comment(base_object, comment)

    # if req_body.get('AddIncidentTask', False) and ti_object.AnyTIFound and base_object.IncidentAvailable:
    #     task_result = rest.add_incident_task(base_object, 'Review Threat Intelligence Matches', req_body.get('IncidentTaskInstructions'))

    return Response(file_object)