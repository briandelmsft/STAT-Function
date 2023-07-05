from classes import BaseModule, Response, STATError, RunPlaybook
from shared import rest

def execute_playbook_module (req_body):

    #Inputs AddIncidentComments, LogicAppResourceId, PlaybookName, TenantId

    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])

    playbook = RunPlaybook()

    playbook.LogicAppArmId = req_body.get('LogicAppResourceId')
    playbook.TenantId = req_body.get('TenantId')
    playbook.PlaybookName = req_body.get('PlaybookName', base_object.IncidentARMId)
    playbook.IncidentArmId = base_object.IncidentARMId

    if not playbook.TenantId or not playbook.LogicAppArmId:
        raise STATError(f'Missing logic app id {playbook.LogicAppArmId} or tenant id {playbook.TenantId}.')
    
    if not base_object.IncidentAvailable:
        raise STATError(f'There is no incident associated with this STAT triage.  Unable to execute Incident playbook.')

    path = f'{base_object.IncidentARMId}/runPlaybook?api-version=2022-07-01-preview'
    body = {
        'logicAppsResourceId': playbook.LogicAppArmId,
        'tenantId': playbook.TenantId
    }

    try:
        response = rest.rest_call_post(base_object, api='arm', path=path, body=body)
    except STATError as e:
        comment = f'The Sentinel Triage AssistanT failed to start the playbook {playbook.PlaybookName} on this incident.<br>Playbook resource id: {playbook.LogicAppArmId}'
        rest.add_incident_comment(base_object, comment)
        raise STATError(e.error, e.source_error, e.status_code)

    if req_body.get('AddIncidentComments', True):
        
        comment = f'The Playbook {playbook.PlaybookName} was successfully started on this incident by the Microsoft Sentinel Triage AssistanT (STAT)<br>Playbook resource id: {playbook.LogicAppArmId}'
        comment_result = rest.add_incident_comment(base_object, comment)

    return Response(playbook)