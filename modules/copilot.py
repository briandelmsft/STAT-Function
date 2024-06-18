from classes import BaseModule, RelatedAlertsModule, CopilotModule, Response, STATError
from modules import base, relatedalerts
#from shared import rest, data
import json

def execute_copilot_module (req_body):
    
    #Inputs: IncidentARMId, WorkspaceId
    copilot = CopilotModule()
    req_body['objectSchemaType'] = 'copilot'

    base_object:BaseModule = base.execute_base_module(req_body).body

    related_alerts_input = {
        'AddIncidentComments': False,
        'LookbackInDays': 14,
        'BaseModuleBody': base_object.__dict__
            
    }

    related_alerts:RelatedAlertsModule = relatedalerts.execute_relatedalerts_module(related_alerts_input).body

    copilot.BaseModuleTemp = base_object.__dict__
    copilot.RelatedAlertsTemp = related_alerts.__dict__

    return Response(copilot)