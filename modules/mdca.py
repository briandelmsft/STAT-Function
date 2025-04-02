from classes import BaseModule, Response, MDCAModule, STATError, STATNotFound
from shared import rest, data
import json,os,base64

def execute_mdca_module (req_body):

    #Inputs AddIncidentComments, AddIncidentTask, ScoreThreshold, TopUserThreshold

    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])

    mdac_object = MDCAModule()

    if req_body.get('AddIncidentComments', True):
        comment = "The Sentinel Triage AssistanT's (STAT) Microsoft Defender for Cloud Apps module has been deprecated.  This is due to Microsoft's depreation of the MDCA investigation score.<br />"
        comment += "Please remove the MDCA module from your STAT Analysis."
        comment_result = rest.add_incident_comment(base_object, comment)

    return Response(mdac_object)
