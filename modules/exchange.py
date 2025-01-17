from classes import BaseModule, Response, ExchangeModule, STATError, STATNotFound
from shared import rest, data
import json
import re
from datetime import datetime, timezone

def execute_exchange_module (req_body):

    #Inputs AddIncidentComments, AddIncidentTask, Entities, IncidentTaskInstructions, KQLQuery, LookbackInDays, QueryDescription, RunQueryAgainst

    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])

    exch = ExchangeModule()

    module_lookback = req_body.get('LookbackInDays', 30)
    check_audits = req_body.get('CheckAuditLog', True)
    check_oof = req_body.get('CheckOutOfOffice', True)
    check_rules = req_body.get('CheckRules', True)

    for account in base_object.Accounts:
        upn = account.get('userPrincipalName')
        if upn:      
            if check_rules:
                rule_check(base_object, exch, account)
            if check_oof:
                oof_check(base_object, exch, upn)
    
    if check_audits:
        audit_check(base_object, exch, module_lookback)

    if exch.UsersOutOfOffice == 0 and exch.UsersUnknown == 0:
        exch.AllUsersInOffice = True
        exch.AllUsersOutOfOffice = False
    elif exch.UsersOutOfOffice > 0 and exch.UsersInOffice == 0 and exch.UsersUnknown == 0:
        exch.AllUsersInOffice = False
        exch.AllUsersOutOfOffice = True 
    else:
        exch.AllUsersInOffice = False
        exch.AllUsersOutOfOffice = False

    if req_body.get('AddIncidentComments', True) and base_object.IncidentAvailable:
        
        if exch.OOF:
            oof_table = data.list_to_html_table(exch.OOF)
            o_comment = '<h3>Exchange Online Module - Out of Office</h3>'
            o_comment += oof_table
            o_comment_result = rest.add_incident_comment(base_object, o_comment)

        if exch.Rules:

            rules_table = data.list_to_html_table(exch.Rules, max_rows=50, drop_empty_cols=True)

            comment = '<h3>Exchange Online Module - Mailbox Rules</h3>'
            comment += f'A total of {len(exch.Rules)} mailbox rules have been found.<br />'
            comment += f'<ul><li>Rules with forwarding settings: {exch.RulesForward}</li>'
            comment += f'<li>Rules that delete message: {exch.RulesDelete} </li>'
            comment += f'<li>Rules that move messages: {exch.RulesMove} </li>'
            comment += f'<li>Privileged Users with Mailbox: {exch.PrivilegedUsersWithMailbox} </li></ul><br />'
            comment += rules_table
            comment_result = rest.add_incident_comment(base_object, comment)

        if exch.AuditEvents:
            audit_table = data.list_to_html_table(exch.AuditEvents, max_rows=50, max_cols=15, drop_empty_cols=True)

            a_comment = f'<h3>Exchange Online Module - Audit Events (Last {module_lookback} days)</h3>'
            a_comment += f'A total of {len(exch.AuditEvents)} forwarding, delegation and rule audits have been found.<br />'
            a_comment += audit_table
            a_comment_result = rest.add_incident_comment(base_object, a_comment)

    if req_body.get('AddIncidentTask', False) and base_object.IncidentAvailable and (exch.Rules or exch.AuditEvents):
        task_result = rest.add_incident_task(base_object, req_body.get('QueryDescription', 'Review Exchange Module Output'), req_body.get('IncidentTaskInstructions'))

    return Response(exch)

def process_action(action_list:list):
    out = []
    for action in action_list:
        out.append(action.get('emailAddress', {}).get('address'))
    return ','.join(out)

def append_disabled(exch:ExchangeModule, upn):
    exch.OOF.append({'ExternalMessage': '', 'InternalMessage': '', 'OOFStatus': 'disabled', 'UPN': upn})

def append_unknown(exch:ExchangeModule, upn):
    exch.OOF.append({'ExternalMessage': '', 'InternalMessage': '', 'OOFStatus': 'unknown', 'UPN': upn})

def append_enabled(exch:ExchangeModule, upn, internal, external):
    clean_html = re.compile('<.*?>')
    replace_nbsp = re.compile('&nbsp;|\\n')
    int_msg = re.sub(replace_nbsp, ' ', re.sub(clean_html, '', internal))
    ext_msg = re.sub(replace_nbsp, ' ', re.sub(clean_html, '', external))
    exch.OOF.append({'ExternalMessage': ext_msg, 'InternalMessage': int_msg, 'OOFStatus': 'enabled', 'UPN': upn})

def audit_check(base_object:BaseModule, exch:ExchangeModule, module_lookback:int):
    #Retrieve OfficeActivity Audits
    query = data.load_text_from_file('exchange-audit.kql', account_table=base_object.get_account_kql_table())

    try:
        exch.AuditEvents = rest.execute_la_query(base_object, query, module_lookback)
    except STATError as e:
        raise STATError('Unable to obtain Exchange Audit data from OfficeActivity table', e.source_error, e.status_code)
    else:
        exch.DelegationsFound = len(list(filter(lambda x: x.get('Operation') in ('AddFolderPermissions', 'Add-MailboxPermission'), exch.AuditEvents)))

def oof_check(base_object:BaseModule, exch:ExchangeModule, upn):
    #Retrieve OOF Settings
    path = f'/v1.0/users/{upn}/mailboxSettings/automaticRepliesSetting'
    try:
        results = json.loads(rest.rest_call_get(base_object, api='msgraph', path=path).content)
    except STATError as e:
        if e.source_error['status_code'] == 403:
            raise STATError(e.error, e.source_error, e.status_code)
    else:
        current_time = datetime.now(timezone.utc)
        if results['status'].lower() == 'disabled':
            exch.UsersInOffice += 1
            append_disabled(exch, upn)
        elif results['status'].lower() == 'enabled' or results['status'].lower() == 'alwaysenabled':
            exch.UsersOutOfOffice += 1
            append_enabled(exch, upn, results['internalReplyMessage'], results['externalReplyMessage'])
        elif results['status'].lower() == 'scheduled' and current_time >= results['scheduledStartDateTime']['dateTime'] \
                and current_time <= results['scheduledEndDateTime']['dateTime']:
            exch.UsersOutOfOffice += 1
            append_enabled(exch, upn, results['internalReplyMessage'], results['externalReplyMessage'])
        else:
            exch.UsersInOffice += 1
            append_disabled(exch, upn)

def rule_check(base_object:BaseModule, exch:ExchangeModule, account):
    #Retrieve Mailbox rules
    upn = account.get('userPrincipalName')
    account_roles = account.get('AssignedRoles', [])
    mail_role = rest.check_app_role(base_object, 'msgraph', ['Mail.ReadBasic.All','Mail.ReadWrite','Mail.Read'])
    path = f'/v1.0/users/{upn}/mailFolders/inbox/messageRules'
    try:
        results = json.loads(rest.rest_call_get(base_object, api='msgraph', path=path).content)
    except STATNotFound:
        exch.UsersUnknown += 1
        return   

    privileged_roles = data.load_json_from_file('privileged-roles.json')
    if set(account_roles).intersection(privileged_roles):
        exch.PrivilegedUsersWithMailbox += 1

    for rule in results.get('value'):
        rule_out = {
            'upn': upn,
            'displayName': rule.get('displayName')
        }

        rule_out['conditions'] = ', '.join([f"{k}: {v}" for k, v in rule.get('conditions',{}).items()])

        if not(rule.get('isEnabled')):
            #Skip to the next rule if the rule is disabled
            continue

        delete_message = rule.get('actions',{}).get('delete')
        permanent_delete = rule.get('actions',{}).get('permanentDelete')
        forward_to = rule.get('actions',{}).get('forwardTo')
        forward_as_attachment = rule.get('actions',{}).get('forwardAsAttachmentTo')
        redirect_to = rule.get('actions',{}).get('redirectTo')
        move_to = rule.get('actions',{}).get('moveToFolder')

        if not(any([delete_message, permanent_delete, forward_to, forward_as_attachment, redirect_to, move_to])):
            #Skip to next rule if the mailbox rule isn't one of these types
            continue

        if delete_message:
            rule_out['deleteMessage'] = delete_message
            exch.RulesDelete += 1
        if permanent_delete:
            rule_out['permanentDeleteMessage'] = permanent_delete
            exch.RulesDelete += 1
        if forward_to:
            rule_out['forwardTo'] = process_action(forward_to)
            exch.RulesForward += 1
        if forward_as_attachment:
            rule_out['forwardAsAttachment'] = process_action(forward_as_attachment)
            exch.RulesForward += 1
        if redirect_to:
            rule_out['redirectTo'] = process_action(redirect_to)
            exch.RulesForward += 1
        if move_to:
            exch.RulesMove += 1
            if mail_role:
                try:
                    folder_path = f'/v1.0/users/{upn}/mailFolders/{move_to}'
                    folder_info = json.loads(rest.rest_call_get(base_object, api='msgraph', path=folder_path).content)
                except:
                    rule_out['moveToFolder'] = 'Unknown Destination'
                else:
                    rule_out['moveToFolder'] = folder_info.get('displayName', 'Unknown Folder')
            else:
                rule_out['moveToFolder'] = 'Unknown - Permissions Needed'

        exch.Rules.append(rule_out)
