# -*- coding: utf-8 -*-

from TalentActivityAPI import TalentActivityAPI
import TalentSmartListAPI
from TalentUsers import is_current_user_admin
from TalentEmailMarketing import _html_to_text, send_test_email
from CustomErrors import CustomErrorResponse

@auth.requires_login()
def index():
    campaigns_and_lists = get_campaigns_and_smart_lists(auth.user.domainId, get_last_sent_datetime=True)
    # Filter out subscription campaigns for non-admins
    current_user_admin = is_current_user_admin(auth.user_id)
    campaigns_and_lists = filter(lambda row: not row['isSubscription'] or current_user_admin, campaigns_and_lists)

    return dict(campaigns_and_lists=campaigns_and_lists)


@auth.requires_login()
# Stop scheduler_tasks of a given email campaign id
def stop():
    email_campaign = db.email_campaign(request.vars.id)
    if auth.user.id != email_campaign.userId: return dict(success=0)
    scheduler_task_ids = email_campaign.schedulerTaskIds
    db(db.scheduler_task.id.belongs(scheduler_task_ids)).update(enabled='F')

    # Add activity
    activity_api = TalentActivityAPI()
    activity_api.create(auth.user.id, activity_api.CAMPAIGN_PAUSE, source_table='email_campaign',
                        source_id=email_campaign.id, params=dict(id=email_campaign.id, name=email_campaign.name))

    return dict(success=1)


@auth.requires_login()
# Stop scheduler_tasks of a given email campaign id
def resume():
    email_campaign = db.email_campaign(request.vars.id)
    if auth.user.id != email_campaign.userId: return dict(success=0)
    scheduler_task_ids = email_campaign.schedulerTaskIds
    db(db.scheduler_task.id.belongs(scheduler_task_ids)).update(enabled='T')

    # Add activity
    activity_api = TalentActivityAPI()
    activity_api.create(auth.user.id, activity_api.CAMPAIGN_RESUME, source_table='email_campaign',
                        source_id=email_campaign.id, params=dict(id=email_campaign.id, name=email_campaign.name))

    return dict(success=1)


def amazon_sns_endpoint():
    request_body = request.body.read() or ''

    logger.error("Email couldn't be sent as an error has occured. Response: %s", request_body)
    from TalentReporting import email_notification_to_admins
    email_notification_to_admins(request_body, subject="Amazon SNS endpoint message")

    body_dict = simplejson.loads(request_body)
    message_dict = simplejson.loads(body_dict['Message'])
    if message_dict.get('notificationType') == "Bounce":
        message_id = message_dict['mail']['messageId']
        email_campaign_send = db(db.email_campaign_send.sesMessageId == message_id).select().first()
        row = email_campaign_send or db(db.widget_candidate.sesMessageId == message_id).select().first()

        # Update blast
        if email_campaign_send:
            email_campaign_blast = db(db.email_campaign_blast.sentTime == email_campaign_send.sentTime).select().first()
            email_campaign_blast.update_record(bounces=email_campaign_blast.bounces + 1)

        if row:
            row.update_record(isSesBounce=1)

    elif message_dict.get('notificationType') == "Complaint":
        message_id = message_dict['mail']['messageId']
        email_campaign_send = db(db.email_campaign_send.sesMessageId == message_id).select().first()
        row = email_campaign_send or db(db.widget_candidate.sesMessageId == message_id).select().first()

        # Update blast
        if email_campaign_send:
            email_campaign_blast = db(db.email_campaign_blast.sentTime == email_campaign_send.sentTime).select().first()
            email_campaign_blast.update_record(complaints=email_campaign_blast.complaints + 1)

        if row:
            row.update_record(isSesComplaint=1)
    else:
        logger.error("Unknown Amazon SNS message: \n%s", request_body)
    return ""


@auth.requires_login()
def html_to_text():
    return dict(text=_html_to_text(request.vars.html))


@auth.requires_login()
def builder():
    from TalentEmailMarketing import schedule_email_campaign_sends
    # if not request.vars.sendTime: request.vars.sendTime = request.now.strftime("%Y-%m-%d %H:%M:%S")
    form = SQLFORM(db.email_campaign)

    if request.post_vars:
        # Set the campaign's user ID
        request.vars['userId'] = auth.user.id

        # Set the campaign's custom parameter JSON, if any
        if request.vars['customSrc']:
            import simplejson

            request.vars['customUrlParamsJson'] = simplejson.dumps(dict(src=request.vars.customSrc))

        # If there is an HTML email but not plaintext, automatically set plaintext
        if not request.vars.emailBodyText and request.vars.emailBodyHtml:
            request.vars['emailBodyText'] = _html_to_text(request.vars.emailBodyHtml)

        # get html text from saved template table,
        # @TODO reply on user_email_template to get email content from, and connect it to email_campaign, no need for duplicate data
        if not request.post_vars.SelectedTemplateId:
            request.post_vars['emailBodyHtml'] = request.vars.emailBodyHtml
            request.post_vars['emailBodyText'] = _html_to_text(request.vars.emailBodyHtml)
        else:
            html_email = db(db.user_email_template.id == request.post_vars.SelectedTemplateId).select(
                db.user_email_template.emailBodyHtml, db.user_email_template.emailBodyText
            )
            request.post_vars['emailBodyHtml'] = html_email[0].emailBodyHtml
            request.post_vars['emailBodyText'] = html_email[0].emailBodyText or _html_to_text(request.vars.emailBodyHtml)

        current.email_campaign_validation_error = ''
        if form.process(session=None, formname=None,
                        onvalidation=lambda (frm): email_campaign_validation(frm, request.vars,
                                                                             auth.user.domainId)).accepted:
            # Add activity
            activity_api = TalentActivityAPI()
            activity_api.create(auth.user.id, activity_api.CAMPAIGN_CREATE, source_table='email_campaign',
                                source_id=form.vars.id, params=dict(id=form.vars.id, name=form.vars.name))

            # Make email_campaign_smart_list records
            campaign = db.email_campaign(form.vars.id)
            TalentSmartListAPI.create_email_campaign_smart_lists(request.vars.smart_list_ids, campaign.id, auth.user_id)

            # Schedule the sending of emails
            schedule_email_campaign_sends(campaign, auth.user)
            session.flash = "Campaign %s successfully started" % form.vars.name
            redirect(URL('campaign', 'index'))
            return
        elif form.errors:
            logger.error("Received error saving email campaign form: %s", form.errors)
            if current.email_campaign_validation_error:
                response.flash = current.email_campaign_validation_error
            else:
                response.flash = "%s: %s" % ("Enter a value for", db.email_campaign[form.errors.keys()[0]].label)

    frequencies = db(db.frequency.id > 0).select()

    smart_lists = TalentSmartListAPI.get_in_domain(auth.user.domainId, order=True, get_candidate_count=False)
    # Filter out smart lists that have 0 recipients
    # smart_lists = filter(lambda row: row.candidateCount > 0, smart_lists)

    send_once_frequency_id = [freq.id for freq in frequencies][0]

    # Templates
    templates = db(
        (db.user_email_template.type == TEMPLATE_EMAIL_MARKETING) &
        (db.user_email_template.userId == db.user.id) &
        (db.user.domainId == auth.user.domainId)
    ).select(db.user_email_template.ALL)

    # templates = templates.find(lambda row: row.isImmutable == 1)
    # mails = templates.find(lambda row: not row.isImmutable)

    # Set up folder_id_to_mails_dicts, which is like: [{1: mails}, {2: mails}, ..]
    folders = db(db.email_template_folder.domainId == auth.user.domainId).select()
    folder_id_to_mails_dicts = [{folder.id: []} for folder in folders]
    folder_id_to_mails_dicts.append({0: []})  # Uncategorized: No folder ID
    for template in templates:
        for folder_id_to_mails in folder_id_to_mails_dicts:  # Get the dict of folder ID to mails
            folder_id = folder_id_to_mails.keys()[0]
            if folder_id == (template.emailTemplateFolderId or 0):  # 0 is Uncategorized
                folder_id_to_mails[template.emailTemplateFolderId or 0].append(template)

    # print 'folder_id_to_mails_dicts keys before swapping', [e.keys() for e in folder_id_to_mails_dicts]

    # Make 'Uncategorized' folder last, and 'Templates' folder first if it exists
    uncategorized_index = -1
    folder_called_templates_index = -1
    folder_called_templates = folders.find(lambda row: row.name == 'Templates').first()
    for i, folder_id_to_mails in enumerate(folder_id_to_mails_dicts):
        folder_id = folder_id_to_mails.keys()[0]
        if folder_id == 0:
            uncategorized_index = i
        elif folder_called_templates and folder_id == folder_called_templates.id:
            folder_called_templates_index = i
    if uncategorized_index != -1:  # Swap 'Uncategorized' and the last
        last = folder_id_to_mails_dicts[-1]
        folder_id_to_mails_dicts[-1] = folder_id_to_mails_dicts[uncategorized_index]
        folder_id_to_mails_dicts[uncategorized_index] = last
    if folder_called_templates_index != -1:  # Swap 'Templates' and the first
        first = folder_id_to_mails_dicts[0]
        folder_id_to_mails_dicts[0] = folder_id_to_mails_dicts[folder_called_templates_index]
        folder_id_to_mails_dicts[folder_called_templates_index] = first

    # print 'folder_id_to_mails_dicts keys after swapping', [e.keys() for e in folder_id_to_mails_dicts]

    # Domain-wide default tracking code & from name
    domain = db.domain(auth.user.domainId)
    tracking_code = domain.defaultTrackingCode
    default_from_name = domain.defaultFromName

    # Show/Hide Generate Report button
    domain_settings_dict = get_domain_settings_dict(db.domain(auth.user.domainId))
    hidden_fields = get_hidden_fields_from_domain_settings_dict('builder', domain_settings_dict)
    layout_mode = get_hidden_fields_from_domain_settings_dict('layoutMode', domain_settings_dict)

    # If domain is Kaiser Corporate, hide Job Alert smartlists for non-admin users
    if is_kaiser_domain(auth.user.domainId) and not is_current_user_admin(user_id=auth.user_id):
        smart_lists = filter(lambda row: 'Job Alerts' not in row.name, smart_lists)

    return dict(
        user=db.user(auth.user_id),
        smart_lists=smart_lists,
        frequencies=frequencies,
        send_once_frequency_id=send_once_frequency_id,
        templates=templates,
        folders=folders,
        folder_id_to_mails_dicts=folder_id_to_mails_dicts,
        DEFAULT_FIRST_NAME_MERGETAG=DEFAULT_FIRST_NAME_MERGETAG,
        DEFAULT_LAST_NAME_MERGETAG=DEFAULT_LAST_NAME_MERGETAG,
        tracking_code=tracking_code,
        default_from_name=default_from_name,
        hidden_fields=hidden_fields,
        is_current_user_admin=is_current_user_admin(),
        layout_mode=layout_mode
    )


# Inputs: name, parentId (if any), isImmutable (only if admin)
# Returns: id
@auth.requires_login()
def create_email_template_folder():
    response.generic_patterns = ['*.json']
    name = request.vars.name
    # Check if the name is already exists under same domain
    existing_name = db((db.email_template_folder.name == name) & (db.email_template_folder.domainId == auth.user.domainId)
                       ).select(db.email_template_folder.name).first()
    if existing_name:
        response.status = 400
        return CustomErrorResponse.DUPLICATE_TEMPLATE_FOLDER
    domain_id = auth.user.domainId
    parent_id = request.vars.parentId
    if parent_id and db.email_template_folder(parent_id).domainId != domain_id:
        logger.error("Error creating email campaign folder: parent ID %s does not belong to domain %s", parent_id,
                     domain_id)
        raise HTTP(500, "500: Parent ID does not belong to the same domain")

    # Set isImmutable
    is_immutable = 0
    if request.vars.isImmutable == "1" and not is_current_user_admin():
        raise HTTP(500, "isImmutable = 1 but user is not admin")
    elif request.vars.isImmutable == "1":
        is_immutable = 1

    email_template_folder_id = db.email_template_folder.insert(name=request.vars.name,
                                                               domainId=domain_id,
                                                               parentId=parent_id,
                                                               isImmutable=is_immutable)

    return dict(id=email_template_folder_id)


@auth.requires_login()
def create_user_email_template():
    response.generic_patterns = ['*.json']
    name = request.vars.name

    # Check if the name is already exists in the domain
    existing_name = db((db.user_email_template.name == name) & (db.user_email_template.userId == db.user.id) &
                       (db.user.domainId == auth.user.domainId)).select(db.user_email_template.name)
    if existing_name:
        response.status = 400
        return CustomErrorResponse.DUPLICATE_TEMPLATE
    email_template_folder_id = int(request.vars.emailTemplateFolderId or 0)
    email_template_folder = db.email_template_folder(email_template_folder_id) if email_template_folder_id else None
    if email_template_folder and email_template_folder.domainId != auth.user.domainId:
        raise HTTP(500, "Email template's folder (%s) is in the user's domain (%s)", email_template_folder.id,
                   auth.user.domainId)

    # Set isImmutable
    is_immutable = 0
    if request.vars.isImmutable == "1" and not is_current_user_admin():
        raise HTTP(403, "isImmutable = 1 but user is not admin")
    elif request.vars.isImmutable == "1":
        is_immutable = 1

    user_email_template_id = db.user_email_template.insert(
        userId=auth.user.id,
        type=TEMPLATE_EMAIL_MARKETING,
        name=request.vars.name,
        emailBodyHtml=request.vars.emailBodyHtml or None,
        emailBodyText=request.vars.emailBodyText or None,
        emailTemplateFolderId=email_template_folder.id if email_template_folder else None,
        isImmutable=is_immutable
    )
    return dict(id=user_email_template_id)


# Inputs: id, emailBodyHtml
@auth.requires_login()
def save_user_email_template():
    response.generic_patterns = ['*.json']

    user_email_template = db.user_email_template(request.vars.id)

    # Verify owned by same domain
    owner_user = db.user(user_email_template.userId)
    if owner_user.domainId != auth.user.domainId:
        raise HTTP(500, "Template is not owned by same domain")

    # Verify isImmutable
    if user_email_template.isImmutable and not is_current_user_admin():
        raise HTTP(500, "Non-admin user trying to save immutable template")

    user_email_template.update_record(emailBodyHtml=request.vars.emailBodyHtml or user_email_template.emailBodyHtml,
                                      emailBodyText=request.vars.emailBodyText or user_email_template.emailBodyText)

    return dict(success=1)


# Input: id, Outputs success=1 or 0
@auth.requires_login()
def delete_user_email_template():

    template = db(db.user_email_template.id == request.vars.id).select(db.user_email_template.isImmutable)

    if template[0].isImmutable == 1 and not is_current_user_admin():
        raise HTTP(500, "Non-admin user trying to delete immutable template")
    else:
        result = db(
            (db.user_email_template.id == request.vars.id) &
            (db.user_email_template.userId.belongs(db(db.user.domainId == auth.user.domainId)._select(db.user.id)))
        ).delete()

        return dict(success=result)


@auth.requires_login()
# Path for each file: EmailMarketingFiles/[user_id]/<filename>
# Input: 'upload' is FieldStorage object
def builder_upload_image():
    from TalentS3 import upload_to_s3

    path, key = upload_to_s3(
        file_content=request.vars.upload.file.read(),
        folder_path='EmailMarketingFiles/%s' % auth.user_id,
        name=request.vars.upload.filename
    )

    return """<script type='text/javascript'>window.parent.CKEDITOR.tools.callFunction(%s, '%s', '%s');</script>""" % (
        request.vars.CKEditorFuncNum,
        path,
        ""
    )


# Verify owner of lists is user_id
# Also with the company name
def email_campaign_validation(form, vars, domain_id):
    if not vars.sendTime:
        form.errors.name = current.email_campaign_validation_error = "Campaings must have start time."
    elif not vars.smart_list_ids:
        form.errors.name = "Campaigns must have at least 1 smart list"
        current.email_campaign_validation_error = "Campaigns must have at least 1 smart list"
    else:
        if isinstance(vars.smart_list_ids, str): vars.smart_list_ids = [vars.smart_list_ids]
        num_valid_lists = TalentSmartListAPI.count_valid_lists(vars.smart_list_ids, domain_id)
        if num_valid_lists != len(vars.smart_list_ids):
            form.errors.name = "Invalid smart list IDs"
            current.email_campaign_validation_error = "Invalid smart list IDs"


@auth.requires_login()
def send_test_email_action():
    response.generic_patterns = ['*.json']
    if request.vars.templateId:
        template_data = db(db.user_email_template.id == request.vars.templateId).select().first()
        if not template_data:
            raise HTTP(500, 'Unknown template')
            return
        request.vars.emailBodyHtml = template_data['emailBodyHtml']
        request.vars.emailBodyText = template_data['emailBodyText']
        send_test_email(auth.user, request.vars)
        response.flash = "Test email sent to %s" % auth.user.email
        return dict()

    else:
        raise HTTP(500, 'Select Template')


@auth.requires_login()
# We don't delete campaigns, only set isHidden = 1
def delete():
    campaign_ids = request.vars.ids
    if not verify_campaigns_owner(campaign_ids, auth.user.domainId):
        return dict()
    db(db.email_campaign.id.belongs(campaign_ids)).update(isHidden=1)

    # Add activity
    activity_api = TalentActivityAPI()
    email_campaigns = db(db.email_campaign.id.belongs(campaign_ids)).select(db.email_campaign.id,
                                                                            db.email_campaign.name)
    for campaign_id in campaign_ids:
        campaign_name = email_campaigns.find(lambda row: row.id == campaign_id).first().name
        activity_api.create(auth.user.id, activity_api.CAMPAIGN_DELETE, source_table='email_campaign',
                            source_id=campaign_id, params=dict(id=campaign_id, name=campaign_name))

    return dict()
