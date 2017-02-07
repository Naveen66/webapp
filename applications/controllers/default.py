# -*- coding: utf-8 -*-
# this file is released under public domain and you can use without limitations

# ########################################################################
## This is a samples controller
## - index is the default action of any application
## - user is required for authentication and authorization
## - download is for downloading files uploaded in the db (does streaming)
## - call exposes all registered services (none by default)
#########################################################################
import json

import uuid



def index():
    """
    example action using the internationalization operator T and flash
    rendered by views/default/index.html or views/generic.html
    """

    redirect('/web/dashboard')
    return (dict())

@auth.requires_login()
def angular():
    return dict()


def url_redirect():
    if not URL.verify(request, hmac_key=HMAC_KEY):
        raise HTTP(403)
    # Update hitcount
    url_conversion_id = request.args[0]
    url_conversion = db.url_conversion(url_conversion_id)
    try:
        # Increment hit count for email marketing
        new_hit_count = (url_conversion.hitCount or 0) + 1
        url_conversion.update_record(hitCount=new_hit_count, lastHitTime=request.now)

        row = db(db.email_campaign_send.id == db.email_campaign_send_url_conversion.emailCampaignSendId)(
            db.email_campaign_send_url_conversion.urlConversionId == url_conversion_id).select(
            cache=(cache.ram, 300)).first()
        email_campaign_send, email_campaign_send_url_conversion = row.email_campaign_send, row.email_campaign_send_url_conversion
        email_campaign = db(db.email_campaign.id == email_campaign_send.emailCampaignId).select().first()
        is_open = email_campaign_send_url_conversion.type == TRACKING_URL_TYPE
        candidate = db(db.candidate.id == email_campaign_send.candidateId).select().first()
        if candidate:  # If candidate has been deleted, don't make the activity
            # Add activity
            from TalentActivityAPI import TalentActivityAPI

            activity_api = TalentActivityAPI()
            activity_type = activity_api.CAMPAIGN_EMAIL_OPEN if is_open else activity_api.CAMPAIGN_EMAIL_CLICK
            activity_api.create(email_campaign.userId, activity_type, source_table='email_campaign_send',
                                source_id=email_campaign_send.id,
                                params=dict(candidateId=email_campaign_send.candidateId,
                                            campaign_name=email_campaign.name, candidate_name=candidate.name()))
        else:
            logger.info("Tried performing URL redirect for nonexistent candidate: %s. email_campaign_send: %s",
                        email_campaign_send.candidateId, email_campaign_send.id)

        # Update email_campaign_blast entry only if it's a new hit
        if new_hit_count == 1:
            email_campaign_blast = db(db.email_campaign_blast.sentTime == email_campaign_send.sentTime).select().first()
            if email_campaign_blast:
                if is_open:
                    email_campaign_blast.update_record(opens=email_campaign_blast.opens + 1)
                else:
                    email_campaign_blast.update_record(htmlClicks=email_campaign_blast.htmlClicks + 1)

                if candidate:
                    flush_campaign_send_statistics_cache(db.user(candidate.ownerUserId).domainId)
                flush_campaign_blast_cache(email_campaign_blast.emailCampaignId)
            else:
                logger.error("URL redirect: No email_campaign_blast found matching email_campaign_send.sentTime %s, campaign_id=%s, so creating" % (
                    email_campaign_send.sentTime, email_campaign.id))
    except Exception:
        logger.exception("Received exception doing url_redirect (url_conversion_id=%s)", url_conversion_id)

    response.title = "getTalent.com: Redirecting to %s" % url_conversion.destinationUrl
    if "www." == url_conversion.destinationUrl[0:4]:
        url_conversion.destinationUrl = "http://" + url_conversion.destinationUrl

    if url_conversion.destinationUrl == '#':
        redirect(HOST_NAME + str(URL(a='web', c='dashboard', f='index')))
    else:
        redirect(url_conversion.destinationUrl)


def error():
    if auth.is_logged_in():
        user_id, username = auth.user.id, auth.user.email
    else:
        user_id, username = '(Not logged-in)', '(Not logged-in)'

    if IS_DEV:
        ticket_url = URL('admin', 'default', 'ticket', args=[request.vars.ticket], scheme=True if request.is_local else 'https', host=True)
    else:
        ticket_url = URL('web', 'admin', 'default', args=['ticket', request.vars.ticket], scheme='https', host=True)

    if not IS_TEST or os.environ.get('CIRCLECI'):  # If environment is test (unless CI), don't do Hipchat/email
        server_type = "CircleCI" if os.environ.get('CIRCLECI') else TalentPropertyManager.get_env().upper()

        # HipChat
        import urllib2
        import hypchat
        try:
            # If on local, private-message the user. Otherwise, send it to Codebox.
            hc = hypchat.HypChat(HIPCHAT_TOKEN)
            if TalentPropertyManager.get_env() == 'dev':
                hipchat_user = hc.get_user(TalentPropertyManager.get_email())
                """
                :type: hypchat.restobject.User
                """
                if not hipchat_user:
                    logger.error("I tried sending you a Hipchat message at %s, but no Hipchat user with that email exists! Make sure that email belongs to a getTalent Hipchat user",
                                 TalentPropertyManager.get_email())
                else:
                    hipchat_message = """You got a localhost error!<br /> <a href="%s">Error link</a> <br /> Username: %s""" % \
                                      (ticket_url, username)
                    hipchat_user.message(message=hipchat_message,
                                         message_format='html',
                                         notify=True)
            else:
                hipchat_codebox_room = hc.get_room("Codebox")
                """
                :type: hypchat.restobject.Room
                """
                hipchat_message = """Error occurred on Talent Web %s <br /> <a href="%s">Error link</a> <br /> Username: %s""" % \
                                  (server_type, ticket_url, username)
                hipchat_codebox_room.notification(message=hipchat_message,
                                                  color='red',
                                                  notify=True,
                                                  format='html')
            # hipster.message_room(room_id='Codebox',
            #                      message_from='Talent Web %s' % server_type,
            #                      message=hipchat_message,
            #                      message_format='html',
            #                      color='red',
            #                      notify=True)
        except urllib2.HTTPError:
            logger.exception("Received exception posting error to HipChat. Error link: %s", ticket_url)

        # Email
        email_message = """
            Error occurred on Talent Web %s

            Link to error ticket: %s \n
            User ID: %s\n
            Username: %s\n
            URL: %s\n
            """ % (server_type, ticket_url, user_id, username, request.vars.request_url)
        from TalentReporting import email_error_to_admins
        email_error_to_admins(email_message, subject="Error ticket")

    response.status = "%s Internal Service Error" % request.vars.code

    if request.vars.request_url and '.json' in request.vars.request_url:
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({'error': {'message': 'Internal server error', 'ticket': request.vars.ticket or ""}})

    # request_url = request.vars.request_url
    # if request_url:
    #     args = request_url.split('/')
    #     if args[0] == '':
    #         args.pop(0)

        # error_data = dict(error=dict(system_error=0), ticket=ticket_url)
        # if '.xml' in args[-1]:
        #     response.headers['Content-Type'] = 'text/xml'
        #     return response.render('generic.xml', error_data)
        # elif '.json' in args[-1]:
        #     response.headers['Content-Type'] = 'application/json'
        #     return response.json(error_data)

    return dict(ticket_url=ticket_url)


@auth.requires_login()
def download_csv():
    """ Inputs: table: JSON table (array of arrays)
    """
    return _json_table_to_csv_download(request.vars.table, response)


@auth.requires_login()
def convert_spreadsheet_to_table():
    """
    Inputs CSV, XLS, XLSX. Returns first 10 rows of spreadsheet.

    If filepicker_key and filename are given as inputs, will download the file from S3.

    :return:
    """
    is_csv = request.vars.csv
    filename = request.vars.csv.filename if is_csv else request.vars.filename
    if is_csv:
        file_obj = request.vars.csv.file
        filename = str(uuid.uuid4()) + '.' + ext_from_filename(filename)
    elif request.vars.filepicker_key and request.vars.filename:
        logger.info("Converting spreadsheet (key=%s, filename=%s) into table", request.vars.filepicker_key, request.vars.filename)
        import TalentS3
        filepicker_bucket, conn = TalentS3.get_s3_filepicker_bucket_and_conn()
        file_obj = TalentS3.download_file(filepicker_bucket, request.vars.filepicker_key)
    else:
        logger.error("File not a CSV and no filepicker_key supplied: %s", request.vars.filename)
        response.status_code = 400
        return {'error': {'message': 'File not a CSV and no filepicker_key supplied'}}

    csv_table = _convert_spreadsheet_to_table(file_obj, filename)
    first_rows = csv_table[:10]
    logger.info("Spreadsheet %s converted into rows. First 10: %s", request.vars.filename, first_rows)

    session.csv_filename = filename

    return dict(table=first_rows)
