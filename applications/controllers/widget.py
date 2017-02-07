# -*- coding: utf-8 -*-
import simplejson
import re

from gluon.utils import web2py_uuid
from TalentAreasOfInterest import get_or_create_areas_of_interest, get_area_of_interest_id_to_sub_areas_of_interest

@auth.requires_login()
def widget_upload_image():
    from TalentS3 import upload_to_s3

    path, key = upload_to_s3(
        file_content=request.vars.upload.file.read(),
        folder_path='WidgetFiles/%s' % auth.user_id,
        name=request.vars.upload.filename
    )

    return """<script type='text/javascript'>window.parent.CKEDITOR.tools.callFunction(%s, '%s', '%s');</script>""" % (
        request.vars.CKEditorFuncNum,
        path,
        ""
    )


def get_view_params():
    isWide = request.vars.wide or False  # not wide by default
    isExpanded = False if request.vars.expanded == "0" else True  # expanded by default
    isMobile = request.user_agent().get('is_mobile') or request.vars.mobile
    isBackgroundTransparent = request.vars.transparent == "1"

    # Get widget_page from the user id or the widget name
    user, widget_page = get_user_and_widget_page_from_request(request)
    if not user or not widget_page:
        # If we couldn't find a user or widget_page, something went seriously wrong. Throw top-level exception.
        raise Exception("widget/get_view_params(): Could not find user or widget_page. Request args=%s, vars=%s" % (request.args, request.vars))
    assert user is not None
    assert widget_page is not None

    is_viacom_widget = widget_page.widgetName == "viacom" if widget_page else False

    if not widget_page:
        widget_view_path = 'widget/generic.html'
    elif widget_page.widgetName == "viacom":
        widget_view_path = 'widget/viacom.html'
    elif widget_page.widgetName == "kaiser" and request.vars.is_special:
        widget_view_path = 'widget/kaiser.html'
    elif widget_page.widgetName == "kaiser" and request.vars.is_special_2:
        widget_view_path = 'widget/kaiser_2.html'
    elif widget_page.widgetName == "kaiser-corporate":
        widget_view_path = 'widget/kaiser_3.html'
    elif widget_page.widgetName == "kaiser-military":
        widget_view_path = 'widget/kaiser_military.html'
    elif widget_page.widgetName == "walmart" and request.vars.is_special:
        widget_view_path = 'widget/walmart.html'
    else:
        widget_view_path = 'widget/generic.html'

    # Set width
    if request.vars.width:
        width = request.vars.width
    elif is_viacom_widget:  # viacom widget has special width
        width = '450' if isWide else '320'
    elif isMobile:
        width = "450" if isWide else "250"
    else:
        width = "320" if isWide else "250"

    # Set margin
    margin = request.vars.margin or 'auto'

    return isWide, isExpanded, isMobile, isBackgroundTransparent, user, widget_page, width, margin, is_viacom_widget, widget_view_path


def submit():
    response.optimize_css = 'concat,minify,inline'
    response.optimize_js = 'concat,minify,inline'

    if not request.args:
        current.logger.warning("Missing request args to widget. Request vars: %s", request.vars)
        mode = 'error'
        return response.render('widget/generic.html', locals())

    isWide, isExpanded, isMobile, isBackgroundTransparent, user, widget_page, width, margin, is_viacom_widget, widget_view_path = get_view_params()

    if not widget_page or not request.post_vars:
        current.logger.warning("widget/submit: No widget_page or POST vars found. Request vars: %s", request.vars)
        mode = 'error'
        return response.render(widget_view_path, locals())

    # Validate required fields
    if (not request.post_vars.name) and (not request.post_vars.firstName or not request.post_vars.lastName):
        current.logger.info("widget/submit: Missing name in POST vars. Request vars: %s", request.vars)
        mode = 'error'
        return response.render(widget_view_path, locals())

    # Validate email
    if request.post_vars.emailAdd:
        request.post_vars.emailAdd = request.post_vars.emailAdd.lower().strip()
    if not is_valid_email(request.post_vars.emailAdd):
        current.logger.info("widget/submit: Invalid email address. Address: %s", request.post_vars.emailAdd)
        mode = 'error'
        return response.render(widget_view_path, locals())

    attached_file = request.vars.file

    # for some reason request.vars.file keeps returning false, so have to do this
    is_attached_file = attached_file.__class__.__name__ == 'FieldStorage'

    widget_candidate_form_fields = dict()
    for input_field in WIDGET_INPUT_FIELDS:
        widget_candidate_form_fields[input_field] = request.vars.get(input_field)

    # If k param supplied, update candidate via attached file and return
    if request.vars.k:

        widget_candidate = db(db.widget_candidate.uuid == request.vars.k).select().first()
        if not widget_candidate:
            current.logger.error("widget/submit: Missing widget_candidate. Request vars: %s", request.vars)
            from TalentReporting import email_error_to_admins
            email_error_to_admins(body="widget/submit: Missing widget_candidate. Request vars: %s" % request.vars,
                                  subject="widget/submit: Missing widget candidate")
            mode = 'error'
            return response.render(widget_view_path, locals())
        widget_candidate_status = widget_candidate.status

        candidate_id = create_or_update_candidate_from_widget_form_fields(
            user,
            widget_candidate_form_fields,
            widget_page,
            attached_file=attached_file.file if is_attached_file else None,
            attached_file_ext=ext_from_filename(attached_file.filename) if is_attached_file else None,
            candidate_id=widget_candidate.candidateId
        )

        # Update widget_candidate's form fields to the ones submitted
        if is_attached_file:
            widget_candidate_status = WIDGET_STATUS_CODES['WIDGET_RESUME_RECEIVED']
        widget_candidate.update_record(
            status=widget_candidate_status,
            formFields=simplejson.dumps(widget_candidate_form_fields)
        )
    else:

        # Create/update the candidate via attached resume (if any) and form fields
        candidate_id = create_or_update_candidate_from_widget_form_fields(
            user,
            widget_candidate_form_fields,
            widget_page,
            attached_file=attached_file.file if is_attached_file else None,
            attached_file_ext=ext_from_filename(attached_file.filename) if is_attached_file else None,
            candidate_id=None
        )
        if not candidate_id:
            mode = 'error'
            return response.render(widget_view_path, locals())
        # Update widget_page sign-ups
        widget_page.update_record(signUps=(widget_page.signUps or 0) + 1)

        # Send email to request resume or welcome the user and Make new widget_candidate
        widget_candidate_status = WIDGET_STATUS_CODES['WIDGET_RESUME_IMPORTED'] if is_attached_file else WIDGET_STATUS_CODES['WIDGET_NO_RESUME_IMPORTED']
        widget_candidate_uuid = web2py_uuid()

        # TODO HACK - remove when implementing domain-based widgets
        if request.vars.is_special or request.vars.is_special_2 or request.vars.is_special_3 or is_attached_file:
            email_info = send_welcome_email(
                request.vars.emailAdd,
                request.vars.firstName,
                request.vars.lastName,
                widget_page,
                widget_candidate_uuid,
                candidate_id
            )
        else:
            email_info = send_resume_request_email(
                request.vars.emailAdd,
                request.vars.firstName,
                request.vars.lastName,
                widget_page,
                widget_candidate_uuid,
                candidate_id
            )

        widget_candidate_id = db.widget_candidate.insert(
            candidateId=candidate_id,
            status=widget_candidate_status,
            formFields=simplejson.dumps(widget_candidate_form_fields),
            uuid=widget_candidate_uuid,
            sesMessageId=email_info['message_id'],
            sesRequestId=email_info['request_id'],
            isSesBounce=0 if email_info['message_id'] else 1,
            clientIp=request.client
        )

        # Complete the widget Get Started action for every user in domain, if not completed already
        action_id = GET_STARTED_ACTIONS['INSTALL_WIDGET_OR_BUTTON']
        if not is_get_started_action_complete(user=user, action_id=action_id):
            domain_users = db(db.user.domainId == user.domainId).select()
            for user in domain_users:
                set_get_started_action(user=user, action_id=action_id)

        # for uploading multiple other documents
    if candidate_id and request.vars.documents:
        documents = request.vars.documents
        for document in documents:
            doc_upload(candidate_id, document)
    mode = 'success'

    return response.render(widget_view_path, locals())


# Inputs: 'k'
def edit():
    response.optimize_css = 'concat,minify,inline'
    response.optimize_js = 'concat,minify,inline'

    isWide, isExpanded, isMobile, isBackgroundTransparent, user, widget_page, width, margin, is_viacom_widget, widget_view_path = get_view_params()

    if not widget_page:
        mode = 'error'
        return response.render(widget_view_path, locals())

    # Set <select> options
    areas_of_interest = get_or_create_areas_of_interest(user.domainId)
    area_of_interest_id_to_sub_areas_of_interest = get_area_of_interest_id_to_sub_areas_of_interest(user.domainId)
    global ALL_CITIES_TAG_NAME  # need this for kaiser corp widget

    # Display form for candidate whose uuid is k
    widget_candidate = db(db.widget_candidate.uuid == request.vars.k).select().first()

    if not widget_candidate:
        mode = 'error'
        return response.render(widget_view_path, locals())

    # Get candidate's info to show in form
    form_fields = simplejson.loads(widget_candidate.formFields) if widget_candidate.formFields else dict()
    mode = 'form'

    return response.render(widget_view_path, locals())


@cache.action(time_expire=3600 * 24, cache_model=cache.ram, prefix="widget-")  # Cache for 1 day
def show():
    """
    To show widget, args[0] is widget_page.widgetName or user.id.
    If user.id is supplied, and if user's domain has no widget, then we will auto-create the widget, and user will be the owner of the widget.

    """
    response.optimize_css = 'concat,minify,inline'
    response.optimize_js = 'concat,minify,inline'

    isWide, isExpanded, isMobile, isBackgroundTransparent, user, widget_page, width, margin, is_viacom_widget, widget_view_path = get_view_params()

    if not widget_page:
        mode = 'error'
        return response.render(widget_view_path, locals())

    # Set <select> options
    areas_of_interest = get_or_create_areas_of_interest(user.domainId)
    majors = db(db.majors.domainId == user.domainId).select(db.majors.name)

    def sort_aoi(row):
        if row.description == 'All' or row.description == 'All Subcategories':
            return 'A'
        else:
            return row.description

    areas_of_interest = areas_of_interest.sort(sort_aoi)
    area_of_interest_id_to_sub_areas_of_interest = get_area_of_interest_id_to_sub_areas_of_interest(user.domainId)
    # area_of_interest_id_to_sub_areas_of_interest.sort(sort_aoi)
    global ALL_CITIES_TAG_NAME  # need this for kaiser corp widget

    # Increment page views and display the form
    # NOTE: WE DONT DO THIS ANYMORE. USE GOOGLE ANALYTICS TO GET PAGE VIEWS INSTEAD
    # if not auth.is_logged_in():  # Only increment page views for non-logged in users
    #     widget_page.update_record(pageViews=(widget_page.pageViews or 0) + 1)
    #     # Add activity
    #     from TalentActivityAPI import TalentActivityAPI
    #     activity_api = TalentActivityAPI(db, cache)
    #     activity_api.create(user.id, activity_api.WIDGET_VISIT, source_table='widget_page', source_id=widget_page.id, params=dict(client_ip=request.client))
    # TODO : delete pageViews column

    mode = 'form'
    form_fields = dict()

    import time

    t = time.ctime()
    return response.render(widget_view_path, locals())


def autocomplete_university():
    universities = db().select(db.university.name, cache=(cache.ram, 300))
    autocomplete = []
    term = request.vars.term.lower()

    for university in universities:
        if term in university.name.lower():
            autocomplete.append(university.name)
            if len(autocomplete) > 10:
                break
    return dict(autocomplete=autocomplete)


def get_universities_list():
    universities = [row.name for row in db().select(db.university.name, cache=(cache.ram, 300))]
    return dict(universities_list=universities)


def verify_university():
    if db(db.university.name == request.vars.university).select().first():
        return dict(valid=1)
    else:
        return dict()


def doc_upload(candidate_id, documents):
    file_name = documents.filename
    file_obj = documents.file
    from TalentS3 import upload_to_s3

    upload_to_s3(file_obj.read(), folder_path="CandidateDocuments/%s" % candidate_id, name=file_name, public=False)
    db.candidate_document.insert(candidateId=candidate_id, filename=file_name)
