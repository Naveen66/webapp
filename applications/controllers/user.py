# -*- coding: utf-8 -*-


import datetime
import re
from dateutil import parser
import requests
import json
from applications.web.modules.TalentEventsAPI import save_token_in_db, get_access_and_refresh_token, \
    get_member_id_of_user_on_social_network

from gluon.utils import web2py_uuid
from gluon.tools import redirect, URL
from TalentReporting import email_error_to_admins

from TalentUsers import user_ids_in_domain, get_or_create_user, hash_password
from TalentUsers import transfer_ownership_of_all_things_to_user
from TalentEmailMarketing import send_test_email

# noinspection PyProtectedMember
def login():
    if auth.is_logged_in():
        redirect(URL('dashboard', 'index', host=True))

    response.title = "Login"
    response.files.append(URL('static', 'js/jquery.reject.js'))
    response.files.append(URL('static', 'css/jquery.reject.css'))

    # noinspection PyUnusedLocal,PyProtectedMember
    def email_widget(field, value):
        return INPUT(_name=field.name,
                     _id="%s_%s" % (field._tablename, field.name),
                     _class="span12",
                     _type="text",
                     _placeholder="Email Address",
                     requires=field.requires)

    db.user.email.widget = email_widget

    # noinspection PyProtectedMember,PyUnusedLocal
    def password_widget(field, value):
        return INPUT(_name=field.name,
                     _id="%s_%s" % (field._tablename, field.name),
                     _class="span12",
                     _placeholder="Password",
                     _type="password",
                     requires=field.requires)

    db.user.password.widget = password_widget
    if request.vars.email and request.vars.password:
        email = request.vars.email.strip()
        if auth.login_bare(request.vars.email, request.vars.password):
            user = db(db.user.email == email).select(db.user.ALL).first()

            # Get Bearer Token from Talent AuthService
            import requests
            params = dict(grant_type="password", username=request.vars.email, password=request.vars.password)
            try:
                auth_service_token_response = requests.post(current.OAUTH_SERVER,
                                                            params=params, auth=(current.OAUTH_CLIENT_ID, current.OAUTH_CLIENT_SECRET)).json()
                if not (auth_service_token_response.get(u'access_token') and auth_service_token_response.get(u'refresh_token')):
                    logger.error("Either Access Token or Refresh Token is missing")
                else:
                    from TalentUsers import store_auth_service_tokens_in_session
                    store_auth_service_tokens_in_session(auth_service_token_response)
            except Exception as e:
                logger.exception("Couldn't get Bearer Token, %s" % e.message)

            # Check to see if user has already expired
            if user.expiration and user.expiration < datetime.datetime.now():
                session.auth = None
                session.flash = 'Your account has expired. Please contact your account administrator for details.'

                redirect(URL('user', 'login'))
                return dict()

            web_auth_cas = db(db.web_auth_cas.user_id == user.id).select().first()
            if not web_auth_cas:
                # Make new entry in auth_cas table
                ticket = "ST-" + web2py_uuid()
                db.web_auth_cas.update_or_insert(db.web_auth_cas.user_id == user.id, user_id=user.id,
                                                 service='talent_web',
                                                 ticket=ticket, renew='T')
        else:
            # Try logging in with Dice
            auth.dice_login_bare(email, request.vars.password)

    next_login = request.get_vars._next or URL('dashboard', 'index')

    form = auth.login(next=next_login)

    return dict(form=form)


# Format and add <no-reply@gettalent.com> to email source
def set_email_source(form):
    form.vars.emailSource = '"%s" <no-reply@gettalent.com>' % form.vars.emailSource


# noinspection PyProtectedMember
@auth.requires_login()
def profile():
    response.title = "Profile"

    if request.vars._formname == 'widget_page':
        existing_widget_page = db.widget_page(request.vars.id)
        existing_widget_page.update_record(
            replyAddress=request.vars.replyAddress,
            emailSource='"%s" <no-reply@gettalent.com>' % request.vars.emailSource,
            welcomeEmailSubject=request.vars.welcomeEmailSubject,
            welcomeEmailHtml=request.vars.welcomeEmailHtml,
            requestEmailHtml=request.vars.requestEmailHtml
        )
        response.flash = 'Widget settings updated'

    custom_fields = None
    if request.vars._formname == 'custom_fields':
        custom_fields = db(db.custom_field.domainId == auth.user.domainId).select(cache=(cache.ram, 300))
        current_custom_field_names = [row.name.strip() for row in custom_fields]

        # Convert custom field names & types to array if it's string
        new_custom_field_names = request.vars.get('custom_field.name')
        if isinstance(new_custom_field_names, basestring):
            new_custom_field_names = [new_custom_field_names]
        new_custom_field_types = request.vars.get('custom_field.type')
        if isinstance(new_custom_field_types, basestring):
            new_custom_field_types = [new_custom_field_types]

        new_custom_field_cats = request.vars.get('custom_field.category')
        if isinstance(new_custom_field_cats, int):
            new_custom_field_cats = [new_custom_field_cats]

        # Strip the names
        new_custom_field_names = [name.strip() for name in new_custom_field_names]

        # Make dict of new custom field name -> type
        new_name_to_type = dict()
        new_name_to_cat = dict()
        for index, new_custom_field_name in enumerate(new_custom_field_names):
            cf_type = new_custom_field_types[index]
            cat = new_custom_field_cats[index]
            new_name_to_type[new_custom_field_name] = cf_type if cf_type in ('string', 'datetime') else 'string'
            new_name_to_cat[new_custom_field_name] = int(cat) or None

        # Add in custom fields unless one with the same name already exists
        # hmm, can it be same name with different category ? and could not be done at the moment unless custom-field id comes back from solr @TODO
        refresh_custom_fields_cache = True
        for index, new_name in enumerate(new_custom_field_names):

            if new_name and new_name not in current_custom_field_names:
                db.custom_field.insert(domainId=auth.user.domainId, name=new_name, type=new_name_to_type[new_name],
                                       categoryId=new_name_to_cat[new_name])
                refresh_custom_fields_cache = True
            elif new_name and new_name in current_custom_field_names:
                db((db.custom_field.name == new_name) & (db.custom_field.domainId == auth.user.domainId)).update(
                    categoryId=new_name_to_cat[new_name])

        if refresh_custom_fields_cache:
            custom_fields = db(db.custom_field.domainId == auth.user.domainId).select(cache=(cache.ram, 0))

    # there's a bug in the change_password function in web2py - redirects before returning an error
    if request.vars.old_password and request.vars.new_password and request.vars.new_password2:
        if not auth.login_bare(auth.user.email, request.vars.old_password):
            request.vars.old_password = ''
            request.vars.new_password = ''
            request.vars.new_password2 = ''
            session.flash = 'Your old password is not correct. Please try again.'

    form = auth.change_password(next=URL('user', 'profile'))

    # Get custom fields & the # of candidates in each field
    if not custom_fields:
        custom_fields = db(db.custom_field.domainId == auth.user.domainId).select(cache=(cache.ram, 300))
    custom_field_ids = [row.id for row in custom_fields]
    count = db.candidate_custom_field.id.count()
    candidate_custom_field_counts = db(
        db.candidate_custom_field.customFieldId.belongs(custom_field_ids)
    ).select(db.candidate_custom_field.ALL, count, groupby=db.candidate_custom_field.customFieldId)

    # find what values are assigned to each custom field
    count_values = db.candidate_custom_field.value.count()
    custom_fields_values = db(
        db.candidate_custom_field.customFieldId.belongs(custom_field_ids)
    ).select(count_values, db.candidate_custom_field.customFieldId, db.candidate_custom_field.value,
             groupby=db.candidate_custom_field.value)

    for custom_field in custom_fields:
        candidate_custom_field = candidate_custom_field_counts.find(
            lambda cf_row: cf_row.candidate_custom_field.customFieldId == custom_field.id).first()
        custom_field.num_candidates = candidate_custom_field[count] if candidate_custom_field else 0

    # Default Tracking Code
    domain = db.domain(auth.user.domainId)

    if request.vars._formname == 'email_marketing':
        domain.update_record(defaultTrackingCode=request.vars.tracking_code,
                             defaultFromName=request.vars.default_from_name)

    tracking_code = domain.defaultTrackingCode
    default_from_name = domain.defaultFromName

    # user is a Talent Customer admin(customer management tab)
    if auth.has_membership(group_id=1):
        domain_data = db().select(db.domain.id, db.domain.name)
        domain_ids = [row.id for row in domain_data]
        is_talent_admin = True
    else:
        domain_data = db(db.domain.id == auth.user.domainId).select(db.domain.id, db.domain.name)
        domain_ids = [auth.user.domainId]
        is_talent_admin = False

    customer_data = db(db.domain.id.belongs(domain_ids)).select(db.user.id, db.user.email, db.user.firstName,
                                                                db.user.lastName, db.user.addedTime, db.user.expiration,
                                                                db.user_attributes.brand, db.user_attributes.department,
                                                                db.user_attributes.userGroup,
                                                                db.user_attributes.KPI, db.candidate.id.count(),
                                                                db.user.domainId,

                                                                groupby=db.user.id, orderby=(~db.domain.addedTime),

                                                                left=[
                                                                    db.candidate.on(
                                                                        db.user.id == db.candidate.ownerUserId),
                                                                    db.domain.on(db.user.domainId == db.domain.id),
                                                                    db.user_attributes.on(
                                                                        db.user.id == db.user_attributes.userId),
                                                                ]
                                                                )

    last_login_data = db.executesql("""SELECT * FROM (SELECT web_auth_event.time_stamp, web_auth_event.user_id FROM web_auth_event
        WHERE (web_auth_event.description LIKE '% Logged-in')
        ORDER BY web_auth_event.time_stamp DESC) as temp GROUP BY user_id;""", as_dict=True)

    user_admin_data = db(db.web_auth_membership.group_id == 2).select(db.web_auth_membership.user_id,
                                                                      db.web_auth_membership.group_id)

    last_logins = {}
    for row in last_login_data:
        last_login = row.get('time_stamp').strftime("%D") if row.get('time_stamp') else 'Never'
        last_logins.setdefault(row.get('user_id'), last_login)

    dashboard_data = []
    for domain in domain_data:
        dashboard_row = {'domain': domain.name}

        domain_users = customer_data.find(lambda cd_row: cd_row.user.domainId == domain.id)

        domain_candidate_count = 0
        for user in domain_users:
            account_type = user_admin_data.find(lambda uad_row: uad_row.user_id == user.user.id)

            domain_candidate_count += int(user['_extra']["COUNT(candidate.id)"])
            user.user['last_login'] = last_logins.get(user.user.id)
            user.user['addedTime'] = user.user.addedTime.strftime("%D")
            user.user['expiration'] = user.user.expiration.strftime("%D") if user.user.expiration else ''
            user.user['account_type'] = 'Admin' if len(account_type) else 'Normal'

        dashboard_row['candidate_count'] = domain_candidate_count
        dashboard_row['users'] = domain_users

        dashboard_data.append(dashboard_row)
    from TalentUsers import is_current_user_admin
    is_company_admin = is_current_user_admin()

    widget_pages = db(db.user.domainId == auth.user.domainId)(db.widget_page.userId == db.user.id).select(
        db.widget_page.ALL)
    candidate_source_ids = [wp.candidateSourceId for wp in widget_pages]
    # In case widget has no candidate_source_ids
    if None in candidate_source_ids:
        candidate_source_ids = []
        logger.error("A widget_page did not have a candidate_source_id: domainId=%s", auth.user.domainId)
    candidate_sources = db(db.candidate_source.id.belongs(candidate_source_ids)).select()

    if candidate_sources:
        widget_page = widget_pages.find(
            lambda widget_page_row: widget_page_row.candidateSourceId == candidate_sources.first().id).first()
    else:
        widget_page = get_or_create_widget_page(auth.user)
    # All custom fields in logged-in user's domain
    from TalentUsers import RATING_CATEGORY_NAME, get_or_create_rating_custom_fields

    get_or_create_rating_custom_fields(auth.user.domainId)
    domain_custom_fields = db(db.custom_field_category.domainId == auth.user.domainId).select(
        db.custom_field_category.ALL)
    # custom fields categories
    rating_category = domain_custom_fields.find(lambda cf_cat: cf_cat.name == RATING_CATEGORY_NAME).first()
    custom_fields_categories = domain_custom_fields.find(lambda cf_cat: cf_cat.name != RATING_CATEGORY_NAME)

    # Remove rating related fields from custom_fields, Rating will have separate UI.
    custom_fields_without_ratings = custom_fields.find(lambda cf: cf.categoryId != rating_category.id)

    # Custom fields for rating
    rating_custom_fields = custom_fields.find(lambda cf: cf.categoryId == rating_category.id)

    # areas of interest parents 
    areas_of_interest_parents = db((db.area_of_interest.domainId == auth.user.domainId) & (
        (db.area_of_interest.parentId == None) | (db.area_of_interest.parentId == 0))).select(db.area_of_interest.id,
                                                                                              db.area_of_interest.description)

    # custom layout mode check
    domain_settings = get_domain_settings_dict(db.domain(auth.user.domainId))
    current_layout_mode = domain_settings.get('layoutMode', 0)

    social_network_info = db(db.social_network.authUrl != None).select(db.social_network.name,
                                                                db.social_network.clientKey,
                                                                db.social_network.authUrl,
                                                                db.social_network.redirectUri)

    return dict(
        social_network_info=social_network_info,
        form=form,
        widget_page=widget_page,
        custom_fields=custom_fields_without_ratings,
        candidate_custom_field_counts=candidate_custom_field_counts,
        tracking_code=tracking_code,
        default_from_name=default_from_name,
        domains=domain_data,
        dashboard_data=dashboard_data,
        is_gettalent_admin=is_talent_admin,
        is_company_admin=is_company_admin,
        candidate_sources=candidate_sources,
        custom_fields_categories=custom_fields_categories,
        areas_of_interest_parents=areas_of_interest_parents,
        current_layout_mode=current_layout_mode,
        custom_fields_values=custom_fields_values,
        count_values=count_values,
        rating_custom_fields=rating_custom_fields
    )


def get_token():
    """
    Action created to show processing cube until access_token is saved in
    database successfully
    :return:
    """
    session.access_token_data = request.vars
    return dict()


def process_access_token():
    """
    Here we get the Response after User has authorized to his account on
    specific vendor. Response contains a 'code' for eventbrite, and a 'code'
    and 'state' for meetup. Using 'code' we get the access_token from the
    vendor. Then we get the member_id of the user from respective API POST
    call. Once we have member_id, we store the data in database table
    user_credentials.
    """
    status = False
    social_network = ''
    data = session.access_token_data
    eventbrite = db(db.social_network.name == 'Eventbrite').select().first()
    meetup = db(db.social_network.name == 'Meetup').select().first()
    if data.get('code') and data.has_key('state'):  # meetup
        social_network = meetup
    elif data.get('code'):  # eventbrite
        social_network = eventbrite
    access_token, refresh_token = get_access_and_refresh_token(social_network,
                                                               data['code'])
    if access_token:
        # we have access token, now we need member id from the social network
        member_id = get_member_id_of_user_on_social_network(social_network, access_token)
        if member_id:
            # save access_token, refresh_token and member_id in database
            status = save_token_in_db(access_token, refresh_token, member_id, social_network)
    return status


def get_extended_access_token():
    """
    Facebook issues a short term token which is refreshed here and a long
    term extended token(expires in approx 2 months) is fetched.
    Then extended token is saved in database.
    """
    status = False
    social_network = db(db.social_network.name ==
                        request.vars.vendor_id).select().first()
    if social_network.name == 'Facebook':
        payload = {'client_id': social_network.clientKey,
                   'client_secret': social_network.secretKey,
                   'grant_type': 'fb_exchange_token',
                   'fb_exchange_token': request.vars.token,
                   'redirect_uri': social_network.redirectUri}
        url = social_network.authUrl + "/access_token"
        r = requests.get(url, params=payload)
        extended_token = r.content.split('=')[1].split('&')[0]
        # There is no refresh token for facebook, so second parameter
        # is set to empty
        status = save_token_in_db(extended_token,
                                  ' ',
                                  request.vars.member_id,
                                  social_network)
    return dict(status=status)


def add_social_network():
    """
    An SQL form which stores the information related to a social network.
    Admin can provide data like client_key, secret_key, redirect_url in this
    form to be saved in db table social_network
    :return:
    """
    form = SQLFORM(db.social_network)
    # form['_style'] = 'border:1px solid black; color:#000000'
    form['_class'] = 'table form-horizontal'
    form.add_button('Manage Social Networks', URL('user', 'manage_social_network'))
    if form.process().accepted:
        link = form.vars['redirectUrl']
        form_data = {'vendorId': form.vars['vendorId'],
                     'clientKey': form.vars['clientKey'],
                     'appUrl': form.vars['appUrl'],
                     'redirectUrl': form.vars['redirectUrl'],
                     'authUrl': form.vars['authUrl']}
        session.form_data = form_data
        redirect(link)
    elif form.errors:
        response.flash = 'Form has errors!'
    else:
        response.flash = 'Please fill out the form...'
    return dict(form=form)


def manage_social_network():
    """
    A form to manage social networks in an SQLform grid.
    :return:
    """
    grid = SQLFORM.grid(db.social_network, editable=True, deletable=True)
    return locals()


@auth.requires_login()
def send_test_email_action():
    send_test_email(auth.user, request.vars)
    return ""


@auth.requires_login()
def logout():
    response.generic_patterns = ['*.html']
    return auth.logout()


@auth.requires_membership('Customer Manager')
def membership():
    form = SQLFORM.grid(db.web_auth_membership)
    return response.render('user/form.html', dict(form=form))


@auth.requires_membership('Customer Manager')
def impersonate():
    if request.args:
        impersonated_id = request.args[0]
        if not auth.has_permission('impersonate', db.user, impersonated_id):
            auth.add_permission(1, 'impersonate', db.user, impersonated_id)
        auth.impersonate(user_id=impersonated_id)
        redirect(URL('dashboard', 'index'))
    return dict()


@auth.requires_membership('Customer Manager')
def manage_areas_of_interest():
    areas_of_interest = []
    domain_id = None
    if request.args(0):
        domain_id = int(request.args[0])
        if request.vars.areas_of_interest:  # newline separated areas of interest
            new_descriptions = [desc.strip() for desc in request.vars.areas_of_interest.split('\n')]
            existing_areas_of_interest_rows = db(db.area_of_interest.domainId == domain_id).select(
                db.area_of_interest.ALL)
            existing_areas_of_interest_dict = existing_areas_of_interest_rows.as_dict('description')
            # Add in new AOIs
            for new_description in new_descriptions:
                if new_description and not existing_areas_of_interest_dict.get(new_description):
                    db.area_of_interest.insert(domainId=domain_id, description=new_description)
            # Delete old AOIs
            for existing_aoi in existing_areas_of_interest_rows:
                if existing_aoi.description not in new_descriptions:
                    db(db.area_of_interest.id == existing_aoi.id).delete()
        areas_of_interest = db(db.area_of_interest.domainId == domain_id).select().as_list()

    return dict(areas_of_interest=areas_of_interest, domain_id=domain_id)


@auth.requires_membership('Customer Manager')
def manage_universities():
    if request.vars.universities:  # newline separated areas of interest
        new_names = [desc.strip() for desc in request.vars.universities.split('\n')]
        existing_names_dict = db().select(db.university.ALL).as_dict('name')
        # Add in new universities
        for name in new_names:
            if name and not existing_names_dict.get(name):
                db.university.insert(name=name)
    universities = db().select(db.university.ALL).as_list()

    return dict(universities=universities)


@auth.requires_membership('Customer Manager')
def flush_cache():
    cache.redis.r_server.flushall()
    return {'redis_info': cache.redis.r_server.info()}


@auth.requires(auth.has_membership(group_id=1) or auth.has_membership(group_id=2))
def delete_user():
    from TalentUsers import get_user_manager_group_id
    import TalentUsers
    from CustomErrors import CustomErrorResponse
    # if user is part of User Manager group, validate that the deleted user is part of their domain
    admin = auth.user.id
    user_ids = request.vars.user_id
    user_manager_group_id = get_user_manager_group_id()
    if type(user_ids) != list:
        user_ids = [int(user_ids)]

    if auth.has_membership(group_id=1):
        # current user is a customer administrator (user of gettalent company)
        for user_id in user_ids:
            if user_id != admin:
                domain_id = TalentUsers.domain_id_from_user_id(user_id)
                admin_user_row = db(
                    (db.user.domainId == domain_id) &
                    (db.web_auth_membership.group_id == user_manager_group_id) &
                    (db.user.id != user_id) &
                    (db.web_auth_membership.user_id == db.user.id)).select(db.user.id)
                if admin_user_row:
                    admin_user_id = admin_user_row[0].id
                else:
                    normal_user_row = db(
                        (db.user.domainId == domain_id) &
                        (db.web_auth_membership.group_id != user_manager_group_id) &
                        (db.user.id != user_id)).select(db.user.id)
                    if normal_user_row:
                        normal_user_id = normal_user_row[0].id
                        admin_user_id = normal_user_id
                    else:
                        response.status = 400
                        return CustomErrorResponse.DELETE_LAST_USER_IN_DOMAIN_NOT_ALLOWED

                if admin_user_id:
                    # Assign Candidates,Smartlists,Email Campaigns to admin user or normal user of same domain
                    transfer_ownership_of_all_things_to_user(user_id, admin_user_id)
                    # Upload candidate documents in the domain of deleting user
                    from TalentCloudSearch import upload_candidate_documents_in_domain

                    upload_candidate_documents_in_domain(domain_id)
                    # Delete the user
                    db(db.user.id == user_id).delete()
                    # Delete the user attributes
                    db(db.user_attributes.userId == user_id).delete()
            elif user_id == admin:
                response.status = 400
                return CustomErrorResponse.DELETE_LOGGED_IN_USER_NOT_ALLOWED
    elif auth.has_membership(group_id=2):
        # check to see if requested users are in current user's domain
        users = db((db.user.domainId == auth.user.domainId) &
                   (db.user.id.belongs(user_ids))).select(db.user.id)

        if len(users) != len(user_ids):
            response.status = 403
            return CustomErrorResponse.USER_OUTSIDE_DOMAIN
        # delete users
        for user_id in user_ids:
            if user_id != admin:
                admin_user_row = db((db.user.domainId == auth.user.domainId) & (
                    db.web_auth_membership.group_id == user_manager_group_id) \
                                    & (db.user.id != user_id) & (db.web_auth_membership.user_id == db.user.id)).select(
                    db.user.id)
                admin_user_id = admin_user_row[0].id
                # Assign user's data to the admin of that domain
                transfer_ownership_of_all_things_to_user(user_id, admin_user_id)
                # Upload candidate documents in the domain of deleting user
                from TalentCloudSearch import upload_candidate_documents_in_domain

                upload_candidate_documents_in_domain(auth.user.domainId)
                # Delete the user
                db(db.user.id == user_id).delete()
                # Delete the user attributes
                db(db.user_attributes.userId == user_id).delete()

            elif user_id == admin:
                response.status = 400
                return CustomErrorResponse.DELETE_LOGGED_IN_USER_NOT_ALLOWED

    return response.json(1)


@auth.requires(auth.has_membership(group_id=1) or auth.has_membership(group_id=2))
def resend_invite():
    from CustomErrors import CustomErrorResponse

    user_id = request.vars.user_id

    if auth.has_membership(group_id=1):
        user = db((db.user.id == user_id)).select(db.user.id, db.user.email, db.user.registration_key,
                                                  db.user.expiration).first()
    else:
        user = db((db.user.domainId == auth.user.domainId) & (db.user.id == user_id)).select(db.user.id, db.user.email,
                                                                                             db.user.registration_key,
                                                                                             db.user.expiration).first()

    if not user:
        response.status = 403
        return CustomErrorResponse.USER_OUTSIDE_DOMAIN
    else:
        import datetime

        email, registration_key, expiration = user.email, user.registration_key, user.expiration
        today_date = datetime.datetime.today()
        if not registration_key:
            if expiration and expiration <= today_date:
                response.status = 400
                return CustomErrorResponse.USER_ACCOUNT_EXPIRED
            response.status = 401
            return CustomErrorResponse.USER_ALREADY_REGISTERED
        from TalentUsers import send_new_account_email

        send_new_account_email(email, registration_key)

    return response.json(1)


# Inputs:
# key: dashboard or search
# field: name of search form field to hide/show. can be multiple values comma-separated
@auth.requires(auth.has_membership(group_id=1) or auth.has_membership(group_id=2))
def toggle_hidden_field():
    # Get the domain of this user
    domain = db.domain(auth.user.domainId)
    domain_settings_dict = get_domain_settings_dict(domain)

    # If field is already hidden, remove from list to show it. Otherwise, add field.
    key = request.vars.key
    hidden_fields = get_hidden_fields_from_domain_settings_dict(key, domain_settings_dict)

    form_fields = [field.strip() for field in request.vars.field.split(',')]
    for form_field in form_fields:
        if form_field in hidden_fields:
            hidden_fields.remove(form_field)
        else:
            hidden_fields.append(form_field)

    response_code = 1 if update_hidden_fields(domain, key, hidden_fields) else 0

    return response.json(dict(success=response_code))


@auth.requires_login()
def create_category():
    from CustomErrors import CustomErrorResponse

    name = request.vars.name
    if name:
        existing_category = db((db.custom_field_category.name == name) & (
            db.custom_field_category.domainId == auth.user.domainId)).select()
        if existing_category:
            response.status = 400
            return CustomErrorResponse.DUPLICATE_CATEGORY

        else:
            category_id = db.custom_field_category.insert(domainId=auth.user.domainId, name=name)

            db(db.custom_field_category.id > 0).select(cache=(cache.ram, 0))
            message = 'New category %s has been added.' % name
            return response.json({"id": category_id, "name": name, "message": message})

    response.status = 400
    return CustomErrorResponse.EMPTY_CATEGORY


@auth.requires_login()
def list_categories():
    results = db(db.custom_field_category.domainId == auth.user.domainId).select(db.custom_field_category.id,
                                                                                 db.custom_field_category.name)
    return response.json(results)


@auth.requires_login()
def add_new_aoi():
    if request.post_vars.name:
        existing_aoi = db((db.area_of_interest.description == request.post_vars.name) & (
            db.area_of_interest.domainId == auth.user.domainId)).select(db.area_of_interest.id)
        if not existing_aoi:
            db.area_of_interest.insert(description=request.post_vars.name, parentId=request.post_vars.parent,
                                       domainId=auth.user.domainId)
            return request.post_vars.name
        else:
            raise HTTP(400, 'Area of interest already exists')
    else:
        raise HTTP(400, 'Name is required')


@auth.requires_login()
def add_new_university():
    if request.post_vars.name:
        existing_university = db(db.university.name == request.post_vars.name).select(db.university.id)
        if not existing_university:
            db.university.insert(name=request.post_vars.name)
            return request.post_vars.name
        else:
            raise HTTP(400, 'University already exists')
    else:
        raise HTTP(400, 'Name is required')


@auth.requires_login()
def add_new_major():
    if request.post_vars.name:
        existing_major = db(
            (db.majors.name == request.post_vars.name) & (db.majors.domainId == auth.user.domainId)).select(
            db.majors.id)
        if not existing_major:
            db.majors.insert(name=request.post_vars.name, domainId=auth.user.domainId)
            return request.post_vars.name
        else:
            raise HTTP(400, 'Major already exists')
    else:
        raise HTTP(400, 'Name is required')


@auth.requires(auth.has_membership(group_id=1) or auth.has_membership(group_id=2))
def create_user_for_company():
    email = request.vars.username

    # if user is a gettalent admin, they can create a new domain
    if auth.has_membership(group_id=1):
        from handy_functions import is_number

        if is_number(request.vars.domain):
            domain_id = int(request.vars.domain)
        else:
            domain_name = request.vars.domain

            if domain_name:
                # Check if the domain is already exists or not
                existing_domain = db((db.domain.name == domain_name)).select().first()
                if existing_domain:
                    raise HTTP(400, 'Domain name exists already.')
                else:
                    import TalentUsers

                    domain_id = TalentUsers.get_or_create_domain(domain_name)

            else:
                raise Exception(400, 'Domain Name is required')

            import TalentUsers

            domain_id = TalentUsers.get_or_create_domain(domain_name)

    else:
        domain_id = auth.user.domainId

    expiration = None
    if request.vars.expiration_date:
        expiration = parser.parse(request.vars.expiration_date)

    user_attributes = dict(brand=request.vars.brand, department=request.vars.department, userGroup=request.vars.group,
                           KPI=request.vars.KPI or 1)

    is_active = True
    if request.vars.is_active == '0':
        is_active = False

    is_admin = False
    if request.vars.is_admin == '1':
        is_admin = True

    # create user for existing domain
    result = get_or_create_user(email, domain_id, first_name=request.vars.firstName, last_name=request.vars.lastName,
                                expiration=expiration, is_active=is_active, is_admin=is_admin,
                                user_attributes=user_attributes,
                                set_registration_key=True)

    # If this domain doesn't contain any templates, then create the sample templates
    import TalentUsers

    TalentUsers.get_or_create_default_email_templates(domain_id)

    user_id = result['user_id']

    result = 1 if type(result) == dict else result

    return response.json(dict(result=result, user_id=user_id))


@auth.requires_login()
def change_password():
    response.generic_patterns = ['*.html']
    return dict(form=auth.change_password())


def reset_password():
    return dict(form=auth.reset_password(next=URL('dashboard', 'index')))


def request_reset_password():
    if request.env.request_method == 'POST':
        import datetime

        email = request.vars.email
        if email:
            # Check the email existence on the database
            valid_email = db(db.user.email == email).select().first()
            if not valid_email:
                session.flash = 'No user with email %s found!' % email
                redirect(URL('user', 'request_reset_password'))
            # If there is registation key, user has not yet activated the account.
            registration_key = valid_email.registration_key
            # Check the user account activation via registration key.
            if registration_key:
                session.flash = 'Password reset not allowed: Your registration is pending, please check the email to activate the account'
                redirect(URL('user', 'request_reset_password'))
            expiration = valid_email.expiration
            today_date = datetime.datetime.today()
            # Check the expiration has given to the account and with current date
            if expiration and expiration < today_date:
                session.flash = "Your account has expired. Please contact your account administrator for details."
                redirect(URL('user', 'request_reset_password'))

    return dict(form=auth.request_reset_password(next=URL('user', 'request_reset_password')))


def set_new_password():
    """
    Get registration key from URL params
    Get user email from request params

    If user in db has matching registration key, allow current user to set new password
        If user password matches,
            Set password, then redirect to login screen with message confirming new password change
        else,
            return error message

    """
    registration_key = request.vars.registration_key
    email = request.vars.email

    password1 = request.vars.password1 or ''
    password2 = request.vars.password2 or ''

    # validate password for Caps, Number, and 8-char length
    is_valid_password = len(re.findall(r'[A-Z]', password1)) and len(re.findall(r'[0-9]', password1)) and (
        len(password1) > 7)

    user = db(db.user.email == email).select().first()
    if not user:
        session.flash = 'No user with email %s found!' % email
        redirect(URL('user', 'login'))
    elif user.registration_key == registration_key and user.registration_key:
        if not password1 or not password2:
            # user hasn't submitted their password
            return dict(registration_key=registration_key, email=email)

        elif not is_valid_password:
            response.flash = 'Password is not valid: please follow the password requirements listed below.'
            return dict(registration_key=registration_key, email=email)

        elif password1 == password2:
            password = hash_password(password1)
            user.update_record(password=password, registration_key='')
            # redirect to login page, tell them their new password has been set.
            session.flash = 'New password saved! Please login to continue.'
            redirect(URL('user', 'login'))
        else:
            # passwords don't match, return error message telling them their passwords don't match
            response.flash = 'Your passwords must match! Please re-enter them below.'
            return dict(registration_key=registration_key, email=email)
    else:
        # redirect user to login form, tell them their registration key is incorrect
        session.flash = 'Your registration key is incorrect!'
        redirect(URL('user', 'login'))

    return dict()


# Inputs: domain_id, email, password
# Outputs: user_id
def mobile_create():
    domain_id, email, password = request.vars.domain_id, request.vars.email, request.vars.password

    # Get and verify domain, email, and password
    if not domain_id or not email or not password:
        return dict(user_id=False)
    domain = db.domain(domain_id)
    if not domain:
        return dict(user_id=False)
    user = db(db.user.email == email).select().first()  # make sure user doesn't exist
    if user:
        return dict(user_id=False)

    # Make new entry in user table
    registration_key = web2py_uuid()
    hashed_password = hash_password(password)
    user_id = db.user.insert(email=email, password=hashed_password, registration_key=registration_key,
                             domainId=domain_id)

    db.commit()

    # TODO: Remove this functionality when we'll add UI for user scoped roles
    from TalentUsers import add_roles_to_user
    add_roles_to_user(user_id)
    
    # Make new widget_page if first user in domain
    get_or_create_widget_page(db.user(user_id))

    return dict(user_id=user_id, email=email, registration_key=registration_key)


# Inputs: email, password
# Outputs: user_id, ticket
def mobile_login():
    # Verify email and password
    email, password = request.vars.email, request.vars.password
    if not email or not password:
        return dict(user_id=False, ticket=False)

    # user = db(db.user.email == email).select().first()
    # hashed_password = hash_password(password)
    # if not user or user.password != hashed_password: return dict(user_id=False, ticket=False)
    if not auth.login_bare(email, password):
        return dict(user_id=False, ticket=False)

    user = db(db.user.email == email).select().first()

    # Make new entry in auth_cas table
    web_auth_cas = db(db.web_auth_cas.user_id == user.id).select().first()
    if not web_auth_cas:
        ticket = "ST-" + web2py_uuid()
        db.web_auth_cas.update_or_insert(db.web_auth_cas.user_id == user.id, user_id=user.id, service='talent_mobile',
                                         ticket=ticket, renew='T')
    else:
        ticket = web_auth_cas.ticket

    # Set user's Get Started action for Mobile App Install
    set_get_started_action(user, GET_STARTED_ACTIONS['DOWNLOAD_MOBILE_APP'])

    # Return ticket of new entry
    return dict(user_id=user.id, ticket=ticket)


# Inputs: email, ticket
# Outputs: is_valid (true or false), user_id
def mobile_validate():
    # Take in email and ticket
    email, ticket = request.vars.email, request.vars.ticket
    # Search auth_cas table for email and verify the ticket
    if not email or not ticket:
        return dict(user_id=False, is_valid=False)

    user = db(db.user.email == email).select().first()
    if not user:
        return dict(is_valid=False, user_id=False)

    auth_cas_record = db((db.web_auth_cas.user_id == user.id) & (db.web_auth_cas.ticket == ticket)).select().first()
    # if session lasted longer than 2 weeks, delete and return notHING

    return dict(is_valid=True, user_id=user.id) if auth_cas_record else dict(is_valid=False, user_id=False)


# Inputs: email, ticket
# Outputs: logout (boolean)
def mobile_logout():
    # Get web_auth_cas record
    email, ticket = request.vars.email, request.vars.ticket
    if not email or not ticket:
        return dict(logout=False)

    user = db(db.user.email == email).select().first()
    if not user:
        return dict(logout=False)

    auth_cas_record = db((db.web_auth_cas.user_id == user.id) & (db.web_auth_cas.ticket == ticket)).select().first()
    if not auth_cas_record:
        return dict(logout=False)

    # Delete web_auth_cas record
    db(db.web_auth_cas.id == auth_cas_record.id).delete()
    return dict(logout=True)


# Inputs: email
# Outputs: email_sent, user_id
def mobile_email_reset_password():
    # request_reset_password
    # email_reset_password
    # reset_password

    email = request.vars.email
    user = db(db.user.email == email).select().first()
    if not user:
        return dict(email_sent=False, user_id=False)

    email_sent = auth.email_reset_password(user)

    return dict(email_sent=email_sent, user_id=user.id)


def get_login():
    auth.basic()
    if not auth.user:
        if IS_DEV and request.vars.username and request.vars.password:
            auth.login_bare(request.vars.username, request.vars.password)
        if not auth.user:
            return dict(error='Not authorized', request_headers="%s" % request.wsgi.environ)
    return_dict = dict(request_headers="%s" % request.wsgi.environ)
    domain_id = auth.user.domainId
    return_dict['domainId'] = domain_id
    return_dict['domainName'] = db.domain(domain_id).name
    return_dict['id'] = auth.user.id

    return_dict['ratingTagList'] = db(
        (db.rating_tag.id == db.rating_tag_user.ratingTagId) &
        (db.rating_tag_user.userId == db.user.id) &
        (db.user.domainId == domain_id)
    ).select(db.rating_tag.ALL, distinct=True, cache=(cache.ram, 300)).as_list()

    return_dict['candidateSourceList'] = db(
        (db.candidate_source.domainId == domain_id)
    ).select().as_list()

    return_dict['candidates'] = db(
        (db.candidate.ownerUserId == auth.user.id)
    ).select(db.candidate.formattedName, db.candidate.firstName, db.candidate.lastName, db.candidate.id).as_list()

    return return_dict


def check_for_updated_app_version():
    auth.basic()
    if not auth.user:
        if IS_DEV and request.vars.username and request.vars.password:
            auth.login_bare(request.vars.username, request.vars.password)
        if not auth.user:
            return dict(error='Not authorized', request_headers="%s" % request.wsgi.environ)

    return request.vars.version == "1.0"


@auth.requires_login()
def activities():
    from TalentUsers import domain_from_id
    from TalentActivityAPI import TalentActivityAPI

    domain = domain_from_id(auth.user.domainId)
    api = TalentActivityAPI()
    user_ids = user_ids_in_domain(auth.user.domainId)
    return_activities = api.get(user_ids=user_ids, limit=25)
    return dict(domain=domain, activities=return_activities)


@cache.action(time_expire=60 * 5, cache_model=cache.ram, prefix="activities-", public=False,
              session=True)  # Cache for 5 minutes
@auth.requires_login()
def _activities_in_layout():
    from TalentActivityAPI import TalentActivityAPI

    activity_api = TalentActivityAPI()
    recent_activities = activity_api.get_recent_readable(user_ids_in_domain(auth.user.domainId), limit=5)
    return dict(recent_activities=recent_activities)


@auth.requires_login()
def get_widget_resume_soure_id():  # TODO change to ..._source_id
    candidate_source_id = request.vars.candidateSourceId
    widget_page = db(db.widget_page.candidateSourceId == candidate_source_id).select().first()
    return response.json(dict(result=widget_page))
    # return widgetPage


@auth.requires(auth.has_membership(group_id=1) or auth.has_membership(group_id=2))
def edit_layout_mode():
    domain = db.domain(auth.user.domainId)
    domain_settings = get_domain_settings_dict(domain)

    if not domain_settings.get('layoutMode'):
        layout_mode_value = 1
    else:
        layout_mode_value = 0 if domain_settings.get('layoutMode') else 1

    update_hidden_fields(domain, 'layoutMode', layout_mode_value)
    return layout_mode_value


def dice_oauth_callback():
    """
    Callback for the implicit flow: https://tools.ietf.org/html/rfc6749#section-4.2.2

    Inputs: access_token, refresh_token, token_type, user_id.

    If no getTalent user exists with the given Dice user_id or email address, will auto-create the user & domain. Then, log them in.
    If a getTalent user is found with the given email but does not have a Dice ID, will still log them in.

    """

    # Input validation
    access_token = request.vars.access_token
    refresh_token = request.vars.refresh_token
    token_type = request.vars.token_type
    dice_user_id = request.vars.user_id
    dice_env = request.vars.environment or 'prod'

    if not access_token or not refresh_token or not token_type or not dice_user_id:
        email_error_to_admins(body="Received a request to dice_oauth_callback with missing parameter",
                              subject="dice_oauth_callback: Missing input")
        redirect("https://www.gettalent.com")

    # Query Dice API for user info
    from TalentDiceClient import query_dice_user_id

    user_info = query_dice_user_id(dice_user_id=dice_user_id, dice_access_token=access_token,
                                   dice_refresh_token=refresh_token, dice_env=dice_env)
    if not user_info:
        logger.error("dice_oauth_callback(%s): Failed to query Dice API", request.vars)
        email_error_to_admins(body="Failed to query Dice API during dice_oauth_callback. See error logs for details",
                              subject="dice_oauth_callback: Querying Dice API")
        redirect("https://www.gettalent.com")
    dice_company_id = user_info['dice_company_id']
    first_name = user_info['first_name']
    last_name = user_info['last_name']
    email = user_info['email']

    # Get or create the user
    from TalentUsers import get_or_create_dice_user

    user_row = get_or_create_dice_user(email, first_name, last_name, dice_user_id, dice_company_id, access_token,
                                       refresh_token, dice_env=dice_env)

    if user_row:
        # Log in user & go to Dashboard
        logger.info("Logging in user %s from Dice", user_row.email)
        auth.login_and_set_dice_tokens(user_row, access_token, refresh_token)
        redirect(URL('web', 'dashboard', 'index'))
        return dict(message='Success')
    else:
        # If user unknown or user creation failed, redirect to gettalent.com
        logger.error("dice_oauth_callback(request.vars=%s): User creation failed", request.vars)
        email_error_to_admins(body="User auto-creation failed in dice_oauth_callback",
                              subject="dice_oauth_callback: Auto-create user")
        redirect("https://www.gettalent.com")
