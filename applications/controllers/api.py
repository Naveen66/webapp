import json
from datetime import datetime

import dateutil.parser
import pytz

from requests.packages.urllib3.exceptions import ConnectionError

from handy_functions import is_number
from applications.web.modules.TalentEventsAPI import process_event, \
    EventInputMissing, EventNotCreated, EventNotSaved, EventNotPublished, \
    InvalidAccessToken, EventNotUnpublished, EventLocationNotCreated, Meetup, \
    UserCredentialsNotFound, SocialNetworkNotImplemented, validate_and_refresh_access_token
from CustomErrors import CustomErrorResponse
from TalentUsers import authenticate_user, check_if_user_exists, get_domain_value, verify_user_scoped_role
from TalentUsers import is_current_user_admin, is_current_user_gettalent_admin
from TalentUsers import create_user_for_company, get_or_create_domain
from TalentUsers import domain_id_from_user_id, transfer_ownership_of_all_things_to_user
from TalentUsers import _update_user, get_users_domain_admin
from TalentEmailMarketing import create_email_campaign
from TalentCloudSearch import upload_candidate_documents_of_user
from TalentEmailMarketing import send_campaign_emails_to_candidate
from TalentEmailMarketing import does_email_campaign_belong_to_domain
from TalentCandidates import fetch_candidate_info, does_candidate_belong_to_user
from TalentEmailMarketing import get_email_campaign_candidate_ids_and_emails
from TalentSmartListAPI import get, create


@auth.requires(auth.has_membership(group_id=1) or auth.has_membership(group_id=2))
def daily_job_alert():
    candidate_id = request.vars.candidate_id  # Vince's candidate
    if not candidate_id:
        raise HTTP(400, "candidate_id param required")
    if not request.vars.do_email_business:
        raise HTTP(400, "do_email_business param required")

    user_id = request.vars.user_id or 251  # Michelle Garcia's user ID
    daily_job_alert_campaign_id = 149  # Daily job alert candidate

    candidate_address = db(db.candidate_email.candidateId == candidate_id).select().first().address
    info_dict = send_campaign_emails_to_candidate(db.user(user_id),
                                                  db.email_campaign(daily_job_alert_campaign_id),
                                                  db.candidate(candidate_id),
                                                  candidate_address,
                                                  do_email_business=int(request.vars.do_email_business))

    return info_dict


def test_talent_web():
    import os

    first_candidate = db().select(db.candidate.id).first()
    if not first_candidate: raise HTTP(500, "500: DB unable to select first candidate")

    # Test resume parsing
    user = db(db.user.email == "o.masood@veechi.com").select().first()
    if not user: raise HTTP(400, "400: User email o.masood@veechi.com not found")

    filename = os.getcwd() + "/applications/web/static/sample_resumes/pdfs/Adams.Riley.pdf"

    from TalentCore import process_resume

    result = process_resume(user_id=user.id, file_ext='pdf', file_obj=open(filename))
    candidate_id = result['candidate_id']
    if not candidate_id:
        raise HTTP(500, '500: Resume parsing failed')

    # Now delete the created candidate
    _delete_candidates([candidate_id], user_id=user.id, source_product_id=WEB_PRODUCT_ID)

    return '200'


def dice_import():
    """
    Takes a JSON dict containing:
        -candidates: array of Dice candidate dictionaries. (See GET-261 for a sample of a Dice candidate dictionary.)
        -user_id: Dice user ID.
        -access_token: Access token used to get data about the given user_id.

    """
    try:
        request_body = request.body.read()
        logger.info("api/dice_import: Received request body: %s", request_body)
        import TalentReporting
        TalentReporting.email_notification_to_admins("Body of POST: %s" % request_body, subject="api/dice_import")
        body_dict = json.loads(request_body)
    except Exception:
        logger.exception("api/dice_import: Failed to parse JSON body")
        response.status = 400
        return dict(error=dict(message="Body of POST must be JSON"))

    if not isinstance(body_dict, dict):
        response.status = 400
        return dict(error=dict(message="Body of POST must be a JSON dict"))

    dice_user_id = body_dict.get('user_id')
    access_token = body_dict.get('access_token')
    refresh_token = body_dict.get('refresh_token')
    candidates = body_dict.get('candidates')
    dice_env = body_dict.get('environment', 'prod').lower()

    if dice_env == 'dev':  # TODO Zac asked for us to just return 200 if the environment is dev.
        response.status = 200
        return {"num_added": 1, "num_deleted": 0}

    if not dice_user_id or not access_token or not candidates or not refresh_token:
        response.status = 400
        return dict(error=dict(message="Missing required field"))

    # Get the Dice user given the user_id and access_token
    from TalentDiceClient import query_dice_user_id

    user_dict = query_dice_user_id(dice_user_id=dice_user_id, dice_access_token=access_token, dice_refresh_token=refresh_token, dice_env=dice_env)
    if not user_dict:
        response.status = 500
        current.logger.error("Error querying Dice API for user ID %s, access token %s", dice_user_id, access_token)
        from TalentReporting import email_error_to_admins
        email_error_to_admins("Error querying Dice API for user ID %s, access token %s. Check error logs for more details" % (dice_user_id, access_token),
                              subject="api/dice_import: Error querying Dice API")
        return dict(error=dict(message="Error querying Dice API for user ID %s, access token %s" % (dice_user_id, access_token)))

    # Get or create the user
    dice_company_id = user_dict['dice_company_id']
    first_name = user_dict['first_name']
    last_name = user_dict['last_name']
    email = user_dict['email']
    try:
        from TalentUsers import get_or_create_dice_user
        user_row = get_or_create_dice_user(email, first_name, last_name, dice_user_id, dice_company_id, access_token, refresh_token, dice_env=dice_env)

        # Finally, do the actual import
        from TalentDiceCandidateImport import import_dice_candidates
        result_dict = import_dice_candidates(user_id=user_row.get('id'), dice_candidate_dicts=candidates)
    except Exception:
        logger.exception("api/dice_import: Exception importing candidates for user %s. Candidates=%s", email, candidates)
        response.status = 500
        result_dict = {'error': {'message': 'An internal server error occurred while importing candidates.'}}

    return result_dict


def parse_request_body():
    """
    :rtype: dict[str, T]
    """
    request_body = ''
    try:
        request_body = request.body.read()
        logger.info('api/%s/%s: Received request body: %s',
                    request.function, request.env.request_method, request_body)
        body_dict = json.loads(request_body)
    except Exception:
        logger.exception('api/%s/%s: Received request body: %s',
                         request.function, request.env.request_method, request_body)
        response.status = 400
        return CustomErrorResponse.make_response_with_text(CustomErrorResponse.MUST_BE_JSON_DICT,
                                                           "Unable to parse request body as JSON")

    # Request body must be a JSON dict
    if not isinstance(body_dict, dict):
        response.status = 400
        return CustomErrorResponse.MUST_BE_JSON_DICT

    # Request body cannot be empty
    if not any(body_dict):
        response.status = 400
        return CustomErrorResponse.make_response_with_text(CustomErrorResponse.MISSING_INPUT, "Request body cannot be empty")

    return body_dict


@request.restful()
def events():
    """
    This is RESTful service. It provides methods like:
    GET:
        1. get_events: returns user all events in database
            url: /web/api/events.json

        2. get_event_by_id: returns a single event based on id
            url: web/api/events/event/:id.json

        3. get_groups: returns Meetup groups for which user is admin
            url: web/api/events/groups.json

        3. get_error_codes: returns our custom error codes info so it can be determined by client
        that which error occurred
            url: web/api/events/errorcodes.json

        3. get_timezones: returns a list of timezones along with GMT offset value
            url: web/api/events/timezones.json

    POST:
        create a new event
            url: web/api/events.json

        update an existing event
            url: web/api/events/:id.json

    :return: JSON data
    """

    def GET(*args, **vars):
        user = authenticate_user()
        if not user:
            response.status = 401
            return CustomErrorResponse.NOT_AUTHORIZED
        assert user is not None

        def get_event_by_id(event_id):
            event = db(db.event.id == event_id).select().first()
            return event

        def get_events():
            # return all events
            db_events = db(db.event.userId == user.id).select()
            return db_events

        def get_groups():
            # gets groups of Meetup for which current user is an organizer
            meetup_object = Meetup()
            return meetup_object.get_groups()

        def get_error_codes():
            """
            Get Error codes with their name to know what does a error code means
            """
            error_names = [attr for attr in dir(CustomErrorResponse()) if not callable(attr) and not attr.startswith("__")]
            error_codes = dict()
            for error_name in error_names:
                try:
                    error_codes[error_name] = getattr(CustomErrorResponse, error_name)['error']['code']
                except:
                    pass
            return error_codes

        def get_timezones():
            timezones = []
            for timezone_name in pytz.common_timezones:
                offset = datetime.now(pytz.timezone(timezone_name)).strftime('%z')
                offset_hours = offset[:3]
                offset_minutes = offset[3:]
                timezone = dict(name='GMT ' + offset_hours + ':' + offset_minutes + '  ' + timezone_name,
                                value=timezone_name)
                timezones += [timezone]
                timezones.sort()
            return timezones

        if len(args) > 0 and args[0].lower() == 'groups':
            try:
                return dict(groups=get_groups())
            except InvalidAccessToken:
                response.status = 400
                return CustomErrorResponse.INVALID_ACCESS_TOKEN

        # get single event
        if len(args) > 1 and args[0].lower() == 'event':
            return dict(event=get_event_by_id(args[1]))

        if len(args) > 0 and args[0].lower() == 'errorcodes':
            return dict(errorCodes=get_error_codes())

        if len(args) > 0 and args[0].lower() == 'timezones':
            return dict(timezones=get_timezones())

        return dict(events=get_events())

    def POST(*args, **vars):
        user = authenticate_user()
        if not user:
            response.status = 401
            return CustomErrorResponse.NOT_AUTHORIZED
        assert user is not None
        # status contains the inserted id or False in case insert fails
        try:
            process_event(vars, user.id)
        except EventInputMissing:
            response.status = 400
            return CustomErrorResponse.MISSING_INPUT
        except EventNotPublished:
            response.status = 400
            return CustomErrorResponse.EVENT_NOT_PUBLISHED
        except EventNotUnpublished:
            response.status = 400
            return CustomErrorResponse.EVENT_NOT_UNPUBLISHED
        except EventNotSaved:
            response.status = 400
            return CustomErrorResponse.EVENT_NOT_CREATED
        except InvalidAccessToken:
            response.status = 400
            return CustomErrorResponse.INVALID_ACCESS_TOKEN
        except EventNotCreated as error:
            response.status = 400
            CustomErrorResponse.EVENT_NOT_CREATED['error']['message'] = 'Cannot create event'
            CustomErrorResponse.EVENT_NOT_CREATED['error']['message'] += '\n' + error.message
            return CustomErrorResponse.EVENT_NOT_CREATED
        except EventLocationNotCreated as error:
            response.status = 400
            CustomErrorResponse.EVENT_LOCATION_NOT_CREATED['error']['message'] = 'Unable to create venue for event'
            CustomErrorResponse.EVENT_LOCATION_NOT_CREATED['error']['message'] += '\n' + error.message
            return CustomErrorResponse.EVENT_LOCATION_NOT_CREATED
        except ConnectionError:
            response.status = 400
            return CustomErrorResponse.CONNECTION_TIMEOUT
        except SocialNetworkNotImplemented:
            response.status = 400
            return CustomErrorResponse.SOCIAL_NETWORK_NOT_IMPLEMENTED
        except:
            response.status = 400
            return CustomErrorResponse.UNKNOWN_ERROR

        return dict(status=True, msg='Event created successfully')

    def PUT(*args, **vars):
        return dict()

    def DELETE(*args, **kwargs):
        event_id = kwargs.get('event_id', '').strip()
        user = authenticate_user()
        if not user:
            response.status = 403
            return CustomErrorResponse.NOT_AUTHORIZED
        assert user is not None
        if not event_id:
            response.status = 400
            return CustomErrorResponse.MISSING_INPUT
        deleted = db(db.event.id == event_id,
                     db.event.userId == user.id).delete()
        return dict(deleted_record=deleted)

    return locals()


@request.restful()
def social_networks():
    """
    GET:
        1. get_social_networks: returns all social networks info
            url: /web/api/social_networks.json

        2. user_social_networks: returns all social networks for which belongs to.
            So basically we look into user_credentials table and we get all the records
            that match a certain userId
            url: /web/api/social_networks/user.json

        3. token_validity_info: returns token validity status for user's social networks.
            This essentially give us the information which social networks user is still
            connected to and which social networks user is not connected to (so that way
            we can show appropriate messages to the user e.g. tell him to re-authenticate).
            url: /web/api/social_networks/token_validity_info.json
    :return: json response
    """

    def GET(*args, **vars):
        user = authenticate_user()
        if not user:
            response.status = 401
            return CustomErrorResponse.NOT_AUTHORIZED
        assert user is not None

        def get_social_networks():
            social_networks = db((db.user_credentials.userId == user.id) &
                                 (db.user_credentials.socialNetworkId == db.social_network.id)). \
                select(db.social_network.id, db.social_network.name)
            return social_networks

        def get_and_update_auth_info():
            """
            Here we call validate_token() to check validity of access token
            If token is expired (meetup for now) we refresh the token by
            calling refresh_access_token() defined in TalentEventsAPI.py
            :return:
            """
            social_networks = get_social_networks()
            token_validity = dict()
            for social_network in social_networks:
                user_credential = db((db.user_credentials.userId == user.id) &
                                     (db.user_credentials.socialNetworkId == social_network.id)).select().first()
                if user_credential:
                    result = validate_and_refresh_access_token(user_credential)
                    valid_token_status = result[0] or result[1]
                else:
                    raise UserCredentialsNotFound
                token_validity[social_network.name] = dict(id=social_network.id,
                                                           auth_status=valid_token_status)
            return token_validity

        if len(args) > 0 and args[0].lower() == 'get_and_update_auth_info':
            return dict(get_and_update_auth_info=get_and_update_auth_info())

        return dict(social_networks=get_social_networks())

    return locals()


@request.restful()
def user_credentials():
    def GET(*args, **kwargs):
        print args, kwargs
        user_credential_id = None
        if args:
            user_credential_id = args[0]
        user = authenticate_user()
        if not user:
            response.status = 403
            return CustomErrorResponse.NOT_AUTHORIZED
        assert user is not None
        records = None
        if not user_credential_id:
            records = db(db.user_credentials.id == user_credential_id).select()
        return dict(data=records)

    def POST(*args, **kwargs):
        user = authenticate_user()
        if not user:
            response.status = 403
            return CustomErrorResponse.NOT_AUTHORIZED
        assert user is not None
        social_network_id = kwargs.get('socialNetworkId', "").strip()
        access_token = kwargs.get('accessToken', "").strip()
        member_id = kwargs.get('memberId', '').strip()
        web_hook = kwargs.get('webhook', '').strip()
        if not any([social_network_id, access_token, member_id,
                    web_hook]):
            response.status = 400
            return CustomErrorResponse.MISSING_INPUT
        user_credential_id = db.user_credentials.insert(
            userId=user.id,
            socialNetworkId=social_network_id,
            accessToken=access_token,
            memberId=member_id, webhook=web_hook)
        return dict(user_credential_id=user_credential_id)

    def DELETE(*args, **kwargs):
        user_credential_id = kwargs.get('user_credential_id', '').strip()
        user = authenticate_user()
        if not user:
            response.status = 403
            return CustomErrorResponse.NOT_AUTHORIZED
        assert user is not None
        if not user_credential_id:
            response.status = 400
            return CustomErrorResponse.MISSING_INPUT
        deleted = db(db.user_credentials.id == user_credential_id,
                     db.user_credentials.userId == user.id).delete()
        return dict(deleted_record=deleted)

    return locals()


@request.restful()
def users():
    def GET(*args, **kwargs):
        """ GET /web/api/users/:id

        Fetch user object with user's basic info.

        Takes an integer as user_id, assigned to args[0].
        The function will only accept an integer.
        Logged in user must be an admin.

        :return: A dictionary containing user's info from the database except
                 user's password, registration_key, and reset_password_key.
                 Not Found Error if user is not found.
        """
        authenticated_user = authenticate_user()
        if not authenticated_user:
            response.status = 401
            return CustomErrorResponse.NOT_AUTHORIZED
        assert authenticated_user is not None

        # Logged in user must be an admin
        if not is_current_user_admin(user_id=authenticated_user.id):
            response.status = 403
            return CustomErrorResponse.NOT_AUTHORIZED

        if not args:
            response.status = 400
            return CustomErrorResponse.MISSING_INPUT

        # Requested user's id must be an integer
        if not is_number(args[0]):
            response.status = 400
            return CustomErrorResponse.UNACCEPTABLE_INPUT_TYPE

        requested_user_id = int(args[0])
        requested_user = db.user(requested_user_id)
        if not requested_user:
            response.status = 404
            return CustomErrorResponse.USER_NOT_FOUND

        # Requested-user must be in the same domain as logged in user
        if requested_user.domainId != authenticated_user.domainId:
            response.status = 403
            return CustomErrorResponse.NOT_AUTHORIZED

        return {'user': {
            'id': requested_user.id,
            'domain_id': requested_user.get('domainId'),
            'email': requested_user.get('email'),
            'first_name': requested_user.get('firstName'),
            'last_name': requested_user.get('lastName'),
            'phone': requested_user.get('phone'),
            'registration_id': requested_user.get('registrationId'),
            'dice_user_id': requested_user.get('diceUserId')
        }}

    def POST(*args, **kwargs):
        """ POST /web/api/users
            input: {'users': [userObject1, userObject2, userObject3, ... ]}

        Creates one user object per request.

        Takes a JSON dict containing user's information; assigned to kwargs.
        Function only accepts JSON dict.
        JSON dict must contain user's first name, last name, and email.
        Logged in user must be an admin.
        If user is a getTalent admin, user can create a new domain.

        :return:    {'users': [{'id': user_id}, {'id': user_id}, ...]}
        """
        authenticated_user = authenticate_user()
        if not authenticated_user:
            response.status = 401
            return CustomErrorResponse.NOT_AUTHORIZED
        assert authenticated_user is not None

        # Logged in user must be an admin
        if not is_current_user_admin(user_id=authenticated_user.id):
            response.status = 403
            return CustomErrorResponse.NOT_AUTHORIZED

        # Parse the request body
        body_dict = parse_request_body()
        if body_dict.get('error'):
            return body_dict

        # Save user object(s)
        users = body_dict['users']

        # User object(s) must be in a list
        if not isinstance(users, list):
            response.status = 400
            return CustomErrorResponse.UNACCEPTABLE_INPUT_TYPE

        for user_dict in users:

            first_name = user_dict.get('first_name', "").strip()
            last_name = user_dict.get('last_name', "").strip()
            email = user_dict.get('email', "").strip()
            domain = get_domain_value(user=authenticated_user, domain=user_dict.get('domain'))

            if not first_name or not last_name or not email:
                response.status = 400
                return CustomErrorResponse.MISSING_INPUT

            if not is_valid_email(email=email):
                response.status = 400
                return CustomErrorResponse.UNACCEPTABLE_INPUT_TYPE

            # if user is a getTalent admin, they can create a new domain. See get_domain_value()
            if is_number(domain):
                domain_id = int(domain)
            else:
                domain_name = domain
                domain_id = get_or_create_domain(domain_name)

            if check_if_user_exists(email=email, domain_id=domain_id):
                response.status = 400
                return CustomErrorResponse.USER_ALREADY_REGISTERED

        user_ids = []  # Newly created user object's id(s) are appended to this list
        for user_dict in users:

            first_name = user_dict.get('first_name', "").strip()
            last_name = user_dict.get('last_name', "").strip()
            email = user_dict.get('email', "").strip()
            domain = get_domain_value(user=authenticated_user, domain=user_dict.get('domain'))
            is_admin = True if user_dict.get('is_admin') == '1' else False
            dice_user_id = user_dict.get('dice_user_id')

            # if user is a getTalent admin, they can create a new domain. See get_domain_value()
            if is_number(domain):
                domain_id = int(domain)
            else:
                domain_name = domain
                domain_id = get_or_create_domain(domain_name)

            resp_dict = create_user_for_company(first_name=first_name,
                                                last_name=last_name,
                                                email=email,
                                                domain_id=domain_id,
                                                is_admin=is_admin,
                                                dice_user_id=dice_user_id)
            user_ids.append(resp_dict)

        return {'users': [user_id_dict for user_id_dict in user_ids]}

    def DELETE(*args, **kwargs):
        """ DELETE /web/api/users/:id

        Function can delete one user per request.
        Function will remove user-object and user-attributes from db

        Only admin users can delete users
        Only getTalent admins can delete admin-users or getTalent-admin-users
        User will be prevented from deleting itself
        Last user in domain cannot be deleted
        All of user's data will be transferred to the admin of the requested-user's domain

        :return:    {'user' {'id': user_id}}
        """
        authenticated_user = authenticate_user()
        if not authenticated_user:
            response.status = 401
            return CustomErrorResponse.NOT_AUTHORIZED
        assert authenticated_user is not None

        # Logged in user must be an admin
        if not is_current_user_admin(user_id=authenticated_user.id):
            response.status = 403
            return CustomErrorResponse.NOT_AUTHORIZED

        if not args:
            response.status = 400
            return CustomErrorResponse.MISSING_INPUT

        # User id must be an integer
        if not is_number(args[0]):
            response.status = 400
            return CustomErrorResponse.UNACCEPTABLE_INPUT_TYPE

        # Save requested user's id
        user_id_to_delete = int(args[0])

        # Return 404 if requested user does not exist
        requested_user = db.user(user_id_to_delete)
        if not requested_user:
            response.status = 404
            return CustomErrorResponse.USER_NOT_FOUND

        # Get requested user's domain id
        user_domain_id_to_delete = domain_id_from_user_id(user_id=user_id_to_delete)

        # Only getTalent admin can delete admin users, i.e. Only Customer Manager can delete User Manager
        is_logged_in_user_a_gettalent_admin = is_current_user_gettalent_admin(user_id=authenticated_user.id)
        is_requested_user_admin = is_current_user_admin(user_id=user_id_to_delete)
        if not is_logged_in_user_a_gettalent_admin and is_requested_user_admin:
            response.status = 403
            return CustomErrorResponse.NOT_AUTHORIZED

        # Requested user must be in logged-in-user's domain. Only getTalent admins can update users in other domains
        if not is_logged_in_user_a_gettalent_admin:
            if user_domain_id_to_delete != authenticated_user.domainId:
                response.status = 403
                return CustomErrorResponse.NOT_AUTHORIZED

        # Prevent user from deleting itself
        if user_id_to_delete == authenticated_user.id:
            response.status = 403
            return CustomErrorResponse.DELETE_LOGGED_IN_USER_NOT_ALLOWED

        # Prevent user from deleting the last user in the domain
        # count < 3 accounts for: logged_in_user and at least one user in the logged_in_user's domain
        if db(db.user.domainId == authenticated_user.domainId).count() < 3:
            response.status = 403
            return CustomErrorResponse.DELETE_LAST_USER_IN_DOMAIN_NOT_ALLOWED

        # Assign requested-user's data to the admin of requested-user's domain
        requested_users_domain_admin = get_users_domain_admin(requested_user=requested_user)
        transfer_ownership_of_all_things_to_user(user_id=user_id_to_delete,
                                                 admin_user_id=requested_users_domain_admin.id)

        # Upload candidate documents belonging to the user
        upload_candidate_documents_of_user(user=authenticated_user)

        # Delete user
        db(db.user.id == user_id_to_delete).delete()

        # Delete user attributes
        db(db.user_attributes.userId == user_id_to_delete).delete()

        return {'user': {'id': user_id_to_delete}}

    def PUT(*args, **kwargs):
        """ PUT /web/api/users/:id

        Function updates requested user's information.

        Only admin users can update user's information.
        Prevents updating users in other domains.
        Only getTalent admins can update a user's domain_id.

        :return: {'user': {'id': user_id_to_update}}
        """
        authenticated_user = authenticate_user()
        if not authenticated_user:
            response.status = 401
            return CustomErrorResponse.NOT_AUTHORIZED
        assert authenticated_user is not None

        # Logged in user must be an admin
        if not is_current_user_admin(user_id=authenticated_user.id):
            response.status = 403
            return CustomErrorResponse.NOT_AUTHORIZED

        # Parse the request body
        body_dict = parse_request_body()
        if body_dict.get('error'):
            return body_dict

        if not args:
            response.status = 400
            return CustomErrorResponse.MISSING_INPUT

        # User id must be an integer
        if not is_number(args[0]):
            response.status = 400
            return CustomErrorResponse.UNACCEPTABLE_INPUT_TYPE

        user_id_to_update = int(args[0])
        first_name = body_dict.get('first_name')
        last_name = body_dict.get('last_name')
        email = body_dict.get('email')
        phone = body_dict.get('phone')

        # Return 403 if user does not exist
        if not db.user(user_id_to_update):
            response.status = 403
            return CustomErrorResponse.NOT_AUTHORIZED

        # Get requested user's domain_id
        user_domain_id_to_update = domain_id_from_user_id(user_id=user_id_to_update)

        # Check if logged in user is a getTalent admin
        is_gettalent_admin = is_current_user_gettalent_admin(user_id=authenticated_user.id)

        # Requested user must be in logged-in-user's domain. Only getTalent admins can update users in other domains
        if not is_gettalent_admin:
            if user_domain_id_to_update != authenticated_user.domainId:
                response.status = 403
                return CustomErrorResponse.NOT_AUTHORIZED

        if email:
            if not is_valid_email(email=email):
                response.status = 400
                return CustomErrorResponse.UNACCEPTABLE_INPUT_TYPE

        # Update user
        _update_user({
            'user_id': user_id_to_update,
            'firstName': first_name,
            'lastName': last_name,
            'email': email,
            'phone': phone
        })

        return {'user': {'id': user_id_to_update}}

    return locals()


@request.restful()
def candidates():
    def GET(*args, **kwargs):
        """
        Endpoint can do these operations:
            1. Fetch and return candidate object with candidate's basic info.

                Function can fetch a candidate via four methods:
                    I.   GET /web/api/candidates/:id
                         Takes an integer as candidate's unique id, assigned to args[0].
                         :return: A dictionary containing candidate's info.
                                 404 if candidate is not found.
                    OR
                    II.  GET /web/api/candidates/:email
                         Takes a vali email address, assigned to args[0].
                         :return: A dictionary containing candidate's info.
                                 404 if candidate is not found.
                    OR
                    III. GET /web/api/candidates?q=PHP&limit=100
                         Takes a search query.
                         :return: First 100 candidates matching 'PHP' search query;
                                  encapsulated in a "candidates" dict.
                                  Empty array if no matching candidate is found.
                    OR
                    IV.  GET /web/api/candidates
                         If no args or query is provided, function will return up to 15
                         most recently added cadidates. These candidates belong to the user
                         and the user's domain.

            2. Fetch candidates via SocialCV (OpenWeb) API.
                GET /web/api/candidates/open_web.json?email=johnterry@gmail.com.
                Queries the SocialCV API and returns a list of Candidate objects.
                :return: A list of Candidate objects.

            3. Fetch and return all EmailCampaignSend objects sent to a known candidate.
                GET /web/api/candidates/:candidate_id/email_campaigns/:email_campaign_id/email_campaign_sends
                - This requires an email_campaign_id & a candidate_id.
                - Email campaign must belong to the candidate & candidate must belong to the logged in user.

                :return: A list of EmailCampaignSend object(s).
                         404 status if no email campaign is found.
        """
        authenticated_user = authenticate_user()
        if not authenticated_user:
            response.status = 401
            return CustomErrorResponse.NOT_AUTHORIZED
        assert authenticated_user is not None

        if not args:
            # Assume we're doing a search (via CloudSearch)
            from TalentCloudSearch import search_candidates
            if not request.vars.sort_by:  # Default sort should be most recently addded
                request.vars.sort_by = "added_time-desc"
            search_candidates_result = search_candidates(domainId=authenticated_user.domainId,
                                                         vars=request.vars,
                                                         search_limit=int(request.vars.limit or 15),  # Can't send in a falsy limit, or it means 'no limit'
                                                         candidate_ids_only=True)
            candidate_ids = search_candidates_result['candidate_ids']
            return {'candidates': [fetch_candidate_info(candidate_id, fields=request.vars.fields or None) for candidate_id in candidate_ids]}

        elif args[0] == 'open_web':
            # OpenWeb Search (doesn't affect DB)
            logger.info("GET candidates: User %s performing OpenWeb search on email %s", authenticated_user.id, request.vars.email)
            from TalentDiceClient import query_socialcv, convert_dice_candidate_dict_to_gt_candidate_dict
            dice_candidate_dict = query_socialcv(request.vars.email)
            gt_candidate_dict = convert_dice_candidate_dict_to_gt_candidate_dict(dice_candidate_dict)
            return {'candidates': [gt_candidate_dict]}

        elif len(args) == 1:
            # Search via candidate ID or candidate email
            if not is_number(args[0]):
                # Arg is email
                email = args[0] if request.extension in ('json', 'xml', 'html') else request.raw_args
                try:
                    email = urllib.unquote(email).decode('utf8')  # In case email is URL-encoded, as it may be
                except Exception:
                    current.logger.info("GET candidate: Could not URL-decode email %s of user %s", email, authenticated_user.id)
                if is_valid_email(email):  # Find a candidate with existing email in the domain
                    candidate_email = db(
                        (db.candidate_email.address == email) &
                        (db.candidate_email.candidateId == db.candidate.id) &
                        (db.candidate.ownerUserId == db.user.id) &
                        (db.user.domainId == authenticated_user.domainId)
                    ).select(db.candidate_email.ALL).first()
                    if candidate_email:
                        candidate_id = candidate_email.candidateId
                    else:
                        response.status = 404
                        return CustomErrorResponse.CANDIDATE_NOT_FOUND
                else:
                    response.status = 400
                    return CustomErrorResponse.VALID_EMAIL_REQUIRED
            else:
                # Arg is candidate ID
                candidate_id = int(args[0])
                if not does_candidate_belong_to_user(user=authenticated_user, candidate_id=candidate_id):
                    response.status = 404
                    return CustomErrorResponse.CANDIDATE_NOT_FOUND

            return {'candidate': fetch_candidate_info(candidate_id)}

        elif len(args) == 4 and args[1] == 'email_campaigns' and args[3] == 'email_campaign_sends':
            # Retrieve email_campaign_sends which were sent to a known candidate
            email_campaign_id = args[2]
            candidate_id = args[0]

            # Both inputs must be integers
            if not is_number(email_campaign_id) or not is_number(candidate_id):
                response.status = 400
                return CustomErrorResponse.UNACCEPTABLE_INPUT_TYPE

            # Candidate must belong to user & email campaign must belong to user's domain
            if not does_candidate_belong_to_user(user=authenticated_user, candidate_id=candidate_id) or \
                    not does_email_campaign_belong_to_domain(user=authenticated_user):
                response.status = 403
                return CustomErrorResponse.NOT_AUTHORIZED

            email_campaign = db(db.email_campaign.id == email_campaign_id).select().first()

            # Get all email_campaign_send objects to the requested candidate
            from TalentEmailMarketing import retrieve_email_campaign_send
            email_campaign_send_objects = retrieve_email_campaign_send(email_campaign=email_campaign,
                                                                       candidate_id=candidate_id)
            return {'email_campaign_sends': email_campaign_send_objects}


        else:  # Unknown way of accessing endpoint
            response.status = 400
            return CustomErrorResponse.MISSING_INPUT

    def POST(*args, **kwargs):
        """
        POST /web/api/candidates
        input: {'candidates': [candidateObject1, candidateObject2, ...]}

        Creates new candidate(s).

        Takes a JSON dict containing:
            - a candidates key and a list of candidate-object(s) as values
        Function only accepts JSON dict.
        JSON dict must contain candidate's email address(s).

        :return: {'candidates': [{'id': candidate_id}, {'id': candidate_id}, ...]}
        """
        body_dict = None
        authenticated_user = None
        try:
            authenticated_user = authenticate_user()
            if not authenticated_user:
                response.status = 401
                return CustomErrorResponse.NOT_AUTHORIZED
            assert authenticated_user is not None

            # Parse the request body
            body_dict = parse_request_body()
            if body_dict.get('error'):
                return body_dict

            # Capture candidate object(s)
            candidates = body_dict.get('candidates')

            # Candidate object(s) must be in a list
            if not isinstance(candidates, list):
                response.status = 400
                return CustomErrorResponse.make_response_with_text(CustomErrorResponse.UNACCEPTABLE_INPUT_TYPE,
                                                                   "Unacceptable input: Candidate object(s) must be in a list")

            created_candidate_ids = []
            for candidate_dict in candidates:

                emails = [{'label': email.get('label'), 'address': email.get('address')}
                          for email in candidate_dict.get('emails')]
                if not any(emails):
                    response.status = 400
                    return CustomErrorResponse.VALID_EMAIL_REQUIRED

                if filter(lambda email: not is_valid_email(email['address']), emails):
                    response.status = 400
                    return CustomErrorResponse.VALID_EMAIL_REQUIRED

                phones = candidate_dict.get('phones')
                addresses = candidate_dict.get('addresses')
                educations = candidate_dict.get('education')
                military_services = candidate_dict.get('military_service')
                social_networks = candidate_dict.get('social_networks', [])
                custom_fields = candidate_dict.get('custom_fields', [])
                areas_of_interest = candidate_dict.get('areas_of_interest', [])

                # Prevent user from adding custom field(s) to other domain(s)
                custom_field_ids = [custom_field['id'] for custom_field in custom_fields]
                is_custom_field_authorized = db(
                    db.custom_field.id.belongs(custom_field_ids) &
                    (db.custom_field.domainId != authenticated_user.domainId)
                ).count() == 0
                if not is_custom_field_authorized:
                    response.status = 403
                    return CustomErrorResponse.make_response_with_text(CustomErrorResponse.NOT_AUTHORIZED, "Unauthorized custom field IDs")

                # Prevent user from adding area(s) of interest to other domain(s)
                area_of_interest_ids = [area_of_interest['id'] for area_of_interest in areas_of_interest]
                is_area_of_interest_authorized = db(
                    db.area_of_interest.id.belongs(area_of_interest_ids) &
                    (db.area_of_interest.domainId != authenticated_user.domainId)
                ).count() == 0
                if not is_area_of_interest_authorized:
                    response.status = 403
                    return CustomErrorResponse.make_response_with_text(CustomErrorResponse.NOT_AUTHORIZED, "Unauthorized area of interest IDs")

                country_id = country_code_or_name_to_id(addresses[0].get('country')) if addresses else 1
                if not country_id:
                    country_id = 1  # country_code_or_name_to_id returns None if no match

                resp_dict = create_candidate_from_params(
                    owner_user_id=authenticated_user.id,
                    formatted_name=candidate_dict.get('full_name'),
                    status_id=body_dict.get('status_id'),
                    email=emails[0].get('address'),
                    phone=[{'label': phone.get('label'), 'value': phone.get('value')} for phone in phones] if phones else None,
                    city=addresses[0].get('city') if addresses else None,
                    state=addresses[0].get('state') if addresses else None,
                    zip_code=addresses[0].get('zip_code') if addresses else None,
                    country_id=country_id,
                    university=educations[0].get('school_name') if educations else None,
                    university_start_year=educations[0].get('start_year') if educations else None,
                    university_start_month=educations[0].get('start_month') if educations else None,
                    graduation_year=educations[0].get('graduation_year') if educations else None,
                    graduation_month=educations[0].get('graduation_month') if educations else None,
                    military_branch=military_services[0].get('branch') if military_services else None,
                    military_status=military_services[0].get('status') if military_services else None,
                    military_grade=military_services[0].get('grade') if military_services else None,
                    military_to_date=military_services[0].get('to_date') if military_services else None,
                    area_of_interest_ids=[aoi_dict['id'] for aoi_dict in areas_of_interest] if areas_of_interest else None,
                    custom_fields_dict={custom_field["id"]: custom_field["value"] for custom_field in custom_fields} if custom_fields else None,
                    social_networks={social_network["id"]: social_network["url"] for social_network in social_networks} if social_networks else None,
                    candidate_skill_dicts=[{
                                               'description': skill.get('name'),
                                               'totalMonths': skill.get('months_used'),
                                               'lastUsed': skill.get("last_used_date") and dateutil.parser.parse(skill.get("last_used_date")),
                                           }
                                           for skill
                                           in body_dict.get('skills', [])],
                    work_preference=candidate_dict.get('work_preference'),
                    preferred_locations=candidate_dict.get('preferred_locations'),
                    dice_social_profile_id=body_dict.get('openweb_id'),
                    dice_profile_id=body_dict.get('dice_profile_id')
                )

                created_candidate_ids.append(resp_dict['candidate_id'])
        except Exception:
            current.logger.exception("POST /candidates received exception. Body: %s, User: %s", body_dict, authenticated_user)
            response.status = 500
            return CustomErrorResponse.UNKNOWN_ERROR

        return {'candidates': [{'id': candidate_id} for candidate_id in created_candidate_ids]}

    def DELETE(*args, **kwargs):
        """ DELETE /web/api/candidates
            {'candidates': [candidateObject1, candidateObject2, ...]}

        Function will delete candidate objects from CloudSearch and database.

        Only candidate's owner can delete candidate
        Candidate must be in the same domain as the logged in user

        :return: {'candidates': [{'id': candidate_id}, {'id': candidate_id}, ...]}
        """
        authenticated_user = authenticate_user()
        if not authenticated_user:
            response.status = 401
            return CustomErrorResponse.NOT_AUTHORIZED
        assert authenticated_user is not None

        # Prase the request body
        body_dict = parse_request_body()
        if body_dict.get('error'):
            return body_dict

        # Capture candidate objects
        candidates = body_dict['candidates']

        # Candidate object(s) must be in a list
        if not isinstance(candidates, list):
            response.status = 400
            return CustomErrorResponse.UNACCEPTABLE_INPUT_TYPE

        # Candidate id(s) required
        if filter(lambda candidate_dict: 'id' not in candidate_dict, candidates):
            response.status = 400
            return CustomErrorResponse.MISSING_INPUT

        # Save all candidate ids
        candidate_ids = [candidate_dict['id'] for candidate_dict in candidates]

        # Candidate id of each requested candidate must be an integer
        if filter(lambda candidate_id: not is_number(candidate_id), candidate_ids):
            response.status = 400
            return CustomErrorResponse.UNACCEPTABLE_INPUT_TYPE

        # User cannot delete candidate(s) outside of its domain & must be candidate's owner
        is_authorized = db(
            (db.candidate.id.belongs(candidate_ids)) &
            (db.candidate.ownerUserId == db.user.id) &
            (db.user.domainId != authenticated_user.domainId)
        ).count() == 0
        if not is_authorized:
            response.status = 403
            return CustomErrorResponse.NOT_AUTHORIZED

        # Delete candidates from CloudSearch & database
        _delete_candidates(candidate_ids=candidate_ids,
                           user_id=authenticated_user.id,
                           source_product_id=WEB_PRODUCT_ID)

        return {'candidates': [{'id': candidate_id} for candidate_id in candidate_ids]}

    def PUT(*args, **kwargs):
        """ PUT /web/api/candidates/:id

        Function updates candidate's fields.

        Only candidate's owner can edit candidate's fields
        Candidate and logged in user must belong to the same domain
        :return:    {'candidate': {'id': candidate_id}}
        """
        authenticated_user = authenticate_user()
        if not authenticated_user: #or not verify_user_scoped_role(authenticated_user.id, u'CAN_EDIT_CANDIDATE'):
            response.status = 401
            return CustomErrorResponse.NOT_AUTHORIZED
        assert authenticated_user is not None

        # Parse the request body
        body_dict = parse_request_body()
        if body_dict.get('error'):
            return body_dict

        # Request body cannot be empty
        if not any(body_dict):
            response.status = 400
            return CustomErrorResponse.MISSING_INPUT

        candidate = body_dict['candidate']

        # Candidate id is required
        candidate_id = candidate.get('id')
        if not candidate_id:
            response.status = 400
            return CustomErrorResponse.MISSING_INPUT

        # Candidate id must be an integer
        if not is_number(candidate_id):
            response.status = 400
            return CustomErrorResponse.UNACCEPTABLE_INPUT_TYPE

        # User cannot edit candidate outside of its domain & must be candidate's owner
        is_authorized = does_candidate_belong_to_user(user=authenticated_user,
                                                      candidate_id=candidate_id)
        if not is_authorized:
            response.status = 403
            return CustomErrorResponse.NOT_AUTHORIZED

        # All provided email addresses must be valid/formatted properly
        emails = candidate.get('emails')
        if emails:
            if filter(lambda email: not is_valid_email(email['address']), emails):
                response.status = 400
                return CustomErrorResponse.VALID_EMAIL_REQUIRED

        first_name = candidate.get('first_name', '')
        last_name = candidate.get('last_name', '')
        full_name = (first_name.capitalize() + ' ' + last_name.capitalize()).strip()
        phones = candidate.get('phones')
        addresses = candidate.get('addresses')
        educations = candidate.get('education')
        military_services = candidate.get('military_service')
        social_networks = candidate.get('social_networks', [])
        custom_fields = candidate.get('custom_fields', [])
        areas_of_interest = candidate.get('areas_of_interest', [])

        # Prevent user from updating custom field(s) in other domain(s)
        custom_field_ids = [custom_field['id'] for custom_field in custom_fields]
        is_custom_field_authorized = db(
            db.custom_field.id.belongs(custom_field_ids) &
            (db.custom_field.domainId != authenticated_user.domainId)
        ).count() == 0
        if not is_custom_field_authorized:
            response.status = 403
            return CustomErrorResponse.NOT_AUTHORIZED

        area_of_interest_ids = [area_of_interest['id'] for area_of_interest in areas_of_interest]
        is_area_of_interest_authorized = db(
            db.area_of_interest.id.belongs(area_of_interest_ids) &
            (db.area_of_interest.domainId != authenticated_user.domainId)
        ).count() == 0
        if not is_area_of_interest_authorized:
            response.status = 403
            return CustomErrorResponse.make_response_with_text(CustomErrorResponse.NOT_AUTHORIZED, "Unauthorized area of interest IDs")

        # Get education fields
        educations = body_dict.get('educations')
        university, university_start_date, university_end_date = None, None, None
        if educations:
            university = educations[0].get('school_name')
            import datetime
            university_start_date = educations[0].get('start_date') and dateutil.parser.parse(educations[0]['start_date'])
            university_end_date = educations[0].get('graduation_date') and dateutil.parser.parse(educations[0]['graduation_date'])

        resp_dict = create_candidate_from_params(
            owner_user_id=authenticated_user.id,
            candidate_id=candidate_id,
            formatted_name=full_name,
            status_id=body_dict.get('status_id'),
            email=emails[0].get('address') if emails else None,
            phone=[{'label': phone.get('label'), 'value': phone.get('value')} for phone in phones] if phones else None,
            city=addresses[0].get('city') if addresses else None,
            state=addresses[0].get('state') if addresses else None,
            zip_code=addresses[0].get('zip_code') if addresses else None,
            latitude=addresses[0].get('latitude') if addresses else None,
            longitude=addresses[0].get('longitude') if addresses else None,
            country_id=db(db.country.code == addresses[0].get('country')).select().first().id if addresses else 1,
            university=university,
            university_start_year=university_start_date and university_start_date.year,
            university_start_month=university_start_date and university_start_date.month,
            graduation_year=university_end_date and university_end_date.year,
            graduation_month=university_end_date and university_end_date.month,
            military_branch=military_services[0].get('branch') if military_services else None,
            military_status=military_services[0].get('status') if military_services else None,
            military_grade=military_services[0].get('grade') if military_services else None,
            military_to_date=military_services[0].get('to_date') if military_services else None,
            area_of_interest_ids=[aoi_dict['id'] for aoi_dict in areas_of_interest] if areas_of_interest else None,
            custom_fields_dict={custom_field["id"]: custom_field["value"] for custom_field in custom_fields} if custom_fields else None,
            social_networks={social_network["id"]: social_network["url"] for social_network in social_networks} if social_networks else None,
            candidate_skill_dicts=[{
                                       'description': skill.get('name'),
                                       'totalMonths': skill.get('months_used'),
                                       'lastUsed': skill.get("last_used_date") and dateutil.parser.parse(skill.get("last_used_date")),
                                   }
                                   for skill
                                   in body_dict.get('skills', [])],
            work_preference=body_dict.get('work_preferences'),
            preferred_locations=body_dict.get('preferred_locations'),
            dice_social_profile_id=body_dict.get('openweb_id'),
            dice_profile_id=body_dict.get('dice_profile_id'),
        )

        return {'candidate': {'id': resp_dict['candidate_id']}}

    return locals()


@request.restful()
def lists():
    def GET(*args, **kwargs):
        """ GET /web/api/lists/:id

        Fetch list object from the database.

        Takes an integer as smart_list_id, assigned to args[0].
        The function will only accept an integer.
        Logged in user can only fetch smart_lists within its domain.

        :return:    {'list': listObject}
        """
        authenticated_user = authenticate_user()
        if not authenticated_user:
            response.status = 401
            return CustomErrorResponse.NOT_AUTHORIZED
        assert authenticated_user is not None

        if not args:
            response.status = 400
            return CustomErrorResponse.MISSING_INPUT

        # list id must be an integer
        if not is_number(args[0]):
            response.status = 403
            return CustomErrorResponse.UNACCEPTABLE_INPUT_TYPE

        # Ensure authenticated_user accesses only its domain smart list
        smart_list_id = int(args[0])
        smart_list = db((db.smart_list.userId == authenticated_user.id) &
                        (db.smart_list.id == smart_list_id)
                        ).select().first()
        if not smart_list:
            response.status = 404
            return CustomErrorResponse.LIST_NOT_FOUND

        return {'list': {
            'id': smart_list.get('id'),
            'user_id': smart_list.get('userId'),
            'name': smart_list.get('name')
        }}

    def POST(*args, **kwargs):
        """ POST /web/api/lists
            input: {'lists': [listObject1, listObject2, ...]}

        Creates new smart_list object(s).

        Takes a JSON dict containing candidate ids and list name.
        Function only accepts JSON dict.
        Candidate ids must be integers.
        User cannot add smart_list(s) to other domains.

        :return: {'list': [{'id': list_id}, {'id': list_id}, ...]}
        """
        authenticated_user = authenticate_user()
        if not authenticated_user:
            response.status = 401
            return CustomErrorResponse.NOT_AUTHORIZED
        assert authenticated_user is not None

        # Parse the request body
        body_dict = parse_request_body()
        if body_dict.get('error'):
            return body_dict

        # Request body cannot be empty
        if not any(body_dict):
            response.status = 400
            return CustomErrorResponse.MISSING_INPUT

        lists = body_dict['lists']

        # Validate all requests before creating smart_list object(s)
        for list_dict in lists:

            candidate_ids = list_dict.get('candidate_ids')
            name = list_dict.get('name')

            # Candidate id(s) and list-name are required
            if not any(candidate_ids) or not name:
                response.status = 400
                return CustomErrorResponse.MISSING_INPUT

            # Candidate id(s) must be integer
            if filter(lambda candidate_id: not is_number(candidate_id), candidate_ids):
                response.status = 400
                return CustomErrorResponse.UNACCEPTABLE_INPUT_TYPE

            # Prevent user from adding smart list to other domains
            do_candidates_belong_to_user = db(
                db.candidate.id.belongs(candidate_ids) &
                (db.candidate.ownerUserId == db.user.id) &
                (db.user.domainId != authenticated_user.domainId)
            ).count() == 0
            if not do_candidates_belong_to_user:
                response.status = 403
                return CustomErrorResponse.NOT_AUTHORIZED

        result = []
        for list_dict in lists:
            candidate_ids = list_dict['candidate_ids']
            name = list_dict['name']
            resp_dict = create(user_id=authenticated_user.id, name=name,
                               candidate_ids=candidate_ids, queue_task=False)
            result.append(resp_dict.id)

        return {'lists': [{'id': list_id} for list_id in result]}

    def DELETE(*args, **kwargs):
        """ DELETE /web/api/lists/:id

        Function deletes one list per request.

        :return:    {'list': {'id': list_id}}
        """
        authenticated_user = authenticate_user()
        if not authenticated_user:
            response.status = 401
            return CustomErrorResponse.NOT_AUTHORIZED
        assert authenticated_user is not None

        if not args:
            response.status = 400
            return CustomErrorResponse.MISSING_INPUT

        # list_id is a required input
        list_id = args[0]
        if not list_id:
            response.status = 400
            return CustomErrorResponse.MISSING_INPUT

        # List id must be an integer
        if not is_number(list_id):
            response.status = 400
            return CustomErrorResponse.UNACCEPTABLE_INPUT_TYPE

        # Return 404 if requested list does not exist
        requested_list = db.smart_list(list_id)
        if not requested_list:
            response.status = 404
            return CustomErrorResponse.USER_NOT_FOUND

        # authenticated_user can delete only its domain list
        users_smart_lists = get(user=authenticated_user, get_candidate_count=False)
        if not users_smart_lists:
            response.status = 403
            return CustomErrorResponse.NOT_AUTHORIZED

        # list must belong to authenticated_user
        smart_list = db(
            (db.smart_list.userId == authenticated_user.id) &
            (db.smart_list.id == list_id)
        ).select().first()
        if not smart_list:
            response.status = 403
            return CustomErrorResponse.NOT_AUTHORIZED

        # Delete list
        db(db.smart_list.id == list_id).delete()

        return {'list': {'id': list_id}}

    return locals()


@request.restful()
def email_campaigns():
    def POST(*args, **kwargs):
        """ POST /web/api/email_campaigns
            input: {'email_campaign: [emailCampaignObject1, emailCampaignObject2, ...]}

        Creates new email_campaign object.

        Takes a JSON dict containing email_campaign data.
        JSON dict must contain 'email_from' and 'email_reply_to'.

        :return: {'email_campaigns': [{'id': email_campaign_id}, {'id': email_campaign_id}, ...]}
        """
        authenticated_user = authenticate_user()
        if not authenticated_user:
            response.status = 401
            return CustomErrorResponse.NOT_AUTHORIZED
        assert authenticated_user is not None

        # Parse the request body
        body_dict = parse_request_body()
        if body_dict.get('error'):
            return body_dict

        name = body_dict.get('email_campaign_name')
        email_subject = body_dict.get('email_subject')
        email_from = body_dict.get('email_from')
        email_reply_to = body_dict.get('email_reply_to')
        email_body_html = body_dict.get('email_body_html')
        email_body_text = body_dict.get('email_body_text')
        list_ids = body_dict.get('list_ids')
        email_client_id = body_dict.get('email_client_id')
        send_time = body_dict.get('send_time')

        # Ensure email_from and email_reply_to are provided
        if not email_from or not email_reply_to:
            response.status = 400
            return CustomErrorResponse.MISSING_INPUT

        if email_client_id:
            template_id = None
        else:
            template_id = body_dict.get('selected_template_id')

        if not send_time:
            send_time = request.now

        resp_dict = create_email_campaign(user_id=authenticated_user.id,
                                          email_campaign_name=name,
                                          email_subject=email_subject,
                                          email_from=email_from,
                                          email_reply_to=email_reply_to,
                                          email_body_html=email_body_html,
                                          email_body_text=email_body_text,
                                          list_ids=list_ids,
                                          email_client_id=email_client_id,
                                          template_id=template_id,
                                          send_time=send_time)

        return {'email_campaign': {'id': resp_dict['id']}}

    return locals()


# @request.restful()
# def domains():
#     def POST(*args, **kwargs):
#         """ POST /web/api/domains
#
#         :return:
#         """
#         authenticated_user = authenticate_user()
#         if not authenticated_user:
#             response.status = 401
#             return CustomErrorResponse.NOT_AUTHORIZED
#         assert authenticated_user is not None
#
#         return {}
#
#     return locals()


# @request.restful()
# def campaigns():
#     def POST(*args, **kwargs):
#         """ POST /web/api/campaigns/:id/send
#             {send_time: "2015-08-31 03:45:26", stop_time: "2015-08-31 05:45:26",
#             email_client_id: "zGU2qD7pydK5pWY5WnnMHAoJRD"}
#
#         Start sending an email campaign.
#
#         Takes a JSON dict containing send time and stop time.
#
#         :return: {'success': True}
#         """
#         authenticated_user = authenticate_user()
#         if not authenticated_user:
#             response.status = 401
#             return json.dumps(CustomErrorResponse.NOT_AUTHORIZED)
#         assert authenticated_user is not None
#
#         if len(args) == 2 and args[1] == 'send':
#             campaign_id = args[0]
#         else:
#             response.status = 400
#             return json.dumps(CustomErrorResponse.MISSING_INPUT)
#
#         # Parse the request body
#         body_dict = parse_request_body()
#         if body_dict.get('error'):
#             return json.dumps(body_dict)
#
#         send_time = body_dict.get('send_time')
#         stop_time = body_dict.get('stop_time')
#         email_client_id = body_dict.get('email_client_id')
#
#         if not campaign_id or not send_time:
#             response.status = 400
#             return json.dumps(CustomErrorResponse.MISSING_INPUT)
#
#         campaign = db.email_campaign(campaign_id)
#         try:
#             send_time = datetime.strptime(send_time, "%d-%m-%Y %H:%M:%S")
#             stop_time = datetime.strptime(stop_time, "%d-%m-%Y %H:%M:%S") if stop_time else stop_time
#         except Exception as e:
#             response.status = 400
#             return json.dumps(CustomErrorResponse.MISSING_INPUT)
#
#         if not campaign:
#             response.status = 400
#             return json.dumps(CustomErrorResponse.EMAIL_CAMPAIGN_NOT_FOUND)
#
#         candidates = get_email_campaign_candidate_ids_and_emails(campaign, authenticated_user)
#
#         if len(candidates) == 0:
#             response.status = 400
#             return json.dumps(CustomErrorResponse.MISSING_INPUT)
#
#         # Create the email_campaign_blast for this blast
#         blast_datetime = request.now
#         email_campaign_blast_id = db.email_campaign_blast.insert(emailCampaignId=campaign.id,
#                                                                  sentTime=blast_datetime)
#         blast_params = dict(sends=0, bounces=0)
#
#         for candidate, candidate_address in candidates:
#             new_html, new_text = send_campaign_emails_to_candidate(user=authenticated_user,
#                                                                    campaign=campaign,
#                                                                    candidate=candidate,
#                                                                    candidate_address=candidate_address,
#                                                                    email_client_id=email_client_id,
#                                                                    email_campaign_blast_id=email_campaign_blast_id,
#                                                                    blast_datetime=blast_datetime,
#                                                                    blast_params=blast_params)
#             ## @TODO checking if we have to send back all list of candidates converted htmls
#             return json.dumps({'new_html': new_html, 'new_text': new_text, 'campaign': campaign.name})
#
#         return json.dumps({'send_time': send_time.strftime("%d-%m-%Y %H:%M:%S")})
#
#     return locals()
