import base64
from CustomErrors import CustomErrorResponse


def login():
    logger.debug("cas/login: Received request. Request env: %s", request.env)
    email = ""
    try:
        if request.vars.email and request.vars.password:
            email, password = request.vars.email, request.vars.password
        else:
            basic_auth_str = request.env.http_authorization  # Basic <base64 encoded str>
            if not basic_auth_str:
                response.status = 401
                return {'error': {'message': 'Missing HTTP basic auth header'}}
            try:
                base64_encoded_username_password = basic_auth_str.split(' ')[1]
                email, password = base64.b64decode(base64_encoded_username_password).split(':')
            except Exception as e:
                response.status = 400
                return {'error': {'message': 'Invalid HTTP basic auth header', 'exception': str(e)}}

        if not auth.login_bare(email, password):
            response.status = 403
            return CustomErrorResponse.NOT_AUTHORIZED

        user = db(db.user.email == email).select().first()

        # Get Bearer Token from Talent AuthService
        import requests
        params = dict(grant_type="password", username=email, password=password)
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

        # Make new entry in auth_cas table
        web_auth_cas = db(db.web_auth_cas.user_id == user.id).select().first()
        if not web_auth_cas:
            ticket = "ST-" + web2py_uuid()
            db.web_auth_cas.update_or_insert(db.web_auth_cas.user_id == user.id, user_id=user.id, service='cas_login', ticket=ticket, renew='T')
        else:
            ticket = web_auth_cas.ticket

        return dict(user_id=user.id, ticket=ticket)
    except Exception as e:
        logger.exception("cas/login uncaught exception with email %s", email)
        response.status = 500
        return {'error': {'message': str(e)}}


def logout():
    from TalentUsers import authenticate_user
    user = authenticate_user()
    if user is None:
        response.status = 400
        return {'error': {'message': 'User not logged in'}}
    assert user is not None
    # user = db(db.user.email == auth.user.email).select().first()
    web_aut_cas_row = db(db.web_auth_cas.user_id == user.id).select().first()
    web_aut_cas_row.delete_record()
    auth.logout()
    return {'user_id': user.id}
