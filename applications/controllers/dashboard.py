# -*- coding: utf-8 -*-

import simplejson


# Show Dashboard
@auth.requires_login()
def index():
    from TalentUsers import is_current_user_admin
    response.title = "Dashboard"

    domain_id = auth.user.domainId

    # Get all owners (users) in current user's domain
    owners = db(db.user.domainId == domain_id).select()
    sources = db(db.candidate_source.domainId == auth.user.domainId).select()

    # Dashboard stats
    stats_json = simplejson.dumps(get_dashboard_stats(current_user=auth.user))

    # Show/Hide Generate Report button
    domain_settings_dict = get_domain_settings_dict(db.domain(domain_id))
    show_generate_report = 'generateReport' in get_hidden_fields_from_domain_settings_dict('dashboard',
                                                                                           domain_settings_dict)
    layout_mode = get_hidden_fields_from_domain_settings_dict('layoutMode', domain_settings_dict)
    show_graph_by_status = 'graphByStatus' in get_hidden_fields_from_domain_settings_dict('dashboard',
                                                                                          domain_settings_dict)
    show_graph_by_source = 'graphBySource' in get_hidden_fields_from_domain_settings_dict('dashboard',
                                                                                          domain_settings_dict)
    show_graph_by_owner = 'graphByOwner' in get_hidden_fields_from_domain_settings_dict('dashboard',
                                                                                        domain_settings_dict)
    show_graph_over_time = 'graphOverTime' in get_hidden_fields_from_domain_settings_dict('dashboard',
                                                                                          domain_settings_dict)
    show_graph_areas_of_interest = 'graphAreasOfInterest' in get_hidden_fields_from_domain_settings_dict('dashboard',
                                                                                                         domain_settings_dict)
    return dict(
        owners=owners,
        sources=sources,
        stats_json=stats_json,
        is_current_user_admin=is_current_user_admin(),
        layout_mode=layout_mode,
        show_generate_report_button=show_generate_report,
        show_graph_by_status=show_graph_by_status,
        show_graph_by_source=show_graph_by_source,
        show_graph_by_owner=show_graph_by_owner,
        show_graph_over_time=show_graph_over_time,
        show_graph_areas_of_interest=show_graph_areas_of_interest
    )


@auth.requires_login()
def create_source_ajax():
    data = create_source(auth.user.domainId, request.vars['description'])
    return response.json(data)


@auth.requires_login()
def users_in_domain():
    """ Inputs: None
    """
    domain_id = db((db.domain.id == db.user.domainId) & (db.user.id == auth.user.id)).select(db.domain.id).first()
    rows = db(db.user.domainId == domain_id).select(db.user.id, db.user.email)
    output = []
    for row in rows:
        output.append([row.id, row.email])
    return response.json(output)


@auth.requires_login()
def stats():
    """ Inputs:
    start_timestamp (seconds) - optional
    end_timestamp - optional
    graph_type: candidate (default)
    filter_type: over_time (default), by_owner, by_status [candidate only]
    user_id (optional) - if not given, shows all users
    """

    inputs = get_stats_inputs(request.vars)
    inputs['current_user'] = auth.user
    output = get_dashboard_stats(**inputs)
    return response.json(output)


def help():
    v = request.vars['v']

    if not v:
        return response.stream(
            "%sstatic/help/User_Guide_kaiser.pdf" % request.folder if is_kaiser_domain(auth.user.domainId) else "%sstatic/help/User_Guide.pdf" % request.folder,
            chunk_size=10 ** 5)
    elif v == 'quick-start':
        return response.stream(
            "%sstatic/help/Quick_Start_User_Guide_kaiser.pdf" % request.folder if is_kaiser_domain(auth.user.domainId) else "%sstatic/help/Quick_Start_User_Guide.pdf" % request.folder,
            chunk_size=10 ** 5)

