# -*- coding: utf-8 -*-

import TalentSmartListAPI
from TalentCloudSearch import search_candidates


@auth.requires_login()
# TODO: cannot edit smartlists of campaigns that have been sent!!
# TODO: implement deleting smartlists of unsent campaigns, not just setting isHidden
def delete():
    from CustomErrors import CustomErrorResponse
    # Make sure list owner is current user, then delete
    smart_list = db.smart_list(request.vars.id)
    if not smart_list:
        response.status = 404
        return dict(message="No list found")
    smart_list_owner_id = smart_list.userId
    # Check the current user is belongs to admin group
    from TalentUsers import is_current_user_admin, user_from_id
    is_user_admin = is_current_user_admin(auth.user.id)
    # Get the domain id of current user and smart_list owner
    user_row = user_from_id(smart_list_owner_id)
    smart_list_domain_id = user_row.domainId
    if smart_list_owner_id == auth.user.id or (is_user_admin and smart_list_domain_id == auth.user.domainId):
        TalentSmartListAPI.delete(smart_list)
        return dict(message="List %s has been deleted" % smart_list.name)
    else:
        response.status = 401
        return CustomErrorResponse.NOT_AUTHORIZED


def count():
    try:
        isinstance(int(request.vars.id), int)
        is_single = True
    except:
        is_single = False

    list_count = 0
    if is_single:
        list_count = TalentSmartListAPI.get_candidate_count(request.vars.id, domain_id=request.vars.domain, duration=900)
    else:
        ids = request.vars.id.split(',')
        for smartlist_id in ids:
            list_count += TalentSmartListAPI.get_candidate_count(smartlist_id, domain_id=request.vars.domain, duration=900)

    return dict({'count': list_count, 'smartListId': request.vars.id})


# If id not provided, creates
@auth.requires_login()
def create_or_update():
    response.generic_patterns = ['*.json', '*.html']
    name = request.vars.smart_list_name
    existing_name = db((db.smart_list.userId == db.user.id) & (db.user.domainId == auth.user.domainId)
                       & (db.smart_list.name == name)).select(db.smart_list.name).first()
    if existing_name:
        from CustomErrors import CustomErrorResponse
        response.status = 400
        return CustomErrorResponse.DUPLICATE_LIST_NAME
    id = request.vars.id
    smartlists = TalentSmartListAPI.get(auth.user, order=False, get_candidate_count=False)
    if id:
        smart_list = smartlists.find(lambda row: row.id == id).first()
        if not smart_list:
            return dict(message='No list found')
        if not smart_list.userId == auth.user.id:
            return dict(message='Permission denied')
        TalentSmartListAPI.update(smart_list, new_search_params_dict=request.vars, new_smart_list_name=request.vars.smart_list_name)
    else:  # Create new smartlist or list
        if request.vars.is_smartlist:
            smart_list = TalentSmartListAPI.create_from_vars(auth.user_id, name=request.vars.smart_list_name or "None",
                                                             vars=request.vars)
        elif request.vars.candidate_ids:
            candidate_ids = [int(candidate_id) for candidate_id in request.vars.candidate_ids.split(',')]
            smart_list = TalentSmartListAPI.create(auth.user.id, name=request.vars.smart_list_name, search_params_dict=None,
                                                   candidate_ids=candidate_ids)
        else:
            return dict()

    return dict(
        id=smart_list.id,
        candidate_count=smart_list.candidateCount,
        search_params_json=smart_list.searchParams,
        date_created=readable_datetime(smart_list.addedTime)
    )


@auth.requires_login()
def create():
    """
    Create a smartlist or dumblist
    When creating dumblist, the candidate ids can be provided just with selected_ids or filters with deselected_ids
    By doing this, you don't have to specify all candidate ids, when creating a list with large number of candidates


    :param  list_name           name of list
    :param  is_smartlist        If TRUE, create a smartlist, else create a dumb list
    :param  filters             Filters selected. Used when creating smartlist and creating dumb list with deselected candidate ids
    :param  selected_ids        IDs of candidates selected. It is specified when creating a dumb list
    :param  all_selected        If TRUE, all candidates are selected, retrieved by given filters
    :param  deselected_ids      IDS of candidates deselected, given all candidates by filters provided are selected,
                                that is, creating a list with (ALL candidates - DESELECTED candidates)

    :return:
    """
    response.generic_patterns = ['*.json', '*.html']

    if request.vars.is_smartlist:
        talent_list = TalentSmartListAPI.create_from_vars(auth.user_id,
                                                          name=request.vars.list_name,
                                                          vars=request.vars.filters)
    else:
        if request.vars.all_selected:
            # retrieve all candidates by using filters provided
            search_results = search_candidates(auth.user.domainId,
                                               request.vars.filters,
                                               search_limit = 0,
                                               candidate_ids_only = True)
            candidate_ids = search_results['candidate_ids']

            # remove deselected candidates
            if request.vars.deselected_ids:
                candidate_ids = list(set(candidate_ids) - set(request.vars.deselected_ids))
        else:
            candidate_ids = request.vars.selected_ids

        if not candidate_ids:
            response.status = 400
            return dict(message="No candidates selected")

        candidate_ids = [int(candidate_id) for candidate_id in candidate_ids]
        talent_list = TalentSmartListAPI.create(auth.user.id,
                                               name=request.vars.list_name,
                                               search_params_dict=None,
                                               candidate_ids=candidate_ids)

    return dict(
        id=talent_list.id,
        candidate_count=talent_list.candidateCount,
        search_params_json=talent_list.searchParams,
        date_created=readable_datetime(talent_list.addedTime)
    )