# -*- coding: utf-8 -*-

import os

from TalentJobAlerts import *
from TalentAreasOfInterest import get_area_of_interest_id_to_sub_areas_of_interest
from TalentCloudSearch import search_candidates
from TalentEmailMarketing import get_subscription_preference


def test_job_alert():
    from gluon.storage import Storage

    """
    Retrieve job alert based on:
        - Areas Of Interest
        - City, State
    """

    domainId = 104
    userId = 251

    areas_of_interest = db((db.area_of_interest.domainId == domainId) & (db.area_of_interest.parentId == None)).select()

    if not request.vars.areaOfInterest or not request.vars.state:
        return dict(areas_of_interest=areas_of_interest)

    candidate_id = db.candidate.insert(firstName='test', ownerUserId=userId)
    candidate = db.candidate[candidate_id]

    if type(request.vars.areaOfInterest) == list:
        for aoi in request.vars.areaOfInterest:
            if len(aoi):
                db.candidate_area_of_interest.insert(candidateId=candidate_id, areaOfInterestId=aoi)
    else:
        aoi = request.vars.areaOfInterest
        db.candidate_area_of_interest.insert(candidateId=candidate_id, areaOfInterestId=aoi)

    candidate_address_id = db.candidate_address.insert(candidateId=candidate_id, state=request.vars.state)

    if request.vars.jobFrequency:
        sub_custom_field = db(
            (db.custom_field.domainId == domainId) & (db.custom_field.name == 'Subscription Preference')).select(
            db.custom_field.id).first()
        db.candidate_custom_field.insert(candidateId=candidate_id, customFieldId=sub_custom_field.id,
                                         value=request.vars.jobFrequency)

    campaign_fields = get_email_campaign_fields(candidate.id)

    db.rollback()

    return campaign_fields['emailBodyHtml']


@auth.requires_login()
def delete():
    candidate_ids = request.vars.get('ids[]') or request.vars.get('ids') or request.vars.get('id')
    if type(candidate_ids) == str:
        candidate_ids = [candidate_ids]

    candidate_ids = [int(candidate_id) for candidate_id in candidate_ids]  # convert to int

    # Make sure there are no candidates that belong to users in other domains
    is_authorized = db(
        (db.candidate.id.belongs(candidate_ids)) &
        (db.candidate.ownerUserId == db.user.id) &
        (db.user.domainId != auth.user.domainId)
    ).count() == 0
    if not is_authorized:
        return dict(message='Unauthorized')

    _delete_candidates(candidate_ids, user_id=auth.user.id, source_product_id=WEB_PRODUCT_ID)
    return dict(message='%s candidates deleted!' % len(candidate_ids))


@auth.requires_login()
def delete_with_filters():
    """
    Delete talents with filters
    By doing this, it cures having to specify all candidate ids to delete and leading to crash, when deleting large number of candidates

    :param  filters             Filters selected.
    :param  selected_ids        IDs of candidates selected.
    :param  all_selected        If TRUE, all candidates are selected, retrieved by given filters
    :param  deselected_ids      IDS of candidates deselected, given all candidates by filters provided are selected,
                                that is, deleting (ALL candidates - DESELECTED candidates)

    :return:
    """
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
        return dict(message="Nothing to delete")

    candidate_ids = [int(candidate_id) for candidate_id in candidate_ids]  # convert to int

    # Make sure there are no candidates that belong to users in other domains
    is_authorized = db(
        (db.candidate.id.belongs(candidate_ids)) &
        (db.candidate.ownerUserId == db.user.id) &
        (db.user.domainId != auth.user.domainId)
    ).count() == 0
    if not is_authorized:
        response.status = 400
        return dict(message='Unauthorized')

    _delete_candidates(candidate_ids, user_id=auth.user.id, source_product_id=WEB_PRODUCT_ID)
    return dict(message='%s candidates deleted!' % len(candidate_ids))


# Pass in a table (array of arrays) with jQuery
@auth.requires_login()
def import_from_table():
    """
    Inputs:
    filepicker_key, S3 key of spreadsheet to import
    header_row_json, JSON array whose values are "tablename.columnname"
    source_id (optional), the source_id

    Downloads spreadsheet from S3 and converts into table format. If the table has more than 100 rows, will use scheduler and
    email user when completed. Otherwise, will return in same request.

    :return:
    """
    # set_get_started_action(auth.user, GET_STARTED_ACTIONS['IMPORT_FROM_SPREADSHEET'])

    import json

    user_id = auth.user.id
    header_row = json.loads(request.vars.header_row_json) if request.vars.header_row_json else None
    filepicker_key = request.vars.filepicker_key
    if not user_id or not header_row or not filepicker_key:
        response.status_code = 400
        return {'error': {'message': 'Missing required input(s)'}}
    source_id = request.vars.source_id

    # table_vars = dict()
    # for key, value in request.vars.iteritems():
    #     if 'table[' in key:
    #         table_vars[key] = value

    # table = [table_vars['table[%s][]' % i] for i in range(len(table_vars))]
    logger.info("candidate/import_from_table: Converting spreadsheet (key=%s) into table", filepicker_key)
    import TalentS3
    filepicker_bucket, conn = TalentS3.get_s3_filepicker_bucket_and_conn()
    file_obj = TalentS3.download_file(filepicker_bucket, filepicker_key)

    # csv_filename = session.csv_filename
    # csv_file = open_file(csv_filename)
    csv_table = _convert_spreadsheet_to_table(file_obj, filepicker_key)
    file_obj.seek(0)

    # First row in table is headers: their values are "tablename.columnname"
    # header_row, table = table[0], csv_table or []

    do_email_user_upon_completion = len(csv_table) > 500

    from TalentS3 import upload_to_s3
    url, key = upload_to_s3(file_obj.read(), folder_path="CSVResumes", name=filepicker_key, public=False)
    logger.info("import_from_table: Uploaded CSV of user ID %s to %s", user_id, url)

    import_from_csv_kwargs = dict(header_row=header_row,
                                  csv_filename=filepicker_key,
                                  source_id=source_id,
                                  user_id=user_id,
                                  do_email_user_upon_completion=do_email_user_upon_completion)
    
    if do_email_user_upon_completion:
        from TalentScheduler import queue_task
        queue_task('import_from_csv',
                   function_vars=import_from_csv_kwargs,
                   task_name='import_from_csv')

        return dict(count=len(csv_table), status='pending')
    else:
        return import_from_csv(**import_from_csv_kwargs)


def prefs():
    if not URL.verify(request, hmac_key=HMAC_KEY) and not IS_DEV:
        raise HTTP(403, "Not authorized")

    candidate_id = int(request.args(0))

    if not candidate_id:
        raise HTTP(403, "Not authorized")

    candidate = db.candidate(candidate_id)

    if not candidate:
        logger.warn("Tried accessing prefs for nonexistent candidate %s", candidate_id)
        raise HTTP(404, "Not found")

    user = db(db.user.id == candidate.ownerUserId).select().first()
    domain_id = user.domainId

    if request.env.request_method == 'POST':

        if request.post_vars.frequency_id:
            request.post_vars.frequency_id = int(request.post_vars.frequency_id)
        if request.post_vars.job_alert_frequency_id:
            request.post_vars.job_alert_frequency_id = int(request.post_vars.job_alert_frequency_id)

        candidate_subscription_preference = get_subscription_preference(candidate_id)
        change_subscription_preference = False
        new_frequency_id = None
        if is_kaiser_domain(domain_id):
            """
            For Kaiser, if they set either the normal or Job Alert frequency to -1, set their frequencyId to NULL (Never).
            Otherwise, set the frequencyId to whatever their Job Alert frequency is set to (Daily, Weekly, Monthly).
            """
            if request.post_vars.frequency_id == -1 or request.post_vars.job_alert_frequency_id == -1:
                change_subscription_preference = True
            elif request.post_vars.job_alert_frequency_id:
                change_subscription_preference = True
                new_frequency_id = int(request.post_vars.job_alert_frequency_id)
        else:
            if request.post_vars.frequency_id == -1:
                change_subscription_preference = True
            elif request.post_vars.frequency_id:
                change_subscription_preference = True
                new_frequency_id = 7  # TODO we should actually delete the candidate_subscription_preference in this case (or not create it, if it doesn't exist), because the next time get_subscription_preference is run for this candidate, it will delete it anyway.

        if change_subscription_preference:
            if candidate_subscription_preference:
                candidate_subscription_preference.update_record(frequencyId=new_frequency_id)
            else:
                db.candidate_subscription_preference.insert(candidateId=candidate_id, frequencyId=new_frequency_id)

        # Area of Interest tags and Location tags (for Kaiser)
        db(db.candidate_area_of_interest.candidateId == candidate_id).delete()  # Delete all candidate areas of interest and recreate them
        area_of_interest_ids = get_aoi_ids_from_aoi_tags(user, request.post_vars.interestTags)

        custom_fields_dict = dict()
        if is_kaiser_domain(domain_id):
            # Remove existing City of Interest & State of Interest CFs for the candidate, and add in the new ones
            kaiser_domain_id = get_domain_id_for('kaiser')
            city_of_interest_cf = db(db.custom_field.name == 'City of Interest')(db.custom_field.domainId == kaiser_domain_id).select().first()
            state_of_interest_cf = db(db.custom_field.name == 'State of Interest')(db.custom_field.domainId == kaiser_domain_id).select().first()
            db(db.candidate_custom_field.customFieldId == city_of_interest_cf.id)(db.candidate_custom_field.candidateId == candidate_id).delete()
            db(db.candidate_custom_field.customFieldId == state_of_interest_cf.id)(db.candidate_custom_field.candidateId == candidate_id).delete()
            add_city_and_state_ofhh_interest_to_custom_fields_dict(request.post_vars.locationOfInterestTags, custom_fields_dict, candidate_id, user)

        # Create/update candidate city & state
        # If you're here and realize that Kaiser has separate custom fields for City of Interest and State of Interest, and that those should be updated instead, just shut the fuck up. They don't need to know.
        candidate_address = db(db.candidate_address.candidateId == candidate_id).select().first()
        if candidate_address:
            candidate_address.update_record(city=request.vars.candidate_city, state=request.vars.candidate_state)
        else:
            db.candidate_address.insert(candidateId=candidate_id, city=request.vars.candidate_city, state=request.vars.candidate_state)

        # Upload to CloudSearch
        from TalentCloudSearch import upload_candidate_documents
        upload_candidate_documents(candidate_id)

        create_candidate_from_params(user.id,
                                     candidate.id,
                                     area_of_interest_ids=area_of_interest_ids,
                                     custom_fields_dict=custom_fields_dict,
                                     military_branch=request.vars.militaryBranch,  # Candidate military info
                                     military_status=request.vars.militaryStatus,
                                     military_grade=request.vars.militaryGrade,
                                     military_to_date=format_military_to_date(request.vars.militaryToDate))

        return response.json(dict(status=1))
    else:
        # Get all candidate AOIs
        candidate_areas_of_interest_dicts = db(db.candidate_area_of_interest.candidateId == candidate_id).select(
            db.area_of_interest.id,
            db.area_of_interest.description,
            left=db.candidate_area_of_interest.on(db.candidate_area_of_interest.areaOfInterestId == db.area_of_interest.id)
        ).as_list()
        all_areas_of_interest = db(db.area_of_interest.domainId == domain_id).select().as_list()
        candidate_areas_of_interest = [row['description'] for row in candidate_areas_of_interest_dicts]

        # Get candidate's subscription preferences
        candidate_subscription_preference = get_subscription_preference(candidate_id)

        response.title = 'Change your email preferences'

        return dict(areas_of_interest=all_areas_of_interest,
                    area_of_interest_id_to_sub_areas_of_interest=get_area_of_interest_id_to_sub_areas_of_interest(domain_id),
                    candidate_areas_of_interest=candidate_areas_of_interest,
                    candidate_areas_of_interest_dicts=candidate_areas_of_interest_dicts,
                    candidate_subscription_preference=candidate_subscription_preference,
                    domain_id=domain_id,
                    candidate_id=candidate_id)


def basic_plus():
    return dict()


def full():
    return dict()


def upload():
    import time

    time.sleep(3)
    #filename = request.vars.files.filename
    #size = len(request.vars.files.file.read())

    return response.json({
        'files': [
            {
                'name': 'dd',
                'size': 123,
            }
        ]
    })
