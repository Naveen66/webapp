# -*- coding: utf-8 -*-

"""

Be sure to set routes.py on_error codes to 500 ONLY

In the apache 443 virtual host settings:
WSGIPassAuthorization On

"""

import os


def file_test():
    if request.vars.image is not None:
        return len(request.vars.image.file.read())
    else:
        return 'No file "image" sent'


# /web/mobile_api/email_reset_password.json?email=
def email_reset_password():
    email = request.vars.email
    user = db(db.user.email == email).select().first()
    if not user:
        return dict(user_id=False, email_sent=False)

    email_sent = auth.email_reset_password(user)

    return dict(user_id=user.id, email_sent=email_sent)


@auth.requires_basic_login()
def crud():
    from gluon.tools import Crud

    crud = Crud(db)

    table = request.args(0)
    operation = request.args(1)
    record_id = request.args(2)

    request.vars._formname = table
    request.vars.id = record_id
    request.post_vars = request.vars

    """
    For update/delete calls, validate user ownership of the records
    """

    if operation == 'read':
        if table == 'candidate_rating':
            #TODO: dont use request vars directly
            data = db((db.candidate_rating.candidateId == request.vars.candidateId) & (
            db.candidate_rating.ratingTagId == request.vars.ratingTagId)).select().first().as_dict()
        else:
            data = dict(**crud.read(table, record_id))
        return data

    if operation == 'create':
        #temporary for testing
        form = SQLFORM(db[table], fields=form_fields(table, request))
        if form.process(session=None, formname=table).accepted:
            result = {'errors': {}}
        else:
            result = {'errors': form.errors}

    if operation == 'update':
        if table == 'candidate_rating':
            #TODO: fix later
            record = db[table]((db.candidate_rating.candidateId == request.vars.candidateId) & (
            db.candidate_rating.ratingTagId == request.vars.ratingTagId))
        else:
            record = db[table](record_id)
        form = SQLFORM(db[table], record=record, fields=form_fields(table, request))

        if form.process(session=None, formname=table).accepted:
            result = {'errors': {}}
        else:
            result = {'errors': form.errors}

    if operation == 'delete':
        record = db[table](record_id)

        deletable = table not in ("candidate", "candidate_rating")  # candidate_rating is never deleted, only set to 0
        if deletable and record:
            db(db[table].id == record.id).delete()
            result = {'errors': {}}
        else:
            result = {'errors': {'record': "Can't delete this record."}}

    return dict(**result)


@auth.requires_basic_login()
def search():
    from TalentCloudSearch import search_candidates
    query = request.vars.query or ''
    num_results = int(request.vars.num_results) if request.vars.num_results else 300
    results = search_candidates(domainId=auth.user.domainId, vars=query, search_limit=num_results)
    return results


@auth.requires_basic_login()
def process_resume():
    from ResumeParsing import parse_resume

    results = parse_resume(
        user_id=auth.user.id,
        file_obj=request.vars.image.file,
        filename_str=os.path.basename(request.vars.image.filename),
        source_id=request.vars.candidateSourceId,
    )

    candidate_id = results.get('candidate_id')

    if candidate_id:
        candidate = db(db.candidate.id == candidate_id).select(db.candidate.firstName, db.candidate.lastName).first()
        results['firstName'] = candidate.firstName
        results['lastName'] = candidate.lastName
    else:
        request.vars.image.file.seek(0)
        results = dict(filename=os.path.basename(request.vars.image.filename), user_id=auth.user.id,
                       filesize=len(request.vars.image.file.read()), nocandidate=1)

    return results
