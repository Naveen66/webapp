# -*- coding: utf-8 -*-
import csv
import simplejson

@auth.requires_login()
def index():
    response.title = "Analyze"

    # Data for graph
    chart_data = get_campaign_send_statistics(auth.user.domainId, num_data_points=5)

    # Sum up chart data numbers for each campaign, to display in table
    campaign_id_to_data = dict()
    campaign_id_data_tuples = []
    from TalentUsers import is_current_user_admin
    current_user_admin = is_current_user_admin(auth.user_id)

    for row in chart_data:
        logger.debug('chart_data row, %s', row)
        campaign_id = row[1]
        row_data = row[2]

        # Filter out subscription campaigns for non-admins
        if row_data.get('is_subscription') and not current_user_admin:
            continue

        if not campaign_id_to_data.get(campaign_id):
            campaign_data = dict(sends=0, text_clicks=0, html_clicks=0, opens=0, bounces=0, user_id=row_data['user_id'],
                                 name=row_data['name'], date=row_data['date'])
            campaign_id_to_data[campaign_id] = campaign_data
            campaign_id_data_tuples.append([campaign_id, campaign_data])
        else:
            campaign_id_data_tuples[-1][1]['date'] = row_data['date']

        campaign_id_to_data[campaign_id]['sends'] += row_data['sends']
        campaign_id_to_data[campaign_id]['text_clicks'] += row_data['text_clicks']
        campaign_id_to_data[campaign_id]['html_clicks'] += row_data['html_clicks']
        campaign_id_to_data[campaign_id]['opens'] += row_data['opens']
        campaign_id_to_data[campaign_id]['bounces'] += row_data['bounces']

    from TalentUsers import users_in_domain
    return dict(
        table_data=campaign_id_data_tuples,
        json_chart_data=simplejson.dumps(chart_data),
        users=users_in_domain(auth.user.domainId)
    )


@auth.requires_login()
def show():
    campaign_id = request.args[0]
    email_campaign = db.email_campaign(campaign_id)

    data_dict = get_campaign_statistics(email_campaign.id, weeks_ago=12)

    response.title = "Analyze %s" % email_campaign.name

    # Return response
    return response.render(data_dict)


@auth.requires_login()
def download_csv():
    import StringIO

    campaign_id = request.args[0]
    data = get_campaign_statistics(campaign_id)

    # Set response rows
    header_row = ['Name', 'Total Emails Sent', 'Lists', 'Opens', 'HTML Clicks', 'Text Clicks', 'Bounces', 'Last Open',
                  'Last HTML Click']
    data_row = [
        data['campaign'].name,
        data['total_emails_sent'],
        ', '.join(data['smart_list_names']),
        data['opens'],
        data['html_clicks'],
        data['text_clicks'],
        data['bounces'],
        readable_datetime(data['last_open']),
        readable_datetime(data['last_html_click']),
    ]
    output = StringIO.StringIO()
    csv_writer = csv.writer(output, quoting=csv.QUOTE_ALL)
    csv_writer.writerows([header_row, data_row])

    # Output CSV
    csv_response_headers(response)
    return output.getvalue()


@auth.requires_login()
def view_email():
    campaign_id = request.args[0]
    campaign = db.email_campaign(campaign_id)
    campaign_user = db.user(campaign.userId)
    if not campaign_user or campaign_user.domainId != auth.user.domainId:
        return None

    email_format = 'HTML' if campaign.emailBodyHtml else 'text'

    response.title = "Email of campaign %s (%s)" % (campaign.name, email_format)

    return campaign.emailBodyHtml or campaign.emailBodyText
