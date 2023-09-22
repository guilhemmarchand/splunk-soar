"""
This playbook is designed to be triggered by the master playbook, it will perform several correlation in Splunk data sources to be consolidated for the analyst decision purposes
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_af_for_url' block
    filter_af_for_url(container=container)

    return

def filter_af_for_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_af_for_url() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""]
        ],
        name="filter_af_for_url:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        parse_url(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def format_spl_query_crowdstrike(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_spl_query_crowdstrike() called")

    template = """%%\nindex=\"sec_crowdstrike\" \"{0}\" DomainName=*{0}* | stats min(_time) as _time, values(aid) as aid, dc(aid) as count_endpoints, count as count, values(DomainName) as DomainName, latest(_raw) as last_event | eval summary=if(count>0, \"Results were found in CrowdStrike for the domain \" . \"{0}\", \"No results were found in CrowdStrike for the domain \" . \"{0}\") | tojson\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "parse_url:custom_function_result.data.netloc"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_spl_query_crowdstrike")

    run_spl_query_crowdstrike(container=container)

    return


def parse_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("parse_url() called")

    filtered_artifact_0_data_filter_af_for_url = phantom.collect2(container=container, datapath=["filtered-data:filter_af_for_url:condition_1:artifact:*.cef.requestURL","filtered-data:filter_af_for_url:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'parse_url' call
    for filtered_artifact_0_item_filter_af_for_url in filtered_artifact_0_data_filter_af_for_url:
        parameters.append({
            "input_url": filtered_artifact_0_item_filter_af_for_url[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/url_parse", parameters=parameters, name="parse_url", callback=check_for_netloc)

    return


def run_spl_query_crowdstrike(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_spl_query_crowdstrike() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_spl_query_crowdstrike__as_list = phantom.get_format_data(name="format_spl_query_crowdstrike__as_list")

    parameters = []

    # build parameters list for 'run_spl_query_crowdstrike' call
    for format_spl_query_crowdstrike__item in format_spl_query_crowdstrike__as_list:
        if format_spl_query_crowdstrike__item is not None:
            parameters.append({
                "query": format_spl_query_crowdstrike__item,
                "command": "search",
                "end_time": "now",
                "start_time": "-30d",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_spl_query_crowdstrike", assets=["splunkes"], callback=add_comment_crowdstrike)

    return


def format_spl_query_paloalto(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_spl_query_paloalto() called")

    template = """%%\nindex=\"sec_paloalto\" sourcetype=\"pan:*\" \"{0}\" | stats values(sourcetype) as sourcetype, count as count, count(eval(action=\"allowed\")) as count_allowed, count(eval(action!=\"failure\")) as count_failures, sum(bytes) as bytes, sum(bytes_in) as bytes_in, sum(bytes_out) as bytes_out, dc(src) as dcount_src, dc(dest) as dcount_dest, dc(user) as dcount_user, values(app) as app, values(client_location) as client_location\n | foreach app client_location [ eval <<FIELD>> = mvjoin('<<FIELD>>', \", \") ] | eval summary=if(count>0, \"Results were found in PaloAlto for the domain \" . \"{0}\", \"No results were found in PaloAlto for the domain \" . \"{0}\") | tojson\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "parse_url:custom_function_result.data.netloc"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_spl_query_paloalto")

    run_spl_query_paloalto(container=container)

    return


def run_spl_query_paloalto(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_spl_query_paloalto() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_spl_query_paloalto__as_list = phantom.get_format_data(name="format_spl_query_paloalto__as_list")

    parameters = []

    # build parameters list for 'run_spl_query_paloalto' call
    for format_spl_query_paloalto__item in format_spl_query_paloalto__as_list:
        if format_spl_query_paloalto__item is not None:
            parameters.append({
                "query": format_spl_query_paloalto__item,
                "command": "search",
                "end_time": "now",
                "start_time": "-30d",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_spl_query_paloalto", assets=["splunkes"], callback=add_comment_paloalto)

    return


def add_note_spl_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_note_spl_results() called")

    format_note_spl_results_content__as_list = phantom.get_format_data(name="format_note_spl_results_content__as_list")
    format_note_spl_results_title__as_list = phantom.get_format_data(name="format_note_spl_results_title__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_note_spl_results_content__as_list, note_format="markdown", note_type="general", title=format_note_spl_results_title__as_list)

    return


def join_format_note_spl_results_title(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_format_note_spl_results_title() called")

    if phantom.completed(action_names=["run_spl_query_paloalto", "run_spl_query_crowdstrike", "run_spl_query_netskope", "run_spl_query_mimecast"]):
        # call connected block "format_note_spl_results_title"
        format_note_spl_results_title(container=container, handle=handle)

    return


def format_note_spl_results_title(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_note_spl_results_title() called")

    template = """%%\nSplunk correlation results for URL: {0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_af_for_url:condition_1:artifact:*.cef.requestURL"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_note_spl_results_title")

    format_note_spl_results_content(container=container)

    return


def format_note_spl_results_content(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_note_spl_results_content() called")

    template = """%%\n**CrowdStrike** results: {0}, **PaloAlto** results: {1}, **NetSkope** results: {2}, **Mimecast** results: {3}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "run_spl_query_crowdstrike:action_result.data.*._raw",
        "run_spl_query_paloalto:action_result.data.*._raw",
        "run_spl_query_netskope:action_result.data.*._raw",
        "run_spl_query_mimecast:action_result.data.*._raw"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_note_spl_results_content")

    add_note_spl_results(container=container)

    return


def format_spl_query_netskope(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_spl_query_netskope() called")

    template = """%%\nindex=sec_netskope \"{0}\" | stats min(_time) as _time, count, values(app) as app, values(category) as category, dc(src) as dcount_src, dc(dest) as dcount_dest, dc(user) as dcount_user | foreach app category [ eval <<FIELD>> = mvjoin('<<FIELD>>', \", \") ] | eval summary=if(count>0, \"Results were found in NetSkope for the domain \" . \"{0}\", \"No results were found in NetSkope for the domain \" . \"{0}\") | tojson\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "parse_url:custom_function_result.data.netloc"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_spl_query_netskope")

    run_spl_query_netskope(container=container)

    return


def run_spl_query_netskope(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_spl_query_netskope() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_spl_query_netskope__as_list = phantom.get_format_data(name="format_spl_query_netskope__as_list")

    parameters = []

    # build parameters list for 'run_spl_query_netskope' call
    for format_spl_query_netskope__item in format_spl_query_netskope__as_list:
        if format_spl_query_netskope__item is not None:
            parameters.append({
                "query": format_spl_query_netskope__item,
                "command": "search",
                "end_time": "now",
                "start_time": "-30d",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_spl_query_netskope", assets=["splunkes"], callback=add_comment_netskope)

    return


def format_spl_query_mimecast(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_spl_query_mimecast() called")

    template = """%%\nindex=sec_mimecast \"{0}\" sender!=\"portal@digitalshadows.com\" | eval action=lower(coalesce(action, Act)), direction=lower(coalesce(direction, Dir)), subject=coalesce(subject, Subject), recipient=coalesce(recipient, orig_recipient, Rcpt) | stats values(sourcetype) as sourcetype, count as count, values(action) as action, values(direction) as direction, dc(message_id) as dcount_message_id, dc(Sender) as dcount_sender, dc(recipient) as dcount_recipient, values(Sender) as senders, values(recipient) as recipients, dc(subject) as dcount_subject, dc(dest) as dcount_dest, dc(user) as dcount_user, sum(size) as total_size, sum(SpamScore) as total_spam_score | fillnull value=0 total_size, total_span_score | foreach action direction senders recipients [ eval <<FIELD>> = mvjoin('<<FIELD>>', \", \") ] | eval summary=if(count>0, \"Results were found in Mimecast for the domain \" . \"{0}\", \"No results were found in Mimecast for the domain \" . \"{0}\") | tojson\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "parse_url:custom_function_result.data.netloc"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_spl_query_mimecast")

    run_spl_query_mimecast(container=container)

    return


def run_spl_query_mimecast(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_spl_query_mimecast() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_spl_query_mimecast__as_list = phantom.get_format_data(name="format_spl_query_mimecast__as_list")

    parameters = []

    # build parameters list for 'run_spl_query_mimecast' call
    for format_spl_query_mimecast__item in format_spl_query_mimecast__as_list:
        if format_spl_query_mimecast__item is not None:
            parameters.append({
                "query": format_spl_query_mimecast__item,
                "command": "search",
                "end_time": "now",
                "start_time": "-30d",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_spl_query_mimecast", assets=["splunkes"], callback=add_comment_mimecast)

    return


def add_comment_paloalto(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_paloalto() called")

    run_spl_query_paloalto_result_data = phantom.collect2(container=container, datapath=["run_spl_query_paloalto:action_result.data.*.summary"], action_results=results)

    run_spl_query_paloalto_result_item_0 = [item[0] for item in run_spl_query_paloalto_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=run_spl_query_paloalto_result_item_0)

    join_format_note_spl_results_title(container=container)

    return


def add_comment_crowdstrike(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_crowdstrike() called")

    run_spl_query_crowdstrike_result_data = phantom.collect2(container=container, datapath=["run_spl_query_crowdstrike:action_result.data.*.summary"], action_results=results)

    run_spl_query_crowdstrike_result_item_0 = [item[0] for item in run_spl_query_crowdstrike_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=run_spl_query_crowdstrike_result_item_0)

    join_format_note_spl_results_title(container=container)

    return


def add_comment_netskope(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_netskope() called")

    run_spl_query_netskope_result_data = phantom.collect2(container=container, datapath=["run_spl_query_netskope:action_result.data.*.summary"], action_results=results)

    run_spl_query_netskope_result_item_0 = [item[0] for item in run_spl_query_netskope_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=run_spl_query_netskope_result_item_0)

    join_format_note_spl_results_title(container=container)

    return


def add_comment_mimecast(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_mimecast() called")

    run_spl_query_mimecast_result_data = phantom.collect2(container=container, datapath=["run_spl_query_mimecast:action_result.data.*.summary"], action_results=results)

    run_spl_query_mimecast_result_item_0 = [item[0] for item in run_spl_query_mimecast_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=run_spl_query_mimecast_result_item_0)

    join_format_note_spl_results_title(container=container)

    return


def check_for_netloc(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("check_for_netloc() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["parse_url:custom_function_result.data.netloc", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_spl_query_paloalto(action=action, success=success, container=container, results=results, handle=handle)
        format_spl_query_crowdstrike(action=action, success=success, container=container, results=results, handle=handle)
        format_spl_query_netskope(action=action, success=success, container=container, results=results, handle=handle)
        format_spl_query_mimecast(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    format_comment_netloc_failed(action=action, success=success, container=container, results=results, handle=handle)

    return


def format_comment_netloc_failed(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_comment_netloc_failed() called")

    template = """%%\nFailed to extract the netloc from url=\"{0}\" with returned value=\"{1}\"\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_af_for_url:condition_1:artifact:*.cef.requestURL",
        "parse_url:custom_function_result.data.netloc"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_comment_netloc_failed")

    add_comment_8(container=container)

    return


def add_comment_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_8() called")

    format_comment_netloc_failed__as_list = phantom.get_format_data(name="format_comment_netloc_failed__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_comment_netloc_failed__as_list)

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_note_spl_results_content__as_list = phantom.get_format_data(name="format_note_spl_results_content__as_list")

    output = {
        "summary": format_note_spl_results_content__as_list,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return