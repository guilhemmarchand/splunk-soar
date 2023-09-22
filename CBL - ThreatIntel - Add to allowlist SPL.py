"""
This playbook is designed to be triggered by the master playbook, it adds the provided domain to an allow list collection in Splunk to prevent the same domain from triggering a new alert in the Splunk correlation search
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_for_url' block
    filter_for_url(container=container)

    return

def filter_for_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_for_url() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""]
        ],
        name="filter_for_url:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_spl_query_add_allowlist(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def format_spl_query_add_allowlist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_spl_query_add_allowlist() called")

    template = """%%\n| eval domain=\"{0}\", last_time_seen=now(), allow_listed=\"True\", comment=\"Added by SOAR automation upon analyst decision\" | lookup local=t digital_shadows_allowlist_domains domain OUTPUT _key as key, ctime, comment as current_comment | eval key=if(isnull(key), md5(domain), key), ctime=if(isnull(ctime), now(), ctime), comment=if(isnotnull(current_comment) AND comment!=\"\", current_comment, comment) | fields - current_comment | outputlookup digital_shadows_allowlist_domains append=t key_field=key\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_for_url:condition_1:artifact:*.cef.requestURL"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_spl_query_add_allowlist")

    run_spl_query_add_allowlist(container=container)

    return


def format_note_add_allowlist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_note_add_allowlist() called")

    template = """%%\nThe domain {0} was added to Splunk allow list collection upon the analyst decision, new alerts will not trigger as long as the allow list is active for this domain. (allow_listed=True in the collection digital_shadows_allowlist_domains)\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_for_url:condition_1:artifact:*.cef.requestURL"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_note_add_allowlist")

    format_comment_add_allowlist(container=container)

    return


def format_comment_add_allowlist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_comment_add_allowlist() called")

    template = """%%\nThe domain {0} was added to the Splunk allow list collection.\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_for_url:condition_1:artifact:*.cef.requestURL"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_comment_add_allowlist")

    add_note_allowlist(container=container)

    return


def run_spl_query_add_allowlist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_spl_query_add_allowlist() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_spl_query_add_allowlist__as_list = phantom.get_format_data(name="format_spl_query_add_allowlist__as_list")

    parameters = []

    # build parameters list for 'run_spl_query_add_allowlist' call
    for format_spl_query_add_allowlist__item in format_spl_query_add_allowlist__as_list:
        if format_spl_query_add_allowlist__item is not None:
            parameters.append({
                "query": format_spl_query_add_allowlist__item,
                "command": "| makeresults",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_spl_query_add_allowlist", assets=["splunkes"], callback=check_for_spl_allow_list_result)

    return


def check_for_spl_allow_list_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("check_for_spl_allow_list_result() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["run_spl_query_add_allowlist:action_result.status", "==", "success"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_note_add_allowlist(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    format_comment_failed_allowlist(action=action, success=success, container=container, results=results, handle=handle)

    return


def add_note_allowlist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_note_allowlist() called")

    format_note_add_allowlist__as_list = phantom.get_format_data(name="format_note_add_allowlist__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_note_add_allowlist__as_list, note_format="markdown", note_type="general", title="Splunk add domain to allow list")

    add_comment_4(container=container)

    return


def add_comment_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_4() called")

    format_comment_add_allowlist__as_list = phantom.get_format_data(name="format_comment_add_allowlist__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_comment_add_allowlist__as_list)

    return


def format_comment_failed_allowlist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_comment_failed_allowlist() called")

    template = """%%\nERROR: failed to add the domain {0} in the Splunk allow list collection digital_shadows_allowlist_domains, please review and address this issue.\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_for_url:condition_1:artifact:*.cef.requestURL"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_comment_failed_allowlist")

    add_comment_failed_allowlist(container=container)

    return


def add_comment_failed_allowlist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_failed_allowlist() called")

    format_comment_failed_allowlist__as_list = phantom.get_format_data(name="format_comment_failed_allowlist__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_comment_failed_allowlist__as_list)

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    run_spl_query_add_allowlist_result_data = phantom.collect2(container=container, datapath=["run_spl_query_add_allowlist:action_result.status"])

    run_spl_query_add_allowlist_result_item_0 = [item[0] for item in run_spl_query_add_allowlist_result_data]

    output = {
        "status": run_spl_query_add_allowlist_result_item_0,
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