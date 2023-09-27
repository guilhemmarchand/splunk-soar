"""
This input playbook closes a notable event in Splunk Enterprise Security
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'check_for_action' block
    check_for_action(container=container)

    return

@phantom.playbook_block()
def format_spl_query_close(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_spl_query_close() called")

    template = """| eval event_id=\"{0}\"\n| eval _key=event_id, rule_id=event_id, comment=\"Updated from SOAR automation\", time=now(), status=5, user=\"admin\", owner=\"soar\"\n| table _key comment rule_id time status rule_name user owner\n| outputlookup append=true incident_review_lookup"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.event_id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_spl_query_close")

    run_spl_query_close_notable(container=container)

    return


@phantom.playbook_block()
def run_spl_query_close_notable(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_spl_query_close_notable() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_spl_query_close = phantom.get_format_data(name="format_spl_query_close")

    parameters = []

    if format_spl_query_close is not None:
        parameters.append({
            "query": format_spl_query_close,
            "command": "| makeresults",
            "end_time": "now",
            "start_time": "-5m",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_spl_query_close_notable", assets=["splunk"])

    return


@phantom.playbook_block()
def check_for_action(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("check_for_action() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_input:action", "==", "progress"]
        ],
        delimiter=",")

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_spl_query_progress(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_input:action", "==", "close"]
        ],
        delimiter=",")

    # call connected blocks if condition 2 matched
    if found_match_2:
        format_spl_query_close(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 3
    found_match_3 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_input:action", "==", "pending"]
        ],
        delimiter=",")

    # call connected blocks if condition 3 matched
    if found_match_3:
        format_spl_query_pending(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 4
    found_match_4 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_input:action", "==", "resolved"]
        ],
        delimiter=",")

    # call connected blocks if condition 4 matched
    if found_match_4:
        format_spl_query_resolved(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def format_spl_query_progress(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_spl_query_progress() called")

    template = """| eval event_id=\"{0}\"\n| eval _key=event_id, rule_id=event_id, comment=\"Updated from SOAR automation\", time=now(), status=2, user=\"admin\", owner=\"soar\"\n| table _key comment rule_id time status rule_name user owner\n| outputlookup append=true incident_review_lookup"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.event_id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_spl_query_progress")

    run_spl_query_progress_notable(container=container)

    return


@phantom.playbook_block()
def run_spl_query_progress_notable(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_spl_query_progress_notable() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_spl_query_progress = phantom.get_format_data(name="format_spl_query_progress")

    parameters = []

    if format_spl_query_progress is not None:
        parameters.append({
            "query": format_spl_query_progress,
            "command": "| makeresults",
            "end_time": "now",
            "start_time": "-5m",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_spl_query_progress_notable", assets=["splunk"])

    return


@phantom.playbook_block()
def format_spl_query_pending(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_spl_query_pending() called")

    template = """| eval event_id=\"{0}\"\n| eval _key=event_id, rule_id=event_id, comment=\"Updated from SOAR automation\", time=now(), status=3, user=\"admin\", owner=\"soar\"\n| table _key comment rule_id time status rule_name user owner\n| outputlookup append=true incident_review_lookup"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.event_id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_spl_query_pending")

    run_spl_query_pending_notable(container=container)

    return


@phantom.playbook_block()
def run_spl_query_pending_notable(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_spl_query_pending_notable() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_spl_query_pending = phantom.get_format_data(name="format_spl_query_pending")

    parameters = []

    if format_spl_query_pending is not None:
        parameters.append({
            "query": format_spl_query_pending,
            "command": "| makeresults",
            "end_time": "now",
            "start_time": "-5m",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_spl_query_pending_notable", assets=["splunk"])

    return


@phantom.playbook_block()
def format_spl_query_resolved(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_spl_query_resolved() called")

    template = """| eval event_id=\"{0}\"\n| eval _key=event_id, rule_id=event_id, comment=\"Updated from SOAR automation\", time=now(), status=4, user=\"admin\", owner=\"soar\"\n| table _key comment rule_id time status rule_name user owner\n| outputlookup append=true incident_review_lookup"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.event_id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_spl_query_resolved")

    run_spl_query_resolved_notable(container=container)

    return


@phantom.playbook_block()
def run_spl_query_resolved_notable(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_spl_query_resolved_notable() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_spl_query_pending = phantom.get_format_data(name="format_spl_query_pending")

    parameters = []

    if format_spl_query_pending is not None:
        parameters.append({
            "query": format_spl_query_pending,
            "command": "| makeresults",
            "end_time": "now",
            "start_time": "-5m",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_spl_query_resolved_notable", assets=["splunk"])

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    run_spl_query_close_notable_result_data = phantom.collect2(container=container, datapath=["run_spl_query_close_notable:action_result.status"])
    run_spl_query_progress_notable_result_data = phantom.collect2(container=container, datapath=["run_spl_query_progress_notable:action_result.status"])
    run_spl_query_pending_notable_result_data = phantom.collect2(container=container, datapath=["run_spl_query_pending_notable:action_result.status"])
    run_spl_query_resolved_notable_result_data = phantom.collect2(container=container, datapath=["run_spl_query_resolved_notable:action_result.status"])

    run_spl_query_close_notable_result_item_0 = [item[0] for item in run_spl_query_close_notable_result_data]
    run_spl_query_progress_notable_result_item_0 = [item[0] for item in run_spl_query_progress_notable_result_data]
    run_spl_query_pending_notable_result_item_0 = [item[0] for item in run_spl_query_pending_notable_result_data]
    run_spl_query_resolved_notable_result_item_0 = [item[0] for item in run_spl_query_resolved_notable_result_data]

    status_combined_value = phantom.concatenate(run_spl_query_close_notable_result_item_0, run_spl_query_progress_notable_result_item_0, run_spl_query_pending_notable_result_item_0, run_spl_query_resolved_notable_result_item_0)

    output = {
        "status": status_combined_value,
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