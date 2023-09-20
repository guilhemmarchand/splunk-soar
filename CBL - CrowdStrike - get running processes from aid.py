"""
This playbook is designed to retrieve the list of active processed on a given endpoint using CrowdStrike
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_for_aid' block
    filter_for_aid(container=container)

    return

def filter_for_aid(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_for_aid() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAid", "!=", ""]
        ],
        name="filter_for_aid:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        create_crowdstrike_session(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def get_running_processes_from_crowdstrike(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_running_processes_from_crowdstrike() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_filter_for_aid = phantom.collect2(container=container, datapath=["filtered-data:filter_for_aid:condition_1:artifact:*.cef.destinationAid","filtered-data:filter_for_aid:condition_1:artifact:*.id"])
    create_crowdstrike_session_result_data = phantom.collect2(container=container, datapath=["create_crowdstrike_session:action_result.data.*.resources.*.session_id","create_crowdstrike_session:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_running_processes_from_crowdstrike' call
    for filtered_artifact_0_item_filter_for_aid in filtered_artifact_0_data_filter_for_aid:
        for create_crowdstrike_session_result_item in create_crowdstrike_session_result_data:
            if filtered_artifact_0_item_filter_for_aid[0] is not None and create_crowdstrike_session_result_item[0] is not None:
                parameters.append({
                    "command": "ps",
                    "device_id": filtered_artifact_0_item_filter_for_aid[0],
                    "session_id": create_crowdstrike_session_result_item[0],
                    "context": {'artifact_id': create_crowdstrike_session_result_item[1]},
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run admin command", parameters=parameters, name="get_running_processes_from_crowdstrike", assets=["crowdstrikefalcon"], callback=check_for_command_result)

    return


def create_crowdstrike_session(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("create_crowdstrike_session() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_filter_for_aid = phantom.collect2(container=container, datapath=["filtered-data:filter_for_aid:condition_1:artifact:*.cef.destinationAid","filtered-data:filter_for_aid:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'create_crowdstrike_session' call
    for filtered_artifact_0_item_filter_for_aid in filtered_artifact_0_data_filter_for_aid:
        if filtered_artifact_0_item_filter_for_aid[0] is not None:
            parameters.append({
                "device_id": filtered_artifact_0_item_filter_for_aid[0],
                "context": {'artifact_id': filtered_artifact_0_item_filter_for_aid[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("create session", parameters=parameters, name="create_crowdstrike_session", assets=["crowdstrikefalcon"], callback=check_for_session_result)

    return


def check_for_session_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("check_for_session_result() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["create_crowdstrike_session:action_result.status", "==", "success"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        get_running_processes_from_crowdstrike(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    format_comment_failed_connect(action=action, success=success, container=container, results=results, handle=handle)

    return


def check_for_command_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("check_for_command_result() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["get_running_processes_from_crowdstrike:action_result.status", "==", "success"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_comment(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def format_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_comment() called")

    template = """%%\nRunning processes were successfully retrieved via CrowdStrike for device id {0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_for_aid:condition_1:artifact:*.cef.destinationAid"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_comment")

    add_comment(container=container)

    return


def add_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment() called")

    format_comment__as_list = phantom.get_format_data(name="format_comment__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_comment__as_list)

    return


def format_comment_failed_connect(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_comment_failed_connect() called")

    template = """%%\nCrowdStrike get running processes could not be executed, session was not estabilished successfully {0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_for_aid:condition_1:artifact:*.cef.destinationAid"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_comment_failed_connect")

    add_comment_failed(container=container)

    return


def add_comment_failed(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_failed() called")

    format_comment_failed_connect__as_list = phantom.get_format_data(name="format_comment_failed_connect__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_comment_failed_connect__as_list)

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

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

    return