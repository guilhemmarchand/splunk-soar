"""
This input playbook is designed to be called in the Recon use case by a master playbook.\nThe paybook uses either the AID (device_id) or the HostName of the endpoint to retrieve information from CrowdStrike API (local_ip and more) and enriches the artifacts automatically
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'format_crowdstrike_query' block
    format_crowdstrike_query(container=container)

    return

def query_device_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("query_device_info() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_crowdstrike_query__as_list = phantom.get_format_data(name="format_crowdstrike_query__as_list")

    parameters = []

    # build parameters list for 'query_device_info' call
    for format_crowdstrike_query__item in format_crowdstrike_query__as_list:
        parameters.append({
            "limit": 1,
            "filter": format_crowdstrike_query__item,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("query device", parameters=parameters, name="query_device_info", assets=["crowdstrikefalcon"], callback=check_for_device_id)

    return


def format_crowdstrike_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_crowdstrike_query() called")

    ################################################################################
    # Format the CrowdStrike query
    ################################################################################

    template = """%%\n{0}: '{1}'\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:inputfieldname",
        "playbook_input:inputfieldvalue"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_crowdstrike_query")

    query_device_info(container=container)

    return


def check_for_device_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("check_for_device_id() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["query_device_info:action_result.data.*.hostname", "!=", ""],
            ["query_device_info:action_result.data.*.local_ip", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_comment_success(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    format_failed_comment(action=action, success=success, container=container, results=results, handle=handle)

    return


def format_failed_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_failed_comment() called")

    template = """%%\nFailed to retrieve the aid value from CrowdStrike for the endpoint using query=\"{0}\"\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "format_crowdstrike_query:formatted_data.*"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_failed_comment")

    add_failed_comment(container=container)

    return


def format_comment_success(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_comment_success() called")

    template = """%%\nInformation successfully retrieved for CrowdStike device_id: {0}, local_ip: {1}, hostname: {2}, mac_address: {3}, plateform_name: {4}, os_version: {5}\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "query_device_info:action_result.data.*.device_id",
        "query_device_info:action_result.data.*.local_ip",
        "query_device_info:action_result.data.*.hostname",
        "query_device_info:action_result.data.*.mac_address",
        "query_device_info:action_result.data.*.os_version",
        "query_device_info:action_result.data.*.platform_name"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_comment_success")

    add_success_comment(container=container)

    return


def add_success_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_success_comment() called")

    format_comment_success__as_list = phantom.get_format_data(name="format_comment_success__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_comment_success__as_list)

    format_update_artifact(container=container)

    return


def add_failed_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_failed_comment() called")

    format_failed_comment__as_list = phantom.get_format_data(name="format_failed_comment__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_failed_comment__as_list)

    return


def update_artifact_for_destination(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_artifact_for_destination() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_input_artifactid = phantom.collect2(container=container, datapath=["playbook_input:artifactid"])
    format_update_artifact__as_list = phantom.get_format_data(name="format_update_artifact__as_list")

    parameters = []

    # build parameters list for 'update_artifact_for_destination' call
    for format_update_artifact__item in format_update_artifact__as_list:
        for playbook_input_artifactid_item in playbook_input_artifactid:
            if playbook_input_artifactid_item[0] is not None:
                parameters.append({
                    "cef_json": format_update_artifact__item,
                    "artifact_id": playbook_input_artifactid_item[0],
                    "artifact_json": "",
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update artifact", parameters=parameters, name="update_artifact_for_destination", assets=["soar-helper"])

    return


def format_update_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_update_artifact() called")

    template = """%%\n{{\"destinationAid\": \"{0}\",\"destinationAddress\": \"{1}\", \"destinationHostName\": \"{2}\",\"destinationMacAddress\": \"{3}\", \"plateform_name\": \"{4}\", \"os_version\": \"{5}\"}}\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "query_device_info:action_result.data.*.device_id",
        "query_device_info:action_result.data.*.local_ip",
        "query_device_info:action_result.data.*.hostname",
        "query_device_info:action_result.data.*.mac_address",
        "query_device_info:action_result.data.*.platform_name",
        "query_device_info:action_result.data.*.os_version"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_update_artifact")

    update_artifact_for_destination(container=container)

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    query_device_info_result_data = phantom.collect2(container=container, datapath=["query_device_info:action_result.data.*.hostname","query_device_info:action_result.data.*.local_ip","query_device_info:action_result.data.*.mac_address","query_device_info:action_result.data.*.platform_name","query_device_info:action_result.data.*.os_version","query_device_info:action_result.data.*.device_id"])

    query_device_info_result_item_0 = [item[0] for item in query_device_info_result_data]
    query_device_info_result_item_1 = [item[1] for item in query_device_info_result_data]
    query_device_info_result_item_2 = [item[2] for item in query_device_info_result_data]
    query_device_info_result_item_3 = [item[3] for item in query_device_info_result_data]
    query_device_info_result_item_4 = [item[4] for item in query_device_info_result_data]
    query_device_info_result_item_5 = [item[5] for item in query_device_info_result_data]

    output = {
        "destinationhostname": query_device_info_result_item_0,
        "destinationaddress": query_device_info_result_item_1,
        "destinationmacaddress": query_device_info_result_item_2,
        "plateform_name": query_device_info_result_item_3,
        "os_version": query_device_info_result_item_4,
        "destinationaid": query_device_info_result_item_5,
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