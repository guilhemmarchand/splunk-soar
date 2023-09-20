"""
Orchestrates the ThreatIntel use case, the master playbook runs all dependent playbooks accordingly
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'check_for_url' block
    check_for_url(container=container)

    return

def check_for_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("check_for_url() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        filter_for_url(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_comment_invalid_af(action=action, success=success, container=container, results=results, handle=handle)

    return


def call_spl_correlation_playbook(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("call_spl_correlation_playbook() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/CBL - ThreatIntel - SPL correlation", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/CBL - ThreatIntel - SPL correlation", container=container, name="call_spl_correlation_playbook", callback=call_urlscan_detonate_url_playbook)

    return


def add_comment_invalid_af(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_invalid_af() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Artifact is invalid and has no requestURL")

    return


def call_urlscan_detonate_url_playbook(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("call_urlscan_detonate_url_playbook() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/CBL - ThreatIntel - Detonate urlscan.io", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/CBL - ThreatIntel - Detonate urlscan.io", container=container, name="call_urlscan_detonate_url_playbook", callback=call_virustotal_detonate_url_playbook)

    return


def call_virustotal_detonate_url_playbook(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("call_virustotal_detonate_url_playbook() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/CBL - ThreatIntel - Detonate VirusTotal", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/CBL - ThreatIntel - Detonate VirusTotal", container=container, name="call_virustotal_detonate_url_playbook", callback=format_actions_results)

    return


def format_actions_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_actions_results() called")

    template = """%%\nCorrelation results for domain {0}\n- Splunk results: {1}\n- Urlscan.io results: {2}\n- VirusTotal results: {3}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_for_url:condition_1:artifact:*.cef.requestURL",
        "call_spl_correlation_playbook:playbook_output:summary",
        "call_urlscan_detonate_url_playbook:playbook_output:summary",
        "call_virustotal_detonate_url_playbook:playbook_output:summary"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_actions_results")

    prompt_action_on_digital_shadow_alert(container=container)

    return


def prompt_action_on_digital_shadow_alert(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_action_on_digital_shadow_alert() called")

    # set user and message variables for phantom.prompt call

    user = "Incident Commander"
    message = """A new Digital Shadow alert was detected, correlations were performed as follows:\n{0}\n\nChoose the action to be performed:\n\n- Yes: A new Remedy ticket will be opened and the domain will be blocked on Netskope and Mimecast\n\n- No: If the alert is a false positive, this domain will be added to an allow list stored in Splunk to prevent new alerts from triggering"""

    # parameter list for template variable replacement
    parameters = [
        "format_actions_results:formatted_data.*"
    ]

    # responses
    response_types = [
        {
            "prompt": "Open Remedy ticket and block the domain?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=240, name="prompt_action_on_digital_shadow_alert", parameters=parameters, response_types=response_types, callback=chek_for_prompt_response)

    return


def chek_for_prompt_response(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("chek_for_prompt_response() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_action_on_digital_shadow_alert:action_result.summary.responses.0", "==", "Yes"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        promote_to_case(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_action_on_digital_shadow_alert:action_result.summary.responses.0", "==", "No"]
        ])

    # call connected blocks if condition 2 matched
    if found_match_2:
        call_add_allowlist_playbook(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def call_add_allowlist_playbook(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("call_add_allowlist_playbook() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/CBL - ThreatIntel - Add to allowlist SPL", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/CBL - ThreatIntel - Add to allowlist SPL", container=container, name="call_add_allowlist_playbook", callback=call_add_allowlist_playbook_callback)

    return


def call_add_allowlist_playbook_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("call_add_allowlist_playbook_callback() called")

    
    # Downstream End block cannot be called directly, since execution will call on_finish automatically.
    # Using placeholder callback function so child playbook is run synchronously.


    return


def promote_to_case(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("promote_to_case() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.promote(container=container, template="Risk Investigation")

    container = phantom.get_container(container.get('id', None))

    format_remedy_ticket_description(container=container)

    return


def format_remedy_ticket_description(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_remedy_ticket_description() called")

    template = """%%\nImpersonating domain alert for {0}\n%%"""

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

    phantom.format(container=container, template=template, parameters=parameters, name="format_remedy_ticket_description")

    call_create_ticket_and_block_playbook(container=container)

    return


def call_create_ticket_and_block_playbook(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("call_create_ticket_and_block_playbook() called")

    filtered_artifact_0_data_filter_for_url = phantom.collect2(container=container, datapath=["filtered-data:filter_for_url:condition_1:artifact:*.cef.requestURL"])
    format_remedy_ticket_description__as_list = phantom.get_format_data(name="format_remedy_ticket_description__as_list")

    filtered_artifact_0__cef_requesturl = [item[0] for item in filtered_artifact_0_data_filter_for_url]

    inputs = {
        "requesturl": filtered_artifact_0__cef_requesturl,
        "description": format_remedy_ticket_description__as_list,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/CBL - ThreatIntel - Create ticket and block domain input playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/CBL - ThreatIntel - Create ticket and block domain input playbook", container=container, name="call_create_ticket_and_block_playbook", callback=call_create_ticket_and_block_playbook_callback, inputs=inputs)

    return


def call_create_ticket_and_block_playbook_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("call_create_ticket_and_block_playbook_callback() called")

    
    # Downstream End block cannot be called directly, since execution will call on_finish automatically.
    # Using placeholder callback function so child playbook is run synchronously.


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
        call_spl_correlation_playbook(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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