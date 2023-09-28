"""
This playbook is designed to operate automatically on the label splunk_events which corresponds to events send by Splunk ES from Notable Events.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'check_for_uc_requirements' block
    check_for_uc_requirements(container=container)

    return

@phantom.playbook_block()
def filter_for_uc_ref(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_for_uc_ref() called")

    ################################################################################
    # Filers for artifacts containing the custom field splunk_use_care_ref provided 
    # by enrichment from Splunk
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.soar_playbook", "!=", ""]
        ],
        name="filter_for_uc_ref:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        call_uc_playbook(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def call_uc_playbook(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("call_uc_playbook() called")

    filtered_artifact_0_data_filter_for_uc_ref = phantom.collect2(container=container, datapath=["filtered-data:filter_for_uc_ref:condition_1:artifact:*.cef.soar_playbook"])

    filtered_artifact_0__cef_soar_playbook = [item[0] for item in filtered_artifact_0_data_filter_for_uc_ref]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug("Calling playbook={0}".format(filtered_artifact_0__cef_soar_playbook[0]))
    playbook_run_id = phantom.playbook(filtered_artifact_0__cef_soar_playbook[0], container=container)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return


@phantom.playbook_block()
def check_for_uc_requirements(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("check_for_uc_requirements() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.soar_playbook", "!=", ""]
        ],
        delimiter=",")

    # call connected blocks if condition 1 matched
    if found_match_1:
        filter_for_uc_ref(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_comment_af_invalid(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def add_comment_af_invalid(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_af_invalid() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Invalid: the soar_playbook fields is missing from the artifact")

    format_invalid_notable_email_title(container=container)

    return


@phantom.playbook_block()
def format_invalid_notable_email_title(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_invalid_notable_email_title() called")

    template = """SOAR Invalid Splunk Notable detected id: {0}\n"""

    # parameter list for template variable replacement
    parameters = [
        "container:id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_invalid_notable_email_title")

    format_invalid_notablke_email_body(container=container)

    return


@phantom.playbook_block()
def format_invalid_notablke_email_body(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_invalid_notablke_email_body() called")

    template = """An invalid Notable was forwarded to Splunk SOAR Cloud, triage was refused as the Notable event is missing the Playbook target.\n\nPlease review this issue urgently:\n- Event ID: {0}\n- Event URL: {1}{1}\n\nSplunk SOAR Cloud."""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
        "container:url"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_invalid_notablke_email_body")

    send_email_1(container=container)

    return


@phantom.playbook_block()
def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("send_email_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_invalid_notable_email_title__as_list = phantom.get_format_data(name="format_invalid_notable_email_title__as_list")
    format_invalid_notablke_email_body__as_list = phantom.get_format_data(name="format_invalid_notablke_email_body__as_list")

    parameters = []

    # build parameters list for 'send_email_1' call
    for format_invalid_notable_email_title__item in format_invalid_notable_email_title__as_list:
        for format_invalid_notablke_email_body__item in format_invalid_notablke_email_body__as_list:
            if format_invalid_notablke_email_body__item is not None:
                parameters.append({
                    "from": "gmarchand@splunk.com",
                    "to": "gmarchand@splunk.com",
                    "subject": format_invalid_notable_email_title__item,
                    "body": format_invalid_notablke_email_body__item,
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send email", parameters=parameters, name="send_email_1", assets=["internal_smtp"])

    return


@phantom.playbook_block()
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