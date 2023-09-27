"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'check_for_af_requirements' block
    check_for_af_requirements(container=container)

    return

@phantom.playbook_block()
def check_for_af_requirements(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("check_for_af_requirements() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="or",
        conditions=[
            ["artifact:*.cef.fileHashMd5", "!=", ""],
            ["artifact:*.cef.sourceAddress", "!=", ""],
            ["artifact:*.cef.requestURL", "!=", ""]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        filter_for_af(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_comment_invalid_af(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def add_comment_invalid_af(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_invalid_af() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Artifact is invalid and does not contain a destinationHostname")

    format_subject_invalid_af(container=container)

    return


@phantom.playbook_block()
def format_subject_invalid_af(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_subject_invalid_af() called")

    template = """%%\nSOAR Cloud: invalid event detected {0}\n%%"""

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

    phantom.format(container=container, template=template, parameters=parameters, name="format_subject_invalid_af")

    format_body_invalid_af(container=container)

    return


@phantom.playbook_block()
def format_body_invalid_af(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_body_invalid_af() called")

    template = """SOAR detected that conditions for the triage of the following events were not met:\n\n{0}\n\nPlease review this incident."""

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

    phantom.format(container=container, template=template, parameters=parameters, name="format_body_invalid_af")

    send_email_1(container=container)

    return


@phantom.playbook_block()
def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("send_email_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_body_invalid_af = phantom.get_format_data(name="format_body_invalid_af")
    format_subject_invalid_af = phantom.get_format_data(name="format_subject_invalid_af")

    parameters = []

    if format_body_invalid_af is not None:
        parameters.append({
            "to": "bar@barc.om",
            "body": format_body_invalid_af,
            "from": "foo@bar.com",
            "subject": format_subject_invalid_af,
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
def filter_for_af(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_for_af() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""]
        ],
        name="filter_for_af:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        playbook_barclays___virustotal_url_reputation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "!=", ""]
        ],
        name="filter_for_af:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        playbook_barclays___virustotal_file_reputation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids and results for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "!=", ""]
        ],
        name="filter_for_af:condition_3",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        playbook_barclays___virustotal_ip_reputation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    return


@phantom.playbook_block()
def playbook_barclays___virustotal_file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_barclays___virustotal_file_reputation_1() called")

    filtered_artifact_0_data_filter_for_af = phantom.collect2(container=container, datapath=["filtered-data:filter_for_af:condition_1:artifact:*.cef.fileHash"])

    filtered_artifact_0__cef_filehash = [item[0] for item in filtered_artifact_0_data_filter_for_af]

    inputs = {
        "filehash": filtered_artifact_0__cef_filehash,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "Dev/Barclays - VirusTotal file reputation", returns the playbook_run_id
    playbook_run_id = phantom.playbook("Dev/Barclays - VirusTotal file reputation", container=container, name="playbook_barclays___virustotal_file_reputation_1", callback=playbook_barclays___reversinglabs_sanbox_detonate_1, inputs=inputs)

    return


@phantom.playbook_block()
def playbook_barclays___virustotal_url_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_barclays___virustotal_url_reputation_1() called")

    inputs = {
        "filehash": [],
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "Dev/Barclays - VirusTotal url reputation", returns the playbook_run_id
    playbook_run_id = phantom.playbook("Dev/Barclays - VirusTotal url reputation", container=container, name="playbook_barclays___virustotal_url_reputation_1", callback=playbook_barclays___detonate_urlscan_io_1, inputs=inputs)

    return


@phantom.playbook_block()
def playbook_barclays___virustotal_ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_barclays___virustotal_ip_reputation_1() called")

    inputs = {
        "filehash": [],
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "Dev/Barclays - VirusTotal IP reputation", returns the playbook_run_id
    playbook_run_id = phantom.playbook("Dev/Barclays - VirusTotal IP reputation", container=container, name="playbook_barclays___virustotal_ip_reputation_1", callback=join_playbook_barclays___uc_phising_splunk_correlation_1, inputs=inputs)

    return


@phantom.playbook_block()
def playbook_barclays___detonate_urlscan_io_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_barclays___detonate_urlscan_io_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "Dev/Barclays - Detonate urlscan.io", returns the playbook_run_id
    playbook_run_id = phantom.playbook("Dev/Barclays - Detonate urlscan.io", container=container, name="playbook_barclays___detonate_urlscan_io_1", callback=join_playbook_barclays___uc_phising_splunk_correlation_1)

    return


@phantom.playbook_block()
def playbook_barclays___reversinglabs_sanbox_detonate_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_barclays___reversinglabs_sanbox_detonate_1() called")

    inputs = {
        "message_id": [],
        "recipient": [],
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "Dev/Barclays - ReversingLabs Sanbox detonate", returns the playbook_run_id
    playbook_run_id = phantom.playbook("Dev/Barclays - ReversingLabs Sanbox detonate", container=container, name="playbook_barclays___reversinglabs_sanbox_detonate_1", callback=join_playbook_barclays___uc_phising_splunk_correlation_1, inputs=inputs)

    return


@phantom.playbook_block()
def join_playbook_barclays___uc_phising_splunk_correlation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_playbook_barclays___uc_phising_splunk_correlation_1() called")

    if phantom.completed(playbook_names=["playbook_barclays___virustotal_ip_reputation_1", "playbook_barclays___detonate_urlscan_io_1", "playbook_barclays___reversinglabs_sanbox_detonate_1"]):
        # call connected block "playbook_barclays___uc_phising_splunk_correlation_1"
        playbook_barclays___uc_phising_splunk_correlation_1(container=container, handle=handle)

    return


@phantom.playbook_block()
def playbook_barclays___uc_phising_splunk_correlation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_barclays___uc_phising_splunk_correlation_1() called")

    inputs = {
        "requesturl": [],
        "subject": [],
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "Dev/Barclays - UC Phising Splunk correlation", returns the playbook_run_id
    playbook_run_id = phantom.playbook("Dev/Barclays - UC Phising Splunk correlation", container=container, name="playbook_barclays___uc_phising_splunk_correlation_1", callback=format_prompt_analyst, inputs=inputs)

    return


@phantom.playbook_block()
def format_prompt_analyst(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_prompt_analyst() called")

    template = """%%\n{0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_barclays___virustotal_ip_reputation_1:playbook_output:summary"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_prompt_analyst")

    prompt_analyst(container=container)

    return


@phantom.playbook_block()
def prompt_analyst(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_analyst() called")

    # set user and message variables for phantom.prompt call

    user = None
    role = "CyberOperations T3"
    message = """Option 1\nOption 2"""

    # parameter list for template variable replacement
    parameters = []

    # responses
    response_types = [
        {
            "prompt": "True positive",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="prompt_analyst", parameters=parameters, response_types=response_types, callback=decision_2)

    return


@phantom.playbook_block()
def prompt_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_2() called")

    # set user and message variables for phantom.prompt call

    user = None
    role = "CyberOperations T3"
    message = """option 1"""

    # parameter list for template variable replacement
    parameters = []

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="prompt_2", parameters=parameters)

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_analyst:action_result.summary.responses.0", "==", "yes"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        prompt_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return