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
        pass

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
        pass

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
    playbook_run_id = phantom.playbook("Dev/Barclays - VirusTotal file reputation", container=container, name="playbook_barclays___virustotal_file_reputation_1", inputs=inputs)

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