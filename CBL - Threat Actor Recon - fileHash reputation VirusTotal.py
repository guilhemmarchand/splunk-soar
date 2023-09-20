"""
This playbook is designed to be called by a master playbook for the Threat Actor Recon use case
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_for_hash' block
    filter_for_hash(container=container)

    return

def filter_for_hash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_for_hash() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "!=", ""]
        ],
        name="filter_for_hash:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        run_filehash_reputation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def run_filehash_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_filehash_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_filter_for_hash = phantom.collect2(container=container, datapath=["filtered-data:filter_for_hash:condition_1:artifact:*.cef.fileHash","filtered-data:filter_for_hash:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'run_filehash_reputation' call
    for filtered_artifact_0_item_filter_for_hash in filtered_artifact_0_data_filter_for_hash:
        if filtered_artifact_0_item_filter_for_hash[0] is not None:
            parameters.append({
                "hash": filtered_artifact_0_item_filter_for_hash[0],
                "context": {'artifact_id': filtered_artifact_0_item_filter_for_hash[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("file reputation", parameters=parameters, name="run_filehash_reputation", assets=["virustotal3"], callback=format_hash_reputation_note_title)

    return


def format_hash_reputation_note_title(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_hash_reputation_note_title() called")

    template = """%%\nVirusTotal hash reputation for hash: {0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_for_hash:condition_1:artifact:*.cef.fileHash"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_hash_reputation_note_title")

    format_hash_reputation_note_content(container=container)

    return


def format_hash_reputation_note_content(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_hash_reputation_note_content() called")

    template = """%%\nfileHash: {0}, Summary: {1}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_for_hash:condition_1:artifact:*.cef.fileHash",
        "run_filehash_reputation:action_result.summary"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_hash_reputation_note_content")

    add_hash_reputation_note(container=container)

    return


def add_hash_reputation_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_hash_reputation_note() called")

    format_hash_reputation_note_content__as_list = phantom.get_format_data(name="format_hash_reputation_note_content__as_list")
    format_hash_reputation_note_title__as_list = phantom.get_format_data(name="format_hash_reputation_note_title__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_hash_reputation_note_content__as_list, note_format="markdown", note_type="general", title=format_hash_reputation_note_title__as_list)

    add_comment_hash_reputation(container=container)

    return


def add_comment_hash_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_hash_reputation() called")

    format_hash_reputation_note_content__as_list = phantom.get_format_data(name="format_hash_reputation_note_content__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_hash_reputation_note_content__as_list)

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    run_filehash_reputation_result_data = phantom.collect2(container=container, datapath=["run_filehash_reputation:action_result.summary.malicious","run_filehash_reputation:action_result.summary.suspicious","run_filehash_reputation:action_result.summary"])

    run_filehash_reputation_summary_malicious = [item[0] for item in run_filehash_reputation_result_data]
    run_filehash_reputation_summary_suspicious = [item[1] for item in run_filehash_reputation_result_data]
    run_filehash_reputation_result_item_2 = [item[2] for item in run_filehash_reputation_result_data]

    output = {
        "malicious": run_filehash_reputation_summary_malicious,
        "suspicious": run_filehash_reputation_summary_suspicious,
        "summary": run_filehash_reputation_result_item_2,
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