"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'run_filehash_reputation' block
    run_filehash_reputation(container=container)

    return

@phantom.playbook_block()
def run_filehash_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_filehash_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.fileHash","artifact:*.id"])

    parameters = []

    # build parameters list for 'run_filehash_reputation' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "hash": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("file reputation", parameters=parameters, name="run_filehash_reputation", assets=["virustotal"], callback=format_hash_reputation_note_title)

    return


@phantom.playbook_block()
def format_hash_reputation_note_title(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_hash_reputation_note_title() called")

    template = """%%\nVirusTotal hash reputation for hash: {0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:filehash"
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


@phantom.playbook_block()
def format_hash_reputation_note_content(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_hash_reputation_note_content() called")

    template = """%%\nfileHash: {0}, Summary: {1}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:filehash",
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


@phantom.playbook_block()
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

    return


@phantom.playbook_block()
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

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return