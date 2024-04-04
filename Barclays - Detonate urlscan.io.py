"""
This playbook is designed to be triggered by the master playbook, it will perform the detonation of the domain in Urlscan.io, retrieve automatically the Website screenshot if any and provide the investigation results for consolidation purposes
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_for_url' block
    filter_for_url(container=container)

    return

@phantom.playbook_block()
def filter_for_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_for_url() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""]
        ],
        name="filter_for_url:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        run_detonate_url(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def run_detonate_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_detonate_url() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_filter_for_url = phantom.collect2(container=container, datapath=["filtered-data:filter_for_url:condition_1:artifact:*.cef.requestURL","filtered-data:filter_for_url:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'run_detonate_url' call
    for filtered_artifact_0_item_filter_for_url in filtered_artifact_0_data_filter_for_url:
        if filtered_artifact_0_item_filter_for_url[0] is not None:
            parameters.append({
                "url": filtered_artifact_0_item_filter_for_url[0],
                "private": True,
                "get_result": True,
                "context": {'artifact_id': filtered_artifact_0_item_filter_for_url[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate url", parameters=parameters, name="run_detonate_url", assets=["urlscan.io"], callback=format_detonate_note_title)

    return


@phantom.playbook_block()
def format_detonate_note_content(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_detonate_note_content() called")

    template = """%%\nDomain: {0}, Score: {1}, Malicious: {2}, Report URL: {3}, Screenshot URL: {4}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_for_url:condition_1:artifact:*.cef.requestURL",
        "run_detonate_url:action_result.data.*.verdicts.overall.score",
        "run_detonate_url:action_result.data.*.verdicts.overall.malicious",
        "run_detonate_url:action_result.data.*.task.reportURL",
        "run_detonate_url:action_result.data.*.task.screenshotURL"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_detonate_note_content")

    add_detonate_note(container=container)

    return


@phantom.playbook_block()
def format_detonate_note_title(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_detonate_note_title() called")

    template = """%%\nurlscan.io results for URL: {0}\n%%"""

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

    phantom.format(container=container, template=template, parameters=parameters, name="format_detonate_note_title")

    format_detonate_note_content(container=container)

    return


@phantom.playbook_block()
def add_detonate_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_detonate_note() called")

    format_detonate_note_content__as_list = phantom.get_format_data(name="format_detonate_note_content__as_list")
    format_detonate_note_title__as_list = phantom.get_format_data(name="format_detonate_note_title__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_detonate_note_content__as_list, note_format="markdown", note_type="general", title=format_detonate_note_title__as_list)

    add_detonate_comment(container=container)

    return


@phantom.playbook_block()
def check_for_screenshot_fileurl(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("check_for_screenshot_fileurl() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["run_detonate_url:action_result.data.*.task.screenshotURL", "!=", ""]
        ],
        delimiter=",")

    # call connected blocks if condition 1 matched
    if found_match_1:
        upload_file_from_url_6(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    format_comment_domain_not_found(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def format_comment_upload_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_comment_upload_file() called")

    template = """%%\nurlscan.io screenshot file downloaded from {0} and added as file attached to the container\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "run_detonate_url:action_result.data.*.task.screenshotURL"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_comment_upload_file")

    add_comment_upload_file(container=container)

    return


@phantom.playbook_block()
def add_comment_upload_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_upload_file() called")

    format_comment_upload_file__as_list = phantom.get_format_data(name="format_comment_upload_file__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_comment_upload_file__as_list)

    return


@phantom.playbook_block()
def format_comment_domain_not_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_comment_domain_not_found() called")

    template = """%%\nurlscan.io screenshot for {0} is not available, likely the domain was not found.\n%%"""

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

    phantom.format(container=container, template=template, parameters=parameters, name="format_comment_domain_not_found")

    add_comment_screenshot_not_available(container=container)

    return


@phantom.playbook_block()
def add_comment_screenshot_not_available(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_screenshot_not_available() called")

    format_comment_domain_not_found__as_list = phantom.get_format_data(name="format_comment_domain_not_found__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_comment_domain_not_found__as_list)

    return


@phantom.playbook_block()
def add_detonate_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_detonate_comment() called")

    format_detonate_note_content__as_list = phantom.get_format_data(name="format_detonate_note_content__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_detonate_note_content__as_list)

    check_for_screenshot_fileurl(container=container)

    return


@phantom.playbook_block()
def upload_file_from_url_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("upload_file_from_url_6() called")

    id_value = container.get("id", None)
    run_detonate_url_result_data = phantom.collect2(container=container, datapath=["run_detonate_url:action_result.data.*.task.screenshotURL","run_detonate_url:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'upload_file_from_url_6' call
    for run_detonate_url_result_item in run_detonate_url_result_data:
        parameters.append({
            "fileUrl": run_detonate_url_result_item[0],
            "container_id": id_value,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="Dev/upload_file_from_url", parameters=parameters, name="upload_file_from_url_6", callback=format_comment_upload_file)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    run_detonate_url_result_data = phantom.collect2(container=container, datapath=["run_detonate_url:action_result.data.*.verdicts.overall.score"])
    format_detonate_note_content__as_list = phantom.get_format_data(name="format_detonate_note_content__as_list")

    run_detonate_url_result_item_0 = [item[0] for item in run_detonate_url_result_data]

    output = {
        "score": run_detonate_url_result_item_0,
        "summary": format_detonate_note_content__as_list,
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