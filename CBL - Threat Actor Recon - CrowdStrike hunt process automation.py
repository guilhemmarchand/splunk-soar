"""
This playbook is designed to be triggered by the master playbook, it will perform several correlation in Splunk data sources to be consolidated for the analyst decision purposes
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_for_af_requirements' block
    filter_for_af_requirements(container=container)

    return

def filter_for_af_requirements(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_for_af_requirements() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAid", "!=", ""]
        ],
        name="filter_for_af_requirements:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        gen_spl_time_range_filters(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def gen_spl_time_range_filters(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("gen_spl_time_range_filters() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.epochtime","artifact:*.id"])

    parameters = []

    # build parameters list for 'gen_spl_time_range_filters' call
    for container_artifact_item in container_artifact_data:
        parameters.append({
            "epochtime": container_artifact_item[0],
            "earliest_sec_reduce": 86400,
            "latest_sec_increase": 300,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/cbl_gen_spl_timerange_filter", parameters=parameters, name="gen_spl_time_range_filters", callback=format_spl_query_search_parent_process)

    return


def format_spl_query_search_parent_process(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_spl_query_search_parent_process() called")

    template = """%%\nindex=sec_crowdstrike earliest=\"{2}\" latest=\"{3}\" aid=\"{0}\"  [ | makeresults | eval process=\"{1}\" | rex field=process mode=sed \"s/\\[//g\" | rex field=process mode=sed \"s/\\]//g\" | rex field=process mode=sed \"s/\\'/\\\"/g\" | table process | eval process = \"process IN (\" . process . \")\" | return $process | fields search ] | stats count, values(parent*) as \"parent*\" | foreach parent* [ eval <<FIELD>> = mvjoin('<<FIELD>>', \",\") ] | append [ | makeresults | eval count=0 ] | head 1\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_for_af_requirements:condition_1:artifact:*.cef.destinationAid",
        "filtered-data:filter_for_af_requirements:condition_1:artifact:*.cef.destinationProcessName",
        "gen_spl_time_range_filters:custom_function_result.data.earliest_epoch",
        "gen_spl_time_range_filters:custom_function_result.data.latest_epoch"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_spl_query_search_parent_process")

    run_spl_query_search_parent_process(container=container)

    return


def run_spl_query_search_parent_process(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_spl_query_search_parent_process() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    gen_spl_time_range_filters__result = phantom.collect2(container=container, datapath=["gen_spl_time_range_filters:custom_function_result.data.latest_epoch","gen_spl_time_range_filters:custom_function_result.data.earliest_epoch"])
    format_spl_query_search_parent_process__as_list = phantom.get_format_data(name="format_spl_query_search_parent_process__as_list")

    parameters = []

    # build parameters list for 'run_spl_query_search_parent_process' call
    for format_spl_query_search_parent_process__item in format_spl_query_search_parent_process__as_list:
        for gen_spl_time_range_filters__result_item in gen_spl_time_range_filters__result:
            if format_spl_query_search_parent_process__item is not None:
                parameters.append({
                    "command": "search",
                    "query": format_spl_query_search_parent_process__item,
                    "end_time": gen_spl_time_range_filters__result_item[0],
                    "start_time": gen_spl_time_range_filters__result_item[1],
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_spl_query_search_parent_process", assets=["splunkes"], callback=check_for_parent_hunt_result)

    return


def check_for_parent_hunt_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("check_for_parent_hunt_result() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["run_spl_query_search_parent_process:action_result.data.*.count", "==", 0]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_comment_parent_not_found(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    format_spl_query_hunt_child_processes(action=action, success=success, container=container, results=results, handle=handle)

    return


def format_comment_parent_not_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_comment_parent_not_found() called")

    template = """%%\nThe parent process for {0} on device id {1} could not be identified\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_for_af_requirements:condition_1:artifact:*.cef.destinationProcessName",
        "filtered-data:filter_for_af_requirements:condition_1:artifact:*.cef.destinationAid"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_comment_parent_not_found")

    add_comment_parent_process_not_found(container=container)

    return


def add_comment_parent_process_not_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_parent_process_not_found() called")

    format_comment_parent_not_found__as_list = phantom.get_format_data(name="format_comment_parent_not_found__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_comment_parent_not_found__as_list)

    return


def format_spl_query_hunt_child_processes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_spl_query_hunt_child_processes() called")

    template = """%%\nindex=sec_crowdstrike aid=\"{0}\" parent_process_id=\"{1}\" | addinfo | stats count, min(_time) as earliest_time_event, max(_time) as last_time_event, first(info_min_time) as info_min_time, first(info_max_time) as info_max_time, values(process) as process, values(process_id) as process_id, values(process_hash) as process_hash by aid, parent_process_id, parent_process_name | foreach earliest_time_event, last_time_event, info_min_time, info_max_time [ eval <<FIELD>> = strftime('<<FIELD>>', \"%c\") ] | foreach * [ eval <<FIELD>> = mvjoin('<<FIELD>>', \",\") ] | append [ | makeresults | eval count=0 ] | head 1 | eval summary=if(count>0, \"Child processes were found in CrowdStrike for parent_process=\" . parent_process_name, \"No results were found in CrowdStrike for the parent_process_name=\" . parent_process_name) | tojson\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_for_af_requirements:condition_1:artifact:*.cef.destinationAid",
        "run_spl_query_search_parent_process:action_result.data.*.parent_process_id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_spl_query_hunt_child_processes")

    run_spl_query_hunt_processes_from_parent(container=container)

    return


def run_spl_query_hunt_processes_from_parent(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_spl_query_hunt_processes_from_parent() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    gen_spl_time_range_filters__result = phantom.collect2(container=container, datapath=["gen_spl_time_range_filters:custom_function_result.data.latest_epoch","gen_spl_time_range_filters:custom_function_result.data.earliest_epoch"])
    format_spl_query_hunt_child_processes = phantom.get_format_data(name="format_spl_query_hunt_child_processes")

    parameters = []

    # build parameters list for 'run_spl_query_hunt_processes_from_parent' call
    for gen_spl_time_range_filters__result_item in gen_spl_time_range_filters__result:
        if format_spl_query_hunt_child_processes is not None:
            parameters.append({
                "command": "search",
                "query": format_spl_query_hunt_child_processes,
                "end_time": gen_spl_time_range_filters__result_item[0],
                "start_time": gen_spl_time_range_filters__result_item[1],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_spl_query_hunt_processes_from_parent", assets=["splunkes"], callback=add_comment_parent_process_hunt)

    return


def add_comment_parent_process_hunt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_parent_process_hunt() called")

    run_spl_query_hunt_processes_from_parent_result_data = phantom.collect2(container=container, datapath=["run_spl_query_hunt_processes_from_parent:action_result.data.*.summary"], action_results=results)

    run_spl_query_hunt_processes_from_parent_result_item_0 = [item[0] for item in run_spl_query_hunt_processes_from_parent_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=run_spl_query_hunt_processes_from_parent_result_item_0)

    format_note_title_hunt_processes(container=container)

    return


def format_note_title_hunt_processes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_note_title_hunt_processes() called")

    template = """%%\nCrowdStrike processes hunt Splunk results for parent_process_name=\"{0}\"\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "run_spl_query_search_parent_process:action_result.data.*.parent_process_name"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_note_title_hunt_processes")

    format_note_content_hunt_processes(container=container)

    return


def format_note_content_hunt_processes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_note_content_hunt_processes() called")

    template = """%%\n{0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "run_spl_query_hunt_processes_from_parent:action_result.data.*._raw"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_note_content_hunt_processes")

    add_note_hunt_processes(container=container)

    return


def add_note_hunt_processes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_note_hunt_processes() called")

    format_note_content_hunt_processes__as_list = phantom.get_format_data(name="format_note_content_hunt_processes__as_list")
    format_note_title_hunt_processes__as_list = phantom.get_format_data(name="format_note_title_hunt_processes__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_note_content_hunt_processes__as_list, note_format="markdown", note_type="general", title=format_note_title_hunt_processes__as_list)

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    run_spl_query_hunt_processes_from_parent_result_data = phantom.collect2(container=container, datapath=["run_spl_query_hunt_processes_from_parent:action_result.data.*._raw"])

    run_spl_query_hunt_processes_from_parent_result_item_0 = [item[0] for item in run_spl_query_hunt_processes_from_parent_result_data]

    output = {
        "spl_summary_hunt_processes": run_spl_query_hunt_processes_from_parent_result_item_0,
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