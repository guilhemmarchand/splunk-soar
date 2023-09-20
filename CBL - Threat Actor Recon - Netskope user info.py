"""
This playbook is designed to be triggered by the master playbook, it will perform several correlation in Splunk data sources to be consolidated for the analyst decision purposes
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'gen_spl_time_range_filters' block
    gen_spl_time_range_filters(container=container)

    return

def gen_spl_time_range_filters(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("gen_spl_time_range_filters() called")

    playbook_input_epochtime = phantom.collect2(container=container, datapath=["playbook_input:epochtime"])

    parameters = []

    # build parameters list for 'gen_spl_time_range_filters' call
    for playbook_input_epochtime_item in playbook_input_epochtime:
        parameters.append({
            "epochtime": playbook_input_epochtime_item[0],
            "earliest_sec_reduce": 3600,
            "latest_sec_increase": 60,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/cbl_gen_spl_timerange_filter", parameters=parameters, name="gen_spl_time_range_filters", callback=format_spl_query)

    return


def format_spl_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_spl_query() called")

    template = """%%\nindex=sec_netskope hostname=\"{0}\" earliest=\"{1}\" latest=\"{2}\" | fields user, user_* | stats count, values(user*) as \"user*\" | foreach * [ eval <<FIELD>> = mvjoin('<<FIELD>>', \",\") ] | append [ | makeresults | eval count=0 ]\n| head 1\n| eval summary=if(count>0, \"user info traces were found in NetSkope for the host=\" . \"{0}\", \"No user info results were found in NetSkope for the host=\" .\"{0}\") | tojson\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:destinationhostname",
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

    phantom.format(container=container, template=template, parameters=parameters, name="format_spl_query")

    run_spl_query(container=container)

    return


def run_spl_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_spl_query() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    gen_spl_time_range_filters__result = phantom.collect2(container=container, datapath=["gen_spl_time_range_filters:custom_function_result.data.latest_epoch","gen_spl_time_range_filters:custom_function_result.data.earliest_epoch"])
    format_spl_query__as_list = phantom.get_format_data(name="format_spl_query__as_list")

    parameters = []

    # build parameters list for 'run_spl_query' call
    for format_spl_query__item in format_spl_query__as_list:
        for gen_spl_time_range_filters__result_item in gen_spl_time_range_filters__result:
            if format_spl_query__item is not None:
                parameters.append({
                    "query": format_spl_query__item,
                    "command": "search",
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

    phantom.act("run query", parameters=parameters, name="run_spl_query", assets=["splunkes"], callback=add_comment_user_info)

    return


def add_comment_user_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_user_info() called")

    run_spl_query_result_data = phantom.collect2(container=container, datapath=["run_spl_query:action_result.data.*.summary"], action_results=results)

    run_spl_query_result_item_0 = [item[0] for item in run_spl_query_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=run_spl_query_result_item_0)

    format_note_title(container=container)

    return


def format_note_title(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_note_title() called")

    template = """%%\nNetSkope user info traces for host: {0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:destinationhostname"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_note_title")

    format_note_content(container=container)

    return


def format_note_content(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_note_content() called")

    template = """%%\n{0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "run_spl_query:action_result.data.*._raw"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_note_content")

    add_note_user_info(container=container)

    return


def add_note_user_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_note_user_info() called")

    format_note_content__as_list = phantom.get_format_data(name="format_note_content__as_list")
    format_note_title__as_list = phantom.get_format_data(name="format_note_title__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_note_content__as_list, note_format="markdown", note_type="general", title=format_note_title__as_list)

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    run_spl_query_result_data = phantom.collect2(container=container, datapath=["run_spl_query:action_result.data.*._raw"])

    run_spl_query_result_item_0 = [item[0] for item in run_spl_query_result_data]

    output = {
        "spl_summary_user_info_netskope": run_spl_query_result_item_0,
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