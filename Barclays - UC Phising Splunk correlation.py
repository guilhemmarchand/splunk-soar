"""
This playbook is designed to be triggered by the master playbook, it will perform several correlation in Splunk data sources to be consolidated for the analyst decision purposes
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'gen_spl_time_range_filters_inbound_1' block
    gen_spl_time_range_filters_inbound_1(container=container)
    # call 'gen_spl_time_range_filters_outbound' block
    gen_spl_time_range_filters_outbound(container=container)

    return

@phantom.playbook_block()
def run_spl_query_paloalto_inbound(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_spl_query_paloalto_inbound() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    gen_spl_time_range_filters_inbound_1__result = phantom.collect2(container=container, datapath=["gen_spl_time_range_filters_inbound_1:custom_function_result.data.latest_epoch","gen_spl_time_range_filters_inbound_1:custom_function_result.data.earliest_epoch"])
    format_spl_query_paloalto_inbound__as_list = phantom.get_format_data(name="format_spl_query_paloalto_inbound__as_list")

    parameters = []

    # build parameters list for 'run_spl_query_paloalto_inbound' call
    for format_spl_query_paloalto_inbound__item in format_spl_query_paloalto_inbound__as_list:
        for gen_spl_time_range_filters_inbound_1__result_item in gen_spl_time_range_filters_inbound_1__result:
            if format_spl_query_paloalto_inbound__item is not None:
                parameters.append({
                    "query": format_spl_query_paloalto_inbound__item,
                    "command": "search",
                    "end_time": gen_spl_time_range_filters_inbound_1__result_item[0],
                    "start_time": gen_spl_time_range_filters_inbound_1__result_item[1],
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_spl_query_paloalto_inbound", assets=["splunkes"], callback=add_comment_paloalto_inbound)

    return


@phantom.playbook_block()
def format_spl_query_paloalto_inbound(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_spl_query_paloalto_inbound() called")

    template = """%%\nindex=sec_paloalto sourcetype=\"pan:traffic\" (src=\"{0}\") earliest=\"{1}\" latest=\"{2}\" | addinfo\n| stats min(_time) as earliest_time_event, max(_time) as last_time_event, first(info_min_time) as info_min_time, first(info_max_time) as info_max_time, values(action) as action, values(app) as app, values(client_location) as client_location, values(signature) as signature, sum(bytes) as bytes, sum(bytes_in) as bytes_in, sum(bytes_out) as bytes_out, sum(duration) as duration, dc(dest) as dcount_dest, values(dest_location) as dest_location, values(dest_port) as dest_port, values(dest_zone) as dest_zone, count by src\n| foreach * [ eval <<FIELD>> = mvjoin('<<FIELD>>', \",\") ]\n| foreach earliest_time_event, last_time_event, info_min_time, info_max_time [ eval <<FIELD>> = strftime('<<FIELD>>', \"%c\") ]\n| eval direction=\"inbound\", inbound_traffic_detected=if(count>0, \"true\", \"false\"), \n is_traffic_allowed=if(match(action, \"allowed\"), \"true\", \"false\"),  is_traffic_blocked=if(match(action, \"(blocked|failure)\"), \"true\", \"false\")\n| append [ | makeresults | eval count=0, src=\"{0}\" ]\n| head 1\n| eval summary=if(count>0, \"Inbound traffic results were found in PaloAlto for the src=\" . src, \"No results were found in PaloAlto for the src=\" . src) | tojson\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:destinationaddress",
        "gen_spl_time_range_filters_inbound_1:custom_function_result.data.earliest_epoch",
        "gen_spl_time_range_filters_inbound_1:custom_function_result.data.latest_epoch"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_spl_query_paloalto_inbound")

    run_spl_query_paloalto_inbound(container=container)

    return


@phantom.playbook_block()
def add_comment_paloalto_inbound(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_paloalto_inbound() called")

    run_spl_query_paloalto_inbound_result_data = phantom.collect2(container=container, datapath=["run_spl_query_paloalto_inbound:action_result.data.*.summary"], action_results=results)

    run_spl_query_paloalto_inbound_result_item_0 = [item[0] for item in run_spl_query_paloalto_inbound_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=run_spl_query_paloalto_inbound_result_item_0)

    format_note_spl_results_title_inbound(container=container)

    return


@phantom.playbook_block()
def format_note_spl_results_title_inbound(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_note_spl_results_title_inbound() called")

    template = """%%\nSplunk inbound traffic correlation results for endpoint: {0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:destinationaddress"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_note_spl_results_title_inbound")

    format_note_spl_results_content_inbound(container=container)

    return


@phantom.playbook_block()
def format_note_spl_results_content_inbound(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_note_spl_results_content_inbound() called")

    template = """%%\n{0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "run_spl_query_paloalto_inbound:action_result.data.*._raw"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_note_spl_results_content_inbound")

    add_note_spl_results_inbound(container=container)

    return


@phantom.playbook_block()
def add_note_spl_results_inbound(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_note_spl_results_inbound() called")

    format_note_spl_results_content_inbound__as_list = phantom.get_format_data(name="format_note_spl_results_content_inbound__as_list")
    format_note_spl_results_title_inbound__as_list = phantom.get_format_data(name="format_note_spl_results_title_inbound__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_note_spl_results_content_inbound__as_list, note_format="markdown", note_type="general", title=format_note_spl_results_title_inbound__as_list)

    return


@phantom.playbook_block()
def format_spl_query_paloalto_outbound(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_spl_query_paloalto_outbound() called")

    template = """%%\nindex=sec_paloalto sourcetype=\"pan:traffic\" (dest=\"{0}\") earliest=\"{1}\" latest=\"{2}\" | addinfo\n| stats min(_time) as earliest_time_event, max(_time) as last_time_event, first(info_min_time) as info_min_time, first(info_max_time) as info_max_time, values(action) as action, values(app) as app, values(client_location) as client_location, values(signature) as signature, sum(bytes) as bytes, sum(bytes_in) as bytes_in, sum(bytes_out) as bytes_out, sum(duration) as duration, values(src) as src, values(dest_location) as dest_location, values(dest_port) as dest_port, values(dest_zone) as dest_zone, count by dest\n| foreach * [ eval <<FIELD>> = mvjoin('<<FIELD>>', \",\") ]\n| foreach earliest_time_event, last_time_event, info_min_time, info_max_time [ eval <<FIELD>> = strftime('<<FIELD>>', \"%c\") ]\n| eval direction=\"outbound\", outbound_traffic_detected=if(count>0, \"true\", \"false\"), is_traffic_allowed=if(match(action, \"allowed\"), \"true\", \"false\"),  is_traffic_blocked=if(match(action, \"(blocked|failure)\"), \"true\", \"false\")\n| append [ | makeresults | eval count=0, dest=\"{0}\" ]\n| head 1\n| eval summary=if(count>0, \"Outbound traffic results were found in PaloAlto for the dest=\" . dest, \"No outbound traffic results were found in PaloAlto for the dest=\" . dest) | tojson\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:destinationaddress",
        "gen_spl_time_range_filters_outbound:custom_function_result.data.earliest_epoch",
        "gen_spl_time_range_filters_outbound:custom_function_result.data.latest_epoch"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_spl_query_paloalto_outbound")

    run_spl_query_paloalto_outbound(container=container)

    return


@phantom.playbook_block()
def run_spl_query_paloalto_outbound(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_spl_query_paloalto_outbound() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    gen_spl_time_range_filters_outbound__result = phantom.collect2(container=container, datapath=["gen_spl_time_range_filters_outbound:custom_function_result.data.latest_epoch","gen_spl_time_range_filters_outbound:custom_function_result.data.earliest_epoch"])
    format_spl_query_paloalto_outbound__as_list = phantom.get_format_data(name="format_spl_query_paloalto_outbound__as_list")

    parameters = []

    # build parameters list for 'run_spl_query_paloalto_outbound' call
    for format_spl_query_paloalto_outbound__item in format_spl_query_paloalto_outbound__as_list:
        for gen_spl_time_range_filters_outbound__result_item in gen_spl_time_range_filters_outbound__result:
            if format_spl_query_paloalto_outbound__item is not None:
                parameters.append({
                    "query": format_spl_query_paloalto_outbound__item,
                    "command": "search",
                    "end_time": gen_spl_time_range_filters_outbound__result_item[0],
                    "start_time": gen_spl_time_range_filters_outbound__result_item[1],
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_spl_query_paloalto_outbound", assets=["splunkes"], callback=add_comment_paloalto_outbound)

    return


@phantom.playbook_block()
def add_comment_paloalto_outbound(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_paloalto_outbound() called")

    run_spl_query_paloalto_outbound_result_data = phantom.collect2(container=container, datapath=["run_spl_query_paloalto_outbound:action_result.data.*.summary"], action_results=results)

    run_spl_query_paloalto_outbound_result_item_0 = [item[0] for item in run_spl_query_paloalto_outbound_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=run_spl_query_paloalto_outbound_result_item_0)

    format_note_spl_results_title_outbound(container=container)

    return


@phantom.playbook_block()
def format_note_spl_results_title_outbound(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_note_spl_results_title_outbound() called")

    template = """%%\nSplunk outbound traffic correlation results for endpoint: {0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:destinationaddress"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_note_spl_results_title_outbound")

    format_note_spl_results_content_outbound(container=container)

    return


@phantom.playbook_block()
def format_note_spl_results_content_outbound(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_note_spl_results_content_outbound() called")

    template = """%%\n{0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "run_spl_query_paloalto_outbound:action_result.data.*._raw"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_note_spl_results_content_outbound")

    add_note_spl_results_outbound(container=container)

    return


@phantom.playbook_block()
def add_note_spl_results_outbound(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_note_spl_results_outbound() called")

    format_note_spl_results_content_outbound__as_list = phantom.get_format_data(name="format_note_spl_results_content_outbound__as_list")
    format_note_spl_results_title_outbound__as_list = phantom.get_format_data(name="format_note_spl_results_title_outbound__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_note_spl_results_content_outbound__as_list, note_format="markdown", note_type="general", title=format_note_spl_results_title_outbound__as_list)

    return


@phantom.playbook_block()
def gen_spl_time_range_filters_inbound_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("gen_spl_time_range_filters_inbound_1() called")

    playbook_input_epochtime = phantom.collect2(container=container, datapath=["playbook_input:epochtime"])

    parameters = []

    # build parameters list for 'gen_spl_time_range_filters_inbound_1' call
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

    phantom.custom_function(custom_function="local/cbl_gen_spl_timerange_filter", parameters=parameters, name="gen_spl_time_range_filters_inbound_1", callback=format_spl_query_paloalto_inbound)

    return


@phantom.playbook_block()
def gen_spl_time_range_filters_outbound(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("gen_spl_time_range_filters_outbound() called")

    playbook_input_epochtime = phantom.collect2(container=container, datapath=["playbook_input:epochtime"])

    parameters = []

    # build parameters list for 'gen_spl_time_range_filters_outbound' call
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

    phantom.custom_function(custom_function="local/cbl_gen_spl_timerange_filter", parameters=parameters, name="gen_spl_time_range_filters_outbound", callback=format_spl_query_paloalto_outbound)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    run_spl_query_paloalto_inbound_result_data = phantom.collect2(container=container, datapath=["run_spl_query_paloalto_inbound:action_result.data.*._raw","run_spl_query_paloalto_inbound:action_result.data.*.is_traffic_allowed","run_spl_query_paloalto_inbound:action_result.data.*.is_traffic_blocked","run_spl_query_paloalto_inbound:action_result.data.*.inbound_traffic_detected"])
    run_spl_query_paloalto_outbound_result_data = phantom.collect2(container=container, datapath=["run_spl_query_paloalto_outbound:action_result.data.*._raw","run_spl_query_paloalto_outbound:action_result.data.*.is_traffic_allowed","run_spl_query_paloalto_outbound:action_result.data.*.is_traffic_blocked","run_spl_query_paloalto_outbound:action_result.data.*.outbound_traffic_detected"])

    run_spl_query_paloalto_inbound_result_item_0 = [item[0] for item in run_spl_query_paloalto_inbound_result_data]
    run_spl_query_paloalto_inbound_result_item_1 = [item[1] for item in run_spl_query_paloalto_inbound_result_data]
    run_spl_query_paloalto_inbound_result_item_2 = [item[2] for item in run_spl_query_paloalto_inbound_result_data]
    run_spl_query_paloalto_inbound_result_item_3 = [item[3] for item in run_spl_query_paloalto_inbound_result_data]
    run_spl_query_paloalto_outbound_result_item_0 = [item[0] for item in run_spl_query_paloalto_outbound_result_data]
    run_spl_query_paloalto_outbound_result_item_1 = [item[1] for item in run_spl_query_paloalto_outbound_result_data]
    run_spl_query_paloalto_outbound_result_item_2 = [item[2] for item in run_spl_query_paloalto_outbound_result_data]
    run_spl_query_paloalto_outbound_result_item_3 = [item[3] for item in run_spl_query_paloalto_outbound_result_data]

    output = {
        "spl_summary_inbound": run_spl_query_paloalto_inbound_result_item_0,
        "spl_summary_outbound": run_spl_query_paloalto_outbound_result_item_0,
        "spl_inbound_is_traffic_allowed": run_spl_query_paloalto_inbound_result_item_1,
        "spl_inbound_is_traffic_blocked": run_spl_query_paloalto_inbound_result_item_2,
        "spl_outbound_is_traffic_allowed": run_spl_query_paloalto_outbound_result_item_1,
        "spl_outbound_is_traffic_blocked": run_spl_query_paloalto_outbound_result_item_2,
        "spl_inbound_traffic_detected": run_spl_query_paloalto_inbound_result_item_3,
        "spl_outbound_traffic_detected": run_spl_query_paloalto_outbound_result_item_3,
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