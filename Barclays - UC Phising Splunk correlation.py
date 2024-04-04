"""
This playbook is designed to be triggered by the master playbook, it will perform several correlation in Splunk data sources to be consolidated for the analyst decision purposes
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'format_spl_query_proxy_search' block
    format_spl_query_proxy_search(container=container)
    # call 'format_spl_query_email_search' block
    format_spl_query_email_search(container=container)

    return

@phantom.playbook_block()
def run_spl_query_proxy_search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_spl_query_proxy_search() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_spl_query_proxy_search__as_list = phantom.get_format_data(name="format_spl_query_proxy_search__as_list")

    parameters = []

    # build parameters list for 'run_spl_query_proxy_search' call
    for format_spl_query_proxy_search__item in format_spl_query_proxy_search__as_list:
        if format_spl_query_proxy_search__item is not None:
            parameters.append({
                "command": "search",
                "search_mode": "smart",
                "query": format_spl_query_proxy_search__item,
                "start_time": "-24h",
                "end_time": "now",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_spl_query_proxy_search", assets=["splunk"], callback=add_comment_proxy_search_results)

    return


@phantom.playbook_block()
def format_spl_query_proxy_search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_spl_query_proxy_search() called")

    template = """%%\n(index=gis_bcoat sourcetype=bcoat_proxysg) url=\"{0}\"\n| stats dc(dest_host) as dest_count, values(category) as categories, values(rule_name) as rules, values(http_referrer) as referrers\n| tojson\n| rename _raw as summary\n%%"""

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

    phantom.format(container=container, template=template, parameters=parameters, name="format_spl_query_proxy_search")

    run_spl_query_proxy_search(container=container)

    return


@phantom.playbook_block()
def add_comment_proxy_search_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_proxy_search_results() called")

    run_spl_query_proxy_search_result_data = phantom.collect2(container=container, datapath=["run_spl_query_proxy_search:action_result.data.*.summary"], action_results=results)

    run_spl_query_proxy_search_result_item_0 = [item[0] for item in run_spl_query_proxy_search_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=run_spl_query_proxy_search_result_item_0)

    format_note_spl_results_title_proxy_search(container=container)

    return


@phantom.playbook_block()
def format_note_spl_results_title_proxy_search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_note_spl_results_title_proxy_search() called")

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

    phantom.format(container=container, template=template, parameters=parameters, name="format_note_spl_results_title_proxy_search")

    format_note_spl_results_content_proxy_search(container=container)

    return


@phantom.playbook_block()
def format_note_spl_results_content_proxy_search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_note_spl_results_content_proxy_search() called")

    template = """%%\n{0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "run_spl_query_proxy_search:action_result.data.*._raw"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_note_spl_results_content_proxy_search")

    add_note_spl_results_proxy_search(container=container)

    return


@phantom.playbook_block()
def add_note_spl_results_proxy_search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_note_spl_results_proxy_search() called")

    format_note_spl_results_content_proxy_search__as_list = phantom.get_format_data(name="format_note_spl_results_content_proxy_search__as_list")
    format_note_spl_results_title_proxy_search__as_list = phantom.get_format_data(name="format_note_spl_results_title_proxy_search__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_note_spl_results_content_proxy_search__as_list, note_format="markdown", note_type="general", title=format_note_spl_results_title_proxy_search__as_list)

    return


@phantom.playbook_block()
def format_spl_query_email_search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_spl_query_email_search() called")

    template = """%%\n(index=exchange_mt) subject=\"{0}\"\n| stats dc(recipient) as count_recipients, values(action) as actions\n| tojson\n| rename _raw as summary\n%%"""

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

    phantom.format(container=container, template=template, parameters=parameters, name="format_spl_query_email_search")

    run_spl_query_email_search(container=container)

    return


@phantom.playbook_block()
def run_spl_query_email_search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_spl_query_email_search() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_spl_query_email_search__as_list = phantom.get_format_data(name="format_spl_query_email_search__as_list")

    parameters = []

    # build parameters list for 'run_spl_query_email_search' call
    for format_spl_query_email_search__item in format_spl_query_email_search__as_list:
        if format_spl_query_email_search__item is not None:
            parameters.append({
                "command": "search",
                "search_mode": "smart",
                "query": format_spl_query_email_search__item,
                "start_time": "-24h",
                "end_time": "now",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_spl_query_email_search", assets=["splunk"], callback=add_comment_email_search_results)

    return


@phantom.playbook_block()
def add_comment_email_search_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_email_search_results() called")

    run_spl_query_email_search_result_data = phantom.collect2(container=container, datapath=["run_spl_query_email_search:action_result.data.*.summary"], action_results=results)

    run_spl_query_email_search_result_item_0 = [item[0] for item in run_spl_query_email_search_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=run_spl_query_email_search_result_item_0)

    format_note_spl_results_title_email_search(container=container)

    return


@phantom.playbook_block()
def format_note_spl_results_title_email_search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_note_spl_results_title_email_search() called")

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

    phantom.format(container=container, template=template, parameters=parameters, name="format_note_spl_results_title_email_search")

    format_note_spl_results_content_email_search(container=container)

    return


@phantom.playbook_block()
def format_note_spl_results_content_email_search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_note_spl_results_content_email_search() called")

    template = """%%\n{0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "run_spl_query_email_search:action_result.data.*._raw"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_note_spl_results_content_email_search")

    add_note_spl_results_email_search(container=container)

    return


@phantom.playbook_block()
def add_note_spl_results_email_search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_note_spl_results_email_search() called")

    format_note_spl_results_content_email_search__as_list = phantom.get_format_data(name="format_note_spl_results_content_email_search__as_list")
    format_note_spl_results_title_email_search__as_list = phantom.get_format_data(name="format_note_spl_results_title_email_search__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_note_spl_results_content_email_search__as_list, note_format="markdown", note_type="general", title=format_note_spl_results_title_email_search__as_list)

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