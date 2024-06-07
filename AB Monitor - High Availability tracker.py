"""
This platybook is designed to handle High Availability for the SOAR Automation Broker:\n- Retrieves the list of brokers and build dictionnaries with their status, you scope pools of two or more Automation Brokers.\n- Retrieve the list of associated Assets\n- Act and trace, if an Automation Broker is detected as non availablable, update any asset to the next available broker.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'get_automation_broker_statuses' block
    get_automation_broker_statuses(container=container)
    # call 'get_assets_and_brokers_association' block
    get_assets_and_brokers_association(container=container)

    return

@phantom.playbook_block()
def get_automation_broker_statuses(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_automation_broker_statuses() called")

    inputs = {
        "selectable_brokers": ["UK-AB-001,UK-AB-002"],
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "splunk-soar/AB-monitor - Get Automation Broker statuses", returns the playbook_run_id
    playbook_run_id = phantom.playbook("splunk-soar/AB-monitor - Get Automation Broker statuses", container=container, name="get_automation_broker_statuses", callback=decide_on_offline_brokers_detected, inputs=inputs)

    return


@phantom.playbook_block()
def get_assets_and_brokers_association(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_assets_and_brokers_association() called")

    inputs = {}

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "splunk-soar/AB monitor - get Assets and Automation Brokers", returns the playbook_run_id
    playbook_run_id = phantom.playbook("splunk-soar/AB monitor - get Assets and Automation Brokers", container=container, name="get_assets_and_brokers_association", callback=join_update_and_maintain_assets, inputs=inputs)

    return


@phantom.playbook_block()
def join_update_and_maintain_assets(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_update_and_maintain_assets() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_update_and_maintain_assets_called"):
        return

    if phantom.completed(playbook_names=["get_assets_and_brokers_association", "get_automation_broker_statuses"]):
        # save the state that the joined function has now been called
        phantom.save_run_data(key="join_update_and_maintain_assets_called", value="update_and_maintain_assets")

        # call connected block "update_and_maintain_assets"
        update_and_maintain_assets(container=container, handle=handle)

    return


@phantom.playbook_block()
def update_and_maintain_assets(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_and_maintain_assets() called")

    get_assets_and_brokers_association_output_assets_dict = phantom.collect2(container=container, datapath=["get_assets_and_brokers_association:playbook_output:assets_dict"])
    get_automation_broker_statuses_output_brokers_dict_by_id = phantom.collect2(container=container, datapath=["get_automation_broker_statuses:playbook_output:brokers_dict_by_id"])
    get_automation_broker_statuses_output_brokers_dict_by_name = phantom.collect2(container=container, datapath=["get_automation_broker_statuses:playbook_output:brokers_dict_by_name"])

    get_assets_and_brokers_association_output_assets_dict_values = [item[0] for item in get_assets_and_brokers_association_output_assets_dict]
    get_automation_broker_statuses_output_brokers_dict_by_id_values = [item[0] for item in get_automation_broker_statuses_output_brokers_dict_by_id]
    get_automation_broker_statuses_output_brokers_dict_by_name_values = [item[0] for item in get_automation_broker_statuses_output_brokers_dict_by_name]

    inputs = {
        "mode": ["live"],
        "assets_dict": get_assets_and_brokers_association_output_assets_dict_values,
        "brokers_dict_by_id": get_automation_broker_statuses_output_brokers_dict_by_id_values,
        "brokers_dict_by_name": get_automation_broker_statuses_output_brokers_dict_by_name_values,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "splunk-soar/AB monitor - Update and Maintain Assets Automation Brokers", returns the playbook_run_id
    playbook_run_id = phantom.playbook("splunk-soar/AB monitor - Update and Maintain Assets Automation Brokers", container=container, name="update_and_maintain_assets", callback=decide_on_changes_detected, inputs=inputs)

    return


@phantom.playbook_block()
def decide_on_changes_detected(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decide_on_changes_detected() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["update_and_maintain_assets:playbook_output:update_count", ">", 0]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_comment_changes_detected(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    create_af_summary_no_changes(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def format_comment_changes_detected(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_comment_changes_detected() called")

    template = """%%\nHigh availability automation brokers changes were detected: {0} active updates were achieved\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "update_and_maintain_assets:playbook_output:update_count"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_comment_changes_detected")

    add_comment_changes_detected(container=container)

    return


@phantom.playbook_block()
def format_comment_offline_broker_detected(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_comment_offline_broker_detected() called")

    template = """%%\nAlert: {0} offline Automation Broker(s) detected, list of offline brokers: {1} - Actions will be taken if there are remaining brokers available in the pool.\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "get_automation_broker_statuses:playbook_output:brokers_inactive_count",
        "get_automation_broker_statuses:playbook_output:brokers_inactive_list"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_comment_offline_broker_detected")

    add_comment_offline_broker_detected(container=container)

    return


@phantom.playbook_block()
def add_comment_offline_broker_detected(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_offline_broker_detected() called")

    format_comment_offline_broker_detected__as_list = phantom.get_format_data(name="format_comment_offline_broker_detected__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_comment_offline_broker_detected__as_list)

    join_update_and_maintain_assets(container=container)

    return


@phantom.playbook_block()
def decide_on_offline_brokers_detected(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decide_on_offline_brokers_detected() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["get_automation_broker_statuses:playbook_output:brokers_inactive_count", ">", 0]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_comment_offline_broker_detected(action=action, success=success, container=container, results=results, handle=handle)
        create_af_brokers_offline_info(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    format_comment_brokers_online(action=action, success=success, container=container, results=results, handle=handle)
    create_af_brokers_online_info(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def add_comment_changes_detected(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_changes_detected() called")

    format_comment_changes_detected__as_list = phantom.get_format_data(name="format_comment_changes_detected__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_comment_changes_detected__as_list)

    create_af_summary_changes_detected(container=container)

    return


@phantom.playbook_block()
def format_comment_brokers_online(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_comment_brokers_online() called")

    template = """%%\nInfo: {0} online Automation Broker(s) detected, list of online brokers: {1} - No Actions required.\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "get_automation_broker_statuses:playbook_output:brokers_active_count",
        "get_automation_broker_statuses:playbook_output:brokers_active_list"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_comment_brokers_online")

    add_comment_brokers_online(container=container)

    return


@phantom.playbook_block()
def add_comment_brokers_online(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_brokers_online() called")

    format_comment_brokers_online__as_list = phantom.get_format_data(name="format_comment_brokers_online__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_comment_brokers_online__as_list)

    join_update_and_maintain_assets(container=container)

    return


@phantom.playbook_block()
def create_af_summary_no_changes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("create_af_summary_no_changes() called")

    id_value = container.get("id", None)
    update_and_maintain_assets_output_assets_update_results = phantom.collect2(container=container, datapath=["update_and_maintain_assets:playbook_output:assets_update_results"])

    parameters = []

    # build parameters list for 'create_af_summary_no_changes' call
    for update_and_maintain_assets_output_assets_update_results_item in update_and_maintain_assets_output_assets_update_results:
        parameters.append({
            "name": "Summary Actions",
            "tags": None,
            "label": "abmon",
            "severity": "Low",
            "cef_field": "assets_update_results",
            "cef_value": update_and_maintain_assets_output_assets_update_results_item[0],
            "container": id_value,
            "input_json": None,
            "cef_data_type": None,
            "run_automation": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="create_af_summary_no_changes")

    return


@phantom.playbook_block()
def create_af_summary_changes_detected(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("create_af_summary_changes_detected() called")

    id_value = container.get("id", None)
    update_and_maintain_assets_output_assets_update_results = phantom.collect2(container=container, datapath=["update_and_maintain_assets:playbook_output:assets_update_results"])

    parameters = []

    # build parameters list for 'create_af_summary_changes_detected' call
    for update_and_maintain_assets_output_assets_update_results_item in update_and_maintain_assets_output_assets_update_results:
        parameters.append({
            "name": "Summary Actions",
            "tags": None,
            "label": "abmon",
            "severity": "High",
            "cef_field": "assets_update_results",
            "cef_value": update_and_maintain_assets_output_assets_update_results_item[0],
            "container": id_value,
            "input_json": None,
            "cef_data_type": None,
            "run_automation": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="create_af_summary_changes_detected")

    return


@phantom.playbook_block()
def create_af_brokers_online_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("create_af_brokers_online_info() called")

    id_value = container.get("id", None)
    get_automation_broker_statuses_output_brokers_active_list = phantom.collect2(container=container, datapath=["get_automation_broker_statuses:playbook_output:brokers_active_list"])

    parameters = []

    # build parameters list for 'create_af_brokers_online_info' call
    for get_automation_broker_statuses_output_brokers_active_list_item in get_automation_broker_statuses_output_brokers_active_list:
        parameters.append({
            "name": "Brokers Online information",
            "tags": None,
            "label": "abmon",
            "severity": "Low",
            "cef_field": "brokers_active_list",
            "cef_value": get_automation_broker_statuses_output_brokers_active_list_item[0],
            "container": id_value,
            "input_json": None,
            "cef_data_type": None,
            "run_automation": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="create_af_brokers_online_info", callback=set_severity_low)

    return


@phantom.playbook_block()
def create_af_brokers_offline_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("create_af_brokers_offline_info() called")

    id_value = container.get("id", None)
    get_automation_broker_statuses_output_brokers_inactive_list = phantom.collect2(container=container, datapath=["get_automation_broker_statuses:playbook_output:brokers_inactive_list"])

    parameters = []

    # build parameters list for 'create_af_brokers_offline_info' call
    for get_automation_broker_statuses_output_brokers_inactive_list_item in get_automation_broker_statuses_output_brokers_inactive_list:
        parameters.append({
            "name": "Brokers Offline information",
            "tags": None,
            "label": "abmon",
            "severity": "High",
            "cef_field": "brokers_inactive_list",
            "cef_value": get_automation_broker_statuses_output_brokers_inactive_list_item[0],
            "container": id_value,
            "input_json": None,
            "cef_data_type": None,
            "run_automation": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="create_af_brokers_offline_info", callback=set_severity_high)

    return


@phantom.playbook_block()
def set_severity_high(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_severity_high() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="high")

    container = phantom.get_container(container.get('id', None))

    set_sensivity_white(container=container)

    return


@phantom.playbook_block()
def set_severity_low(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_severity_low() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="low")

    container = phantom.get_container(container.get('id', None))

    set_sensitivity_white(container=container)

    return


@phantom.playbook_block()
def set_sensivity_white(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_sensivity_white() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_sensitivity(container=container, sensitivity="white")

    container = phantom.get_container(container.get('id', None))

    join_update_and_maintain_assets(container=container)

    return


@phantom.playbook_block()
def set_sensitivity_white(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_sensitivity_white() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_sensitivity(container=container, sensitivity="white")

    container = phantom.get_container(container.get('id', None))

    join_update_and_maintain_assets(container=container)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    update_and_maintain_assets_output_assets_update_results = phantom.collect2(container=container, datapath=["update_and_maintain_assets:playbook_output:assets_update_results"])

    update_and_maintain_assets_output_assets_update_results_values = [item[0] for item in update_and_maintain_assets_output_assets_update_results]

    output = {
        "assets_update_results": update_and_maintain_assets_output_assets_update_results_values,
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