"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'get_automation_brokers' block
    get_automation_brokers(container=container)

    return

@phantom.playbook_block()
def get_automation_brokers(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_automation_brokers() called")

    playbook_input_selectable_brokers = phantom.collect2(container=container, datapath=["playbook_input:selectable_brokers"])

    parameters = []

    # build parameters list for 'get_automation_brokers' call
    for playbook_input_selectable_brokers_item in playbook_input_selectable_brokers:
        parameters.append({
            "selectable_brokers": playbook_input_selectable_brokers_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="splunk-soar/get_automation_brokers", parameters=parameters, name="get_automation_brokers", callback=format_dict_by_id)

    return


@phantom.playbook_block()
def format_dict_by_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_dict_by_id() called")

    template = """%%\n{0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "get_automation_brokers:custom_function_result.data.brokers_dict_by_id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_dict_by_id")

    format_dict_by_name(container=container)

    return


@phantom.playbook_block()
def format_dict_by_name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_dict_by_name() called")

    template = """%%\n{0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "get_automation_brokers:custom_function_result.data.brokers_dict_by_name"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_dict_by_name")

    add_note_2(container=container)

    return


@phantom.playbook_block()
def add_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_2() called")

    format_dict_by_id__as_list = phantom.get_format_data(name="format_dict_by_id__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_dict_by_id__as_list, note_format="markdown", note_type="general", title="Automation Brokers dict by ID")

    add_note_3(container=container)

    return


@phantom.playbook_block()
def add_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_3() called")

    format_dict_by_name__as_list = phantom.get_format_data(name="format_dict_by_name__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_dict_by_name__as_list, note_format="markdown", note_type="general", title="Automation Brokers dict by Name")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    get_automation_brokers__result = phantom.collect2(container=container, datapath=["get_automation_brokers:custom_function_result.data.brokers_active_list","get_automation_brokers:custom_function_result.data.brokers_active_count","get_automation_brokers:custom_function_result.data.brokers_inactive_list","get_automation_brokers:custom_function_result.data.brokers_inactive_count"])
    format_dict_by_id__as_list = phantom.get_format_data(name="format_dict_by_id__as_list")
    format_dict_by_name__as_list = phantom.get_format_data(name="format_dict_by_name__as_list")

    get_automation_brokers_data_brokers_active_list = [item[0] for item in get_automation_brokers__result]
    get_automation_brokers_data_brokers_active_count = [item[1] for item in get_automation_brokers__result]
    get_automation_brokers_data_brokers_inactive_list = [item[2] for item in get_automation_brokers__result]
    get_automation_brokers_data_brokers_inactive_count = [item[3] for item in get_automation_brokers__result]

    output = {
        "brokers_dict_by_id": format_dict_by_id__as_list,
        "brokers_dict_by_name": format_dict_by_name__as_list,
        "brokers_active_list": get_automation_brokers_data_brokers_active_list,
        "brokers_active_count": get_automation_brokers_data_brokers_active_count,
        "brokers_inactive_list": get_automation_brokers_data_brokers_inactive_list,
        "brokers_inactive_count": get_automation_brokers_data_brokers_inactive_count,
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