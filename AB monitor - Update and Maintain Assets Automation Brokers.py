"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'update_assets_and_brokers' block
    update_assets_and_brokers(container=container)

    return

@phantom.playbook_block()
def update_assets_and_brokers(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_assets_and_brokers() called")

    playbook_input_mode = phantom.collect2(container=container, datapath=["playbook_input:mode"])
    playbook_input_assets_dict = phantom.collect2(container=container, datapath=["playbook_input:assets_dict"])
    playbook_input_brokers_dict_by_id = phantom.collect2(container=container, datapath=["playbook_input:brokers_dict_by_id"])
    playbook_input_brokers_dict_by_name = phantom.collect2(container=container, datapath=["playbook_input:brokers_dict_by_name"])

    playbook_input_mode_values = [item[0] for item in playbook_input_mode]
    playbook_input_assets_dict_values = [item[0] for item in playbook_input_assets_dict]
    playbook_input_brokers_dict_by_id_values = [item[0] for item in playbook_input_brokers_dict_by_id]
    playbook_input_brokers_dict_by_name_values = [item[0] for item in playbook_input_brokers_dict_by_name]

    parameters = []

    parameters.append({
        "mode": playbook_input_mode_values,
        "assets_dict": playbook_input_assets_dict_values,
        "brokers_dict_by_id": playbook_input_brokers_dict_by_id_values,
        "brokers_dict_by_name": playbook_input_brokers_dict_by_name_values,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="splunk-soar/update_assets_for_automation_brokers", parameters=parameters, name="update_assets_and_brokers", callback=format_response)

    return


@phantom.playbook_block()
def format_response(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_response() called")

    template = """%%\n{0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "update_assets_and_brokers:custom_function_result.data.response"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_response")

    add_note_2(container=container)

    return


@phantom.playbook_block()
def add_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_2() called")

    format_response__as_list = phantom.get_format_data(name="format_response__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_response__as_list, note_format="html", note_type="general", title="Assets Update and Maintain Response")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    update_assets_and_brokers__result = phantom.collect2(container=container, datapath=["update_assets_and_brokers:custom_function_result.data.update_count"])
    format_response__as_list = phantom.get_format_data(name="format_response__as_list")

    update_assets_and_brokers_data_update_count = [item[0] for item in update_assets_and_brokers__result]

    output = {
        "assets_update_results": format_response__as_list,
        "update_count": update_assets_and_brokers_data_update_count,
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