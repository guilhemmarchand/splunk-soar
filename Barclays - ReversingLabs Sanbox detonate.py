"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'get_cofense_message_metadata' block
    get_cofense_message_metadata(container=container)

    return

@phantom.playbook_block()
def get_cofense_message_metadata(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_cofense_message_metadata() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_input_message_id = phantom.collect2(container=container, datapath=["playbook_input:message_id"])
    playbook_input_recipient = phantom.collect2(container=container, datapath=["playbook_input:recipient"])

    parameters = []

    # build parameters list for 'get_cofense_message_metadata' call
    for playbook_input_message_id_item in playbook_input_message_id:
        for playbook_input_recipient_item in playbook_input_recipient:
            if playbook_input_message_id_item[0] is not None and playbook_input_recipient_item[0] is not None:
                parameters.append({
                    "internet_message_id": playbook_input_message_id_item[0],
                    "recipient_address": playbook_input_recipient_item[0],
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get message metadata", parameters=parameters, name="get_cofense_message_metadata", assets=["cofense_vision"], callback=get_message_cofense_message_attachments)

    return


@phantom.playbook_block()
def get_message_cofense_message_attachments(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_message_cofense_message_attachments() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_cofense_message_metadata_result_data = phantom.collect2(container=container, datapath=["get_cofense_message_metadata:action_result.data.*.attachments.*.md5","get_cofense_message_metadata:action_result.data.*.attachments.*.sha256","get_cofense_message_metadata:action_result.data.*.attachments.*.filename","get_cofense_message_metadata:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_message_cofense_message_attachments' call
    for get_cofense_message_metadata_result_item in get_cofense_message_metadata_result_data:
        if get_cofense_message_metadata_result_item[2] is not None:
            parameters.append({
                "md5": get_cofense_message_metadata_result_item[0],
                "sha256": get_cofense_message_metadata_result_item[1],
                "filename": get_cofense_message_metadata_result_item[2],
                "context": {'artifact_id': get_cofense_message_metadata_result_item[3]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get message attachment", parameters=parameters, name="get_message_cofense_message_attachments", assets=["cofense_vision"], callback=detonate_file_reversinglabs)

    return


@phantom.playbook_block()
def detonate_file_reversinglabs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("detonate_file_reversinglabs() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_message_cofense_message_attachments_result_data = phantom.collect2(container=container, datapath=["get_message_cofense_message_attachments:action_result.data.*.vault_id","get_message_cofense_message_attachments:action_result.parameter.filename","get_message_cofense_message_attachments:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'detonate_file_reversinglabs' call
    for get_message_cofense_message_attachments_result_item in get_message_cofense_message_attachments_result_data:
        if get_message_cofense_message_attachments_result_item[0] is not None:
            parameters.append({
                "vault_id": get_message_cofense_message_attachments_result_item[0],
                "file_name": get_message_cofense_message_attachments_result_item[1],
                "context": {'artifact_id': get_message_cofense_message_attachments_result_item[2]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate file", parameters=parameters, name="detonate_file_reversinglabs", assets=["reversinglabs_appliance"])

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    detonate_file_reversinglabs_result_data = phantom.collect2(container=container, datapath=["detonate_file_reversinglabs:action_result.status","detonate_file_reversinglabs:action_result.summary","detonate_file_reversinglabs:action_result.message"])

    detonate_file_reversinglabs_result_item_0 = [item[0] for item in detonate_file_reversinglabs_result_data]
    detonate_file_reversinglabs_result_item_1 = [item[1] for item in detonate_file_reversinglabs_result_data]
    detonate_file_reversinglabs_result_message = [item[2] for item in detonate_file_reversinglabs_result_data]

    output = {
        "status": detonate_file_reversinglabs_result_item_0,
        "summary": detonate_file_reversinglabs_result_item_1,
        "message": detonate_file_reversinglabs_result_message,
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