"""
Orchestrates the Threat Actor Recon use case, the master playbook runs all dependent playbooks accordingly
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'check_for_af_requirements' block
    check_for_af_requirements(container=container)

    return

def add_comment_invalid_af(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_invalid_af() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Artifact is invalid and does not contain a destinationHostname")

    return


def check_for_af_requirements(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("check_for_af_requirements() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="or",
        conditions=[
            ["artifact:*.cef.destinationAid", "!=", ""],
            ["artifact:*.cef.destinationHostName", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        run_progress_es_notable_event(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_comment_invalid_af(action=action, success=success, container=container, results=results, handle=handle)

    return


def filter_for_filehash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_for_filehash() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "!=", ""]
        ],
        name="filter_for_filehash:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        call_virustotal_filehash_reputation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def call_virustotal_filehash_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("call_virustotal_filehash_reputation() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/CBL - Threat Actor Recon - fileHash reputation VirusTotal", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/CBL - Threat Actor Recon - fileHash reputation VirusTotal", container=container, name="call_virustotal_filehash_reputation", callback=join_merge_virustotal_results)

    return


def format_summary_note_content_for_correlated_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_summary_note_content_for_correlated_results() called")

    template = """%%\n- **VirusTotal fileHash reputation:** {0} \n- **Inbound traffic correlation:** {1}\n- **Outbound traffic correlation:** {2}\n- **NetSkope user traces:** {3}\n- **Process hunt traces:** {4}\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "pretty_print_virustotal_results:custom_function_result.data.outputJson",
        "pretty_print_inbound_traffic_results:custom_function_result.data.outputJson",
        "pretty_print_outbound_traffic_results:custom_function_result.data.outputJson",
        "pretty_print_user_info_netskope:custom_function_result.data.outputJson",
        "pretty_prunt_hunt_processes:custom_function_result.data.outputJson"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_summary_note_content_for_correlated_results")

    add_note_summary_results(container=container)

    return


def add_note_summary_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_note_summary_results() called")

    format_summary_note_content_for_correlated_results__as_list = phantom.get_format_data(name="format_summary_note_content_for_correlated_results__as_list")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_summary_note_content_for_correlated_results__as_list, note_format="markdown", note_type="general", title="Summary correlation results")

    run_pending_es_notable(container=container)

    return


def filter_for_destinationaid(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_for_destinationaid() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAid", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        filter_for_aid(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationHostName", "!=", ""]
        ])

    # call connected blocks if condition 2 matched
    if found_match_2:
        filter_for_hostname(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def call_pb_crowdstrike_enrichment_from_aid(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("call_pb_crowdstrike_enrichment_from_aid() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.id"])
    filtered_artifact_0_data_filter_for_aid = phantom.collect2(container=container, datapath=["filtered-data:filter_for_aid:condition_1:artifact:*.cef.destinationAid"])

    container_artifact_header_item_0 = [item[0] for item in container_artifact_data]
    filtered_artifact_0__cef_destinationaid = [item[0] for item in filtered_artifact_0_data_filter_for_aid]

    inputs = {
        "artifactid": container_artifact_header_item_0,
        "inputfieldname": "device_id",
        "inputfieldvalue": filtered_artifact_0__cef_destinationaid,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/CBL - Threat Actor Recon - CrowdStrike enrichment", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/CBL - Threat Actor Recon - CrowdStrike enrichment", container=container, name="call_pb_crowdstrike_enrichment_from_aid", callback=join_call_spl_correlation_in_paloalto, inputs=inputs)

    return


def call_pb_crowdstrike_enrichment_from_hostname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("call_pb_crowdstrike_enrichment_from_hostname() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.id"])
    filtered_artifact_0_data_filter_for_hostname = phantom.collect2(container=container, datapath=["filtered-data:filter_for_hostname:condition_1:artifact:*.cef.destinationHostName"])

    container_artifact_header_item_0 = [item[0] for item in container_artifact_data]
    filtered_artifact_0__cef_destinationhostname = [item[0] for item in filtered_artifact_0_data_filter_for_hostname]

    inputs = {
        "artifactid": container_artifact_header_item_0,
        "inputfieldname": "hostname",
        "inputfieldvalue": filtered_artifact_0__cef_destinationhostname,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/CBL - Threat Actor Recon - CrowdStrike enrichment", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/CBL - Threat Actor Recon - CrowdStrike enrichment", container=container, name="call_pb_crowdstrike_enrichment_from_hostname", callback=join_call_spl_correlation_in_paloalto, inputs=inputs)

    return


def threat_actor_recon(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("threat_actor_recon() called")

    # set user and message variables for phantom.prompt call

    user = "Guilhem-m"
    message = """**Recon security event detected:**\n\n- **CrowdStrike device_id:** {0}\n- **HostName**: {1}\n- **IP Address:** {2}\n- **OS Platform:** {3}\n- **OS Version:** {4}\n- **Processes:** {5}\n\n**Network traffic summary:**\n\n- **Inbound traffic detected?:** {6}\n- **Inbound traffic allowed?:** {7}\n- **Inbound traffic blocked?:** {8}\n- **Outbound traffic detected?:** {9}\n- **Outbound traffic allowed?:** {10}\n- **Outbound traffic blocked?:** {11}\n\n**Correlation results:**\n\n{12}\n\n"""

    # parameter list for template variable replacement
    parameters = [
        "merge_destinationaid:custom_function_result.data.*.item",
        "merge_destinationhostname:custom_function_result.data.*.item",
        "merge_destinationaddress:custom_function_result.data.*.item",
        "merge_plateform_name:custom_function_result.data.*.item",
        "merge_os_version:custom_function_result.data.*.item",
        "artifact:*.cef.destinationProcessName",
        "call_spl_correlation_in_paloalto:playbook_output:spl_inbound_traffic_detected",
        "call_spl_correlation_in_paloalto:playbook_output:spl_inbound_is_traffic_allowed",
        "call_spl_correlation_in_paloalto:playbook_output:spl_inbound_is_traffic_blocked",
        "call_spl_correlation_in_paloalto:playbook_output:spl_outbound_traffic_detected",
        "call_spl_correlation_in_paloalto:playbook_output:spl_outbound_is_traffic_allowed",
        "call_spl_correlation_in_paloalto:playbook_output:spl_outbound_is_traffic_blocked",
        "format_summary_note_content_for_correlated_results:formatted_data.*"
    ]

    # responses
    response_types = [
        {
            "prompt": "Choose an action to be performed:",
            "options": {
                "type": "list",
                "choices": [
                    "Promote to case and send email to operation team",
                    "Promote to a case",
                    "Close this security event (false positive)"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=3600, name="threat_actor_recon", parameters=parameters, response_types=response_types, callback=check_for_prompt_response)

    return


def merge_destinationaid(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_destinationaid() called")

    call_pb_crowdstrike_enrichment_from_aid_output_destinationaid = phantom.collect2(container=container, datapath=["call_pb_crowdstrike_enrichment_from_aid:playbook_output:destinationaid"])
    call_pb_crowdstrike_enrichment_from_hostname_output_destinationaid = phantom.collect2(container=container, datapath=["call_pb_crowdstrike_enrichment_from_hostname:playbook_output:destinationaid"])

    call_pb_crowdstrike_enrichment_from_aid_output_destinationaid_values = [item[0] for item in call_pb_crowdstrike_enrichment_from_aid_output_destinationaid]
    call_pb_crowdstrike_enrichment_from_hostname_output_destinationaid_values = [item[0] for item in call_pb_crowdstrike_enrichment_from_hostname_output_destinationaid]

    parameters = []

    parameters.append({
        "input_1": call_pb_crowdstrike_enrichment_from_aid_output_destinationaid_values,
        "input_2": call_pb_crowdstrike_enrichment_from_hostname_output_destinationaid_values,
        "input_3": None,
        "input_4": None,
        "input_5": None,
        "input_6": None,
        "input_7": None,
        "input_8": None,
        "input_9": None,
        "input_10": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="merge_destinationaid", callback=merge_destinationhostname)

    return


def merge_destinationhostname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_destinationhostname() called")

    call_pb_crowdstrike_enrichment_from_aid_output_destinationhostname = phantom.collect2(container=container, datapath=["call_pb_crowdstrike_enrichment_from_aid:playbook_output:destinationhostname"])
    call_pb_crowdstrike_enrichment_from_hostname_output_destinationhostname = phantom.collect2(container=container, datapath=["call_pb_crowdstrike_enrichment_from_hostname:playbook_output:destinationhostname"])

    call_pb_crowdstrike_enrichment_from_aid_output_destinationhostname_values = [item[0] for item in call_pb_crowdstrike_enrichment_from_aid_output_destinationhostname]
    call_pb_crowdstrike_enrichment_from_hostname_output_destinationhostname_values = [item[0] for item in call_pb_crowdstrike_enrichment_from_hostname_output_destinationhostname]

    parameters = []

    parameters.append({
        "input_1": call_pb_crowdstrike_enrichment_from_aid_output_destinationhostname_values,
        "input_2": call_pb_crowdstrike_enrichment_from_hostname_output_destinationhostname_values,
        "input_3": None,
        "input_4": None,
        "input_5": None,
        "input_6": None,
        "input_7": None,
        "input_8": None,
        "input_9": None,
        "input_10": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="merge_destinationhostname", callback=merge_destinationaddress)

    return


def merge_destinationaddress(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_destinationaddress() called")

    call_pb_crowdstrike_enrichment_from_aid_output_destinationaddress = phantom.collect2(container=container, datapath=["call_pb_crowdstrike_enrichment_from_aid:playbook_output:destinationaddress"])
    call_pb_crowdstrike_enrichment_from_hostname_output_destinationaddress = phantom.collect2(container=container, datapath=["call_pb_crowdstrike_enrichment_from_hostname:playbook_output:destinationaddress"])

    call_pb_crowdstrike_enrichment_from_aid_output_destinationaddress_values = [item[0] for item in call_pb_crowdstrike_enrichment_from_aid_output_destinationaddress]
    call_pb_crowdstrike_enrichment_from_hostname_output_destinationaddress_values = [item[0] for item in call_pb_crowdstrike_enrichment_from_hostname_output_destinationaddress]

    parameters = []

    parameters.append({
        "input_1": call_pb_crowdstrike_enrichment_from_aid_output_destinationaddress_values,
        "input_2": call_pb_crowdstrike_enrichment_from_hostname_output_destinationaddress_values,
        "input_3": None,
        "input_4": None,
        "input_5": None,
        "input_6": None,
        "input_7": None,
        "input_8": None,
        "input_9": None,
        "input_10": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="merge_destinationaddress", callback=merge_plateform_name)

    return


def pretty_print_virustotal_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pretty_print_virustotal_results() called")

    merge_virustotal_results_data = phantom.collect2(container=container, datapath=["merge_virustotal_results:custom_function_result.data.*.item"])

    parameters = []

    # build parameters list for 'pretty_print_virustotal_results' call
    for merge_virustotal_results_data_item in merge_virustotal_results_data:
        parameters.append({
            "inputJson": merge_virustotal_results_data_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/cbl_pretty_json", parameters=parameters, name="pretty_print_virustotal_results", callback=merge_destinationaid)

    return


def pretty_print_inbound_traffic_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pretty_print_inbound_traffic_results() called")

    call_spl_correlation_in_paloalto_output_spl_summary_inbound = phantom.collect2(container=container, datapath=["call_spl_correlation_in_paloalto:playbook_output:spl_summary_inbound"])

    parameters = []

    # build parameters list for 'pretty_print_inbound_traffic_results' call
    for call_spl_correlation_in_paloalto_output_spl_summary_inbound_item in call_spl_correlation_in_paloalto_output_spl_summary_inbound:
        parameters.append({
            "inputJson": call_spl_correlation_in_paloalto_output_spl_summary_inbound_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/cbl_pretty_json", parameters=parameters, name="pretty_print_inbound_traffic_results", callback=pretty_print_outbound_traffic_results)

    return


def pretty_print_outbound_traffic_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pretty_print_outbound_traffic_results() called")

    call_spl_correlation_in_paloalto_output_spl_summary_outbound = phantom.collect2(container=container, datapath=["call_spl_correlation_in_paloalto:playbook_output:spl_summary_outbound"])

    parameters = []

    # build parameters list for 'pretty_print_outbound_traffic_results' call
    for call_spl_correlation_in_paloalto_output_spl_summary_outbound_item in call_spl_correlation_in_paloalto_output_spl_summary_outbound:
        parameters.append({
            "inputJson": call_spl_correlation_in_paloalto_output_spl_summary_outbound_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/cbl_pretty_json", parameters=parameters, name="pretty_print_outbound_traffic_results", callback=pretty_print_user_info_netskope)

    return


def filter_for_hostname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_for_hostname() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationHostName", "!=", ""]
        ],
        name="filter_for_hostname:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        call_pb_crowdstrike_enrichment_from_hostname(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def filter_for_aid(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_for_aid() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationHostName", "!=", ""]
        ],
        name="filter_for_aid:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        call_pb_crowdstrike_enrichment_from_aid(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def join_call_spl_correlation_in_paloalto(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_call_spl_correlation_in_paloalto() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_call_spl_correlation_in_paloalto_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_run_data(key="join_call_spl_correlation_in_paloalto_called", value="call_spl_correlation_in_paloalto")

    # call connected block "call_spl_correlation_in_paloalto"
    call_spl_correlation_in_paloalto(container=container, handle=handle)

    return


def call_spl_correlation_in_paloalto(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("call_spl_correlation_in_paloalto() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.epochtime"])
    call_pb_crowdstrike_enrichment_from_aid_output_destinationaddress = phantom.collect2(container=container, datapath=["call_pb_crowdstrike_enrichment_from_aid:playbook_output:destinationaddress"])
    call_pb_crowdstrike_enrichment_from_hostname_output_destinationaddress = phantom.collect2(container=container, datapath=["call_pb_crowdstrike_enrichment_from_hostname:playbook_output:destinationaddress"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    call_pb_crowdstrike_enrichment_from_aid_output_destinationaddress_values = [item[0] for item in call_pb_crowdstrike_enrichment_from_aid_output_destinationaddress]
    call_pb_crowdstrike_enrichment_from_hostname_output_destinationaddress_values = [item[0] for item in call_pb_crowdstrike_enrichment_from_hostname_output_destinationaddress]

    destinationaddress_combined_value = phantom.concatenate(call_pb_crowdstrike_enrichment_from_aid_output_destinationaddress_values, call_pb_crowdstrike_enrichment_from_hostname_output_destinationaddress_values)

    inputs = {
        "epochtime": container_artifact_cef_item_0,
        "destinationaddress": destinationaddress_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/CBL - Threat Actor Recon - SPL correlation input playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/CBL - Threat Actor Recon - SPL correlation input playbook", container=container, name="call_spl_correlation_in_paloalto", callback=call_pb_user_info_in_netskope, inputs=inputs)

    return


def check_for_filehash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("check_for_filehash() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        filter_for_filehash(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    format_no_filehash_summary(action=action, success=success, container=container, results=results, handle=handle)

    return


def format_no_filehash_summary(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_no_filehash_summary() called")

    template = """{\"response\": \"no fileHash available in artifact\"}"""

    # parameter list for template variable replacement
    parameters = []

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_no_filehash_summary")

    join_merge_virustotal_results(container=container)

    return


def join_merge_virustotal_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_merge_virustotal_results() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_merge_virustotal_results_called"):
        return

    if phantom.completed(playbook_names=["call_pb_crowdsttike_hunt_processes"]):
        # save the state that the joined function has now been called
        phantom.save_run_data(key="join_merge_virustotal_results_called", value="merge_virustotal_results")

        # call connected block "merge_virustotal_results"
        merge_virustotal_results(container=container, handle=handle)

    return


def merge_virustotal_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_virustotal_results() called")

    call_virustotal_filehash_reputation_output_summary = phantom.collect2(container=container, datapath=["call_virustotal_filehash_reputation:playbook_output:summary"])
    format_no_filehash_summary = phantom.get_format_data(name="format_no_filehash_summary")

    call_virustotal_filehash_reputation_output_summary_values = [item[0] for item in call_virustotal_filehash_reputation_output_summary]

    parameters = []

    parameters.append({
        "input_1": call_virustotal_filehash_reputation_output_summary_values,
        "input_2": format_no_filehash_summary,
        "input_3": None,
        "input_4": None,
        "input_5": None,
        "input_6": None,
        "input_7": None,
        "input_8": None,
        "input_9": None,
        "input_10": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="merge_virustotal_results", callback=pretty_print_virustotal_results)

    return


def merge_plateform_name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_plateform_name() called")

    call_pb_crowdstrike_enrichment_from_aid_output_plateform_name = phantom.collect2(container=container, datapath=["call_pb_crowdstrike_enrichment_from_aid:playbook_output:plateform_name"])
    call_pb_crowdstrike_enrichment_from_hostname_output_plateform_name = phantom.collect2(container=container, datapath=["call_pb_crowdstrike_enrichment_from_hostname:playbook_output:plateform_name"])

    call_pb_crowdstrike_enrichment_from_aid_output_plateform_name_values = [item[0] for item in call_pb_crowdstrike_enrichment_from_aid_output_plateform_name]
    call_pb_crowdstrike_enrichment_from_hostname_output_plateform_name_values = [item[0] for item in call_pb_crowdstrike_enrichment_from_hostname_output_plateform_name]

    parameters = []

    parameters.append({
        "input_1": call_pb_crowdstrike_enrichment_from_aid_output_plateform_name_values,
        "input_2": call_pb_crowdstrike_enrichment_from_hostname_output_plateform_name_values,
        "input_3": None,
        "input_4": None,
        "input_5": None,
        "input_6": None,
        "input_7": None,
        "input_8": None,
        "input_9": None,
        "input_10": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="merge_plateform_name", callback=merge_os_version)

    return


def merge_os_version(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_os_version() called")

    call_pb_crowdstrike_enrichment_from_aid_output_os_version = phantom.collect2(container=container, datapath=["call_pb_crowdstrike_enrichment_from_aid:playbook_output:os_version"])
    call_pb_crowdstrike_enrichment_from_hostname_output_os_version = phantom.collect2(container=container, datapath=["call_pb_crowdstrike_enrichment_from_hostname:playbook_output:os_version"])

    call_pb_crowdstrike_enrichment_from_aid_output_os_version_values = [item[0] for item in call_pb_crowdstrike_enrichment_from_aid_output_os_version]
    call_pb_crowdstrike_enrichment_from_hostname_output_os_version_values = [item[0] for item in call_pb_crowdstrike_enrichment_from_hostname_output_os_version]

    parameters = []

    parameters.append({
        "input_1": call_pb_crowdstrike_enrichment_from_aid_output_os_version_values,
        "input_2": call_pb_crowdstrike_enrichment_from_hostname_output_os_version_values,
        "input_3": None,
        "input_4": None,
        "input_5": None,
        "input_6": None,
        "input_7": None,
        "input_8": None,
        "input_9": None,
        "input_10": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="merge_os_version", callback=pretty_print_inbound_traffic_results)

    return


def check_for_prompt_response(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("check_for_prompt_response() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["threat_actor_recon:action_result.summary.responses.0", "==", "Promote to case and send email to operation team"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        promote_to_case_and_email(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["threat_actor_recon:action_result.summary.responses.0", "==", "Promote to a case"]
        ])

    # call connected blocks if condition 2 matched
    if found_match_2:
        promote_to_case_only(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 3
    found_match_3 = phantom.decision(
        container=container,
        conditions=[
            ["threat_actor_recon:action_result.summary.responses.0", "==", "Close this security event (false positive)"]
        ])

    # call connected blocks if condition 3 matched
    if found_match_3:
        run_close_es_notable(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def promote_to_case_only(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("promote_to_case_only() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.promote(container=container, template="Risk Response")

    container = phantom.get_container(container.get('id', None))

    return


def promote_to_case_and_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("promote_to_case_and_email() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.promote(container=container, template="Risk Response")

    container = phantom.get_container(container.get('id', None))

    format_email_body(container=container)

    return


def format_email_body(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_email_body() called")

    template = """%%\nA security event was detected for the following endpoint, please review and justify this actity by reponding to this email:\n\n- **CrowdStrike device_id:** {0}\n- **HostName**: {1}\n- **IP Address:** {2}\n- **OS Platform:** {3}\n- **OS Version:** {4}\n- **Processes:** {5}\n\nThis email was sent by Splunk SOAR automation.\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "merge_destinationaid:custom_function_result.data.*.item",
        "merge_destinationhostname:custom_function_result.data.*.item",
        "merge_destinationaddress:custom_function_result.data.*.item",
        "merge_plateform_name:custom_function_result.data.*.item",
        "merge_os_version:custom_function_result.data.*.item",
        "artifact:*.cef.destinationProcessName"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_email_body")

    format_email_subject(container=container)

    return


def check_for_os_team(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("check_for_os_team() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["merge_plateform_name:custom_function_result.data.*.item", "==", "Windows"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_dest_linux_team(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["merge_plateform_name:custom_function_result.data.*.item", "==", "Linux"]
        ])

    # call connected blocks if condition 2 matched
    if found_match_2:
        format_dest_windows_team(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 3
    format_dest_other(action=action, success=success, container=container, results=results, handle=handle)

    return


def format_dest_windows_team(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_dest_windows_team() called")

    template = """gmarchand@splunk.com"""

    # parameter list for template variable replacement
    parameters = []

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_dest_windows_team")

    join_merge_email_dest(container=container)

    return


def format_dest_linux_team(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_dest_linux_team() called")

    template = """gmarchand@splunk.com"""

    # parameter list for template variable replacement
    parameters = []

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_dest_linux_team")

    join_merge_email_dest(container=container)

    return


def format_dest_other(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_dest_other() called")

    template = """gmarchand@splunk.com"""

    # parameter list for template variable replacement
    parameters = []

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_dest_other")

    join_merge_email_dest(container=container)

    return


def join_merge_email_dest(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_merge_email_dest() called")

    if phantom.completed(action_names=["threat_actor_recon"]):
        # call connected block "merge_email_dest"
        merge_email_dest(container=container, handle=handle)

    return


def merge_email_dest(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_email_dest() called")

    format_dest_windows_team = phantom.get_format_data(name="format_dest_windows_team")
    format_dest_linux_team = phantom.get_format_data(name="format_dest_linux_team")
    format_dest_other = phantom.get_format_data(name="format_dest_other")

    parameters = []

    parameters.append({
        "input_1": format_dest_windows_team,
        "input_2": format_dest_linux_team,
        "input_3": format_dest_other,
        "input_4": None,
        "input_5": None,
        "input_6": None,
        "input_7": None,
        "input_8": None,
        "input_9": None,
        "input_10": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="merge_email_dest", callback=send_email_1)

    return


def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("send_email_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    merge_email_dest_data = phantom.collect2(container=container, datapath=["merge_email_dest:custom_function_result.data.*.item"])
    format_email_body__as_list = phantom.get_format_data(name="format_email_body__as_list")
    format_email_subject__as_list = phantom.get_format_data(name="format_email_subject__as_list")

    parameters = []

    # build parameters list for 'send_email_1' call
    for merge_email_dest_data_item in merge_email_dest_data:
        for format_email_body__item in format_email_body__as_list:
            for format_email_subject__item in format_email_subject__as_list:
                if merge_email_dest_data_item[0] is not None and format_email_body__item is not None:
                    parameters.append({
                        "to": merge_email_dest_data_item[0],
                        "body": format_email_body__item,
                        "from": "gmarchand@splunk.com",
                        "subject": format_email_subject__item,
                    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send email", parameters=parameters, name="send_email_1", assets=["internal_smtp"])

    return


def format_email_subject(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_email_subject() called")

    template = """%%\nSOC - security event detected for endpoint {0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "merge_destinationhostname:custom_function_result.data.*.item"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_email_subject")

    check_for_os_team(container=container)

    return


def call_pb_crowdstrike_list_processes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("call_pb_crowdstrike_list_processes() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/CBL - CrowdStrike - get running processes from aid", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/CBL - CrowdStrike - get running processes from aid", container=container)

    call_pb_crowdsttike_hunt_processes(container=container)

    return


def run_progress_es_notable_event(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_progress_es_notable_event() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.event_id"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    inputs = {
        "action": "progress",
        "event_id": container_artifact_cef_item_0,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/CBL - Update ES notable event", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/CBL - Update ES notable event", container=container, name="run_progress_es_notable_event", callback=filter_for_destinationaid, inputs=inputs)

    return


def run_close_es_notable(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_close_es_notable() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.event_id"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    inputs = {
        "action": "close",
        "event_id": container_artifact_cef_item_0,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/CBL - Update ES notable event", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/CBL - Update ES notable event", container=container, name="run_close_es_notable", callback=run_close_es_notable_callback, inputs=inputs)

    return


def run_close_es_notable_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_close_es_notable_callback() called")

    
    # Downstream End block cannot be called directly, since execution will call on_finish automatically.
    # Using placeholder callback function so child playbook is run synchronously.


    return


def run_pending_es_notable(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("run_pending_es_notable() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.event_id"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    inputs = {
        "action": "pending",
        "event_id": container_artifact_cef_item_0,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/CBL - Update ES notable event", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/CBL - Update ES notable event", container=container, name="run_pending_es_notable", callback=threat_actor_recon, inputs=inputs)

    return


def call_pb_user_info_in_netskope(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("call_pb_user_info_in_netskope() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.epochtime"])
    call_pb_crowdstrike_enrichment_from_aid_output_destinationhostname = phantom.collect2(container=container, datapath=["call_pb_crowdstrike_enrichment_from_aid:playbook_output:destinationhostname"])
    call_pb_crowdstrike_enrichment_from_hostname_output_destinationhostname = phantom.collect2(container=container, datapath=["call_pb_crowdstrike_enrichment_from_hostname:playbook_output:destinationhostname"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    call_pb_crowdstrike_enrichment_from_aid_output_destinationhostname_values = [item[0] for item in call_pb_crowdstrike_enrichment_from_aid_output_destinationhostname]
    call_pb_crowdstrike_enrichment_from_hostname_output_destinationhostname_values = [item[0] for item in call_pb_crowdstrike_enrichment_from_hostname_output_destinationhostname]

    destinationhostname_combined_value = phantom.concatenate(call_pb_crowdstrike_enrichment_from_aid_output_destinationhostname_values, call_pb_crowdstrike_enrichment_from_hostname_output_destinationhostname_values)

    inputs = {
        "epochtime": container_artifact_cef_item_0,
        "destinationhostname": destinationhostname_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/CBL - Threat Actor Recon - Netskope user info", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/CBL - Threat Actor Recon - Netskope user info", container=container, name="call_pb_user_info_in_netskope", callback=call_pb_crowdstrike_list_processes, inputs=inputs)

    return


def pretty_print_user_info_netskope(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pretty_print_user_info_netskope() called")

    call_pb_user_info_in_netskope_output_spl_summary_user_info_netskope = phantom.collect2(container=container, datapath=["call_pb_user_info_in_netskope:playbook_output:spl_summary_user_info_netskope"])

    parameters = []

    # build parameters list for 'pretty_print_user_info_netskope' call
    for call_pb_user_info_in_netskope_output_spl_summary_user_info_netskope_item in call_pb_user_info_in_netskope_output_spl_summary_user_info_netskope:
        parameters.append({
            "inputJson": call_pb_user_info_in_netskope_output_spl_summary_user_info_netskope_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/cbl_pretty_json", parameters=parameters, name="pretty_print_user_info_netskope", callback=pretty_prunt_hunt_processes)

    return


def call_pb_crowdsttike_hunt_processes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("call_pb_crowdsttike_hunt_processes() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/CBL - Threat Actor Recon - CrowdStrike hunt process automation", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/CBL - Threat Actor Recon - CrowdStrike hunt process automation", container=container, name="call_pb_crowdsttike_hunt_processes", callback=check_for_filehash)

    return


def pretty_prunt_hunt_processes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pretty_prunt_hunt_processes() called")

    call_pb_crowdsttike_hunt_processes_output_spl_summary_hunt_processes = phantom.collect2(container=container, datapath=["call_pb_crowdsttike_hunt_processes:playbook_output:spl_summary_hunt_processes"])

    parameters = []

    # build parameters list for 'pretty_prunt_hunt_processes' call
    for call_pb_crowdsttike_hunt_processes_output_spl_summary_hunt_processes_item in call_pb_crowdsttike_hunt_processes_output_spl_summary_hunt_processes:
        parameters.append({
            "inputJson": call_pb_crowdsttike_hunt_processes_output_spl_summary_hunt_processes_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/cbl_pretty_json", parameters=parameters, name="pretty_prunt_hunt_processes", callback=format_summary_note_content_for_correlated_results)

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

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

    return