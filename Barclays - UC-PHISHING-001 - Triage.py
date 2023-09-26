"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'check_for_af_requirements' block
    check_for_af_requirements(container=container)

    return

@phantom.playbook_block()
def check_for_af_requirements(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("check_for_af_requirements() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="or",
        conditions=[
            ["artifact:*.cef.fileHashMd5", "!=", ""],
            ["artifact:*.cef.sourceAddress", "!=", ""],
            ["", "!=", "artifact:*.cef.requestURL"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        return

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return