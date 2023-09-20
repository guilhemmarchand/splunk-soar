def cbl_gen_spl_timerange_filter(epochtime=None, earliest_sec_reduce=None, latest_sec_increase=None, **kwargs):
    """
    This custom function is designed to generate a range of epoch time filters (earliest and latest) based on provided options
    
    Args:
        epochtime
        earliest_sec_reduce
        latest_sec_increase
    
    Returns a JSON-serializable object that implements the configured data paths:
        earliest_epoch: Earliest epoch
        latest_epoch: Latest epoch
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    if epochtime:
        phantom.debug("event_time={0}".format(str(epochtime)))
        
        if earliest_sec_reduce:
            earliest_epoch = int(epochtime) - int(earliest_sec_reduce)
            phantom.debug("earliest_epoch={0}".format(str(earliest_epoch)))
            
        if latest_sec_increase:
            latest_epoch = int(epochtime) + int(latest_sec_increase)
            phantom.debug("latest_epoch={0}".format(str(latest_epoch)))

        outputs = {'earliest_epoch': str(earliest_epoch), 'latest_epoch': str(latest_epoch)}
        
    else:
        phantom.error("epochtime was not provided properly!")
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
