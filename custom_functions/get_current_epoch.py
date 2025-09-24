def get_current_epoch(**kwargs):
    """
    Returns a JSON-serializable object that implements the configured data paths:
        current_epoch
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    import time
    current_epoch = time.time()
    outputs = {"current_epoch": current_epoch}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
