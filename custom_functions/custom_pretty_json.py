def custom_pretty_json(inputJson=None, **kwargs):
    """
    This custom function pretty prints a JSON provided in input
    v1.0.11
    
    Args:
        inputJson: Input JSON object
    
    Returns a JSON-serializable object that implements the configured data paths:
        outputJson: Output JSON object
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import re
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    if inputJson:
        # remove any double quotes        
        if type(inputJson) is dict:
            phantom.debug("dict object was detected")
            outputs = {'outputJson': json.dumps(inputJson, indent=4)}
        else:
            phantom.debug("object is not a dict")
            outputs = {'outputJson': json.dumps(json.loads(inputJson), indent=4)}
            
    else:
         outputs = {'outputJson': json.dumps({'response': 'No results found'}, indent=4)}        

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
