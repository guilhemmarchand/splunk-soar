def upload_file_from_url(fileUrl=None, container_id=None, **kwargs):
    """
    This custom function gets a file through the provided  URL and adds it to the container.
    
    Args:
        fileUrl: File URL
        container_id: Container ID
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import os
    from urllib.parse import urlparse
    import hashlib    
    
    outputs = {}
    
    # Write your custom code here...
    import phantom.vault as ph_vault
        
    if fileUrl:
        
        # parse the url to retrieve the file name
        u = urlparse(fileUrl)
        try:
            fileName = os.path.basename(u.path)
        except Exception as e:
            fileName = hashlib.md5(fileUrl.encode('utf-8')).hexdigest()

        try:
            r = phantom.requests.get(fileUrl)
            ph_vault.Vault.create_attachment(file_contents=r.content, file_name=fileName, container_id=container_id)
            phantom.debug("Successfully downloaded the file and uploaded to the container")
        except Exception as e:
            phantom.debug("Failed to perform the operation with Exception=\"{0}\"".format(e))
            
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
