def get_automation_brokers(selectable_brokers=None, **kwargs):
    """
    This function is designed to be used for the purposes of handling High Availability concepts with the Automation Brokers. It returns various dicts and information regarding the Automation Brokers and their current status.
    
    Args:
        selectable_brokers: Restrict to a given list of selectable brokers, to manage a couple of active / active or active / passive brokers, add the brokers names as a CSV string.
    
    Returns a JSON-serializable object that implements the configured data paths:
        brokers_dict_by_id
        brokers_dict_by_name
        brokers_active_list: The list of active brokers.
        brokers_active_count: Count of active brokers
        brokers_inactive_list: The list of inactive brokers.
        brokers_inactive_count: Count of inactive brokers
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    url = phantom.build_phantom_rest_url('automation_proxy')
    params = {'pretty': True, 'page_size': 0}
    params = {
        'pretty': True,
        'page_size': 0,
        'sort': 'create_time',
        'order': 'desc'
    }

    phantom.debug(f'Starting get Automation Brokers, requesting endpoint="/rest/automation_proxy"')

    # Function to make the request and handle pagination
    def make_request_and_get_data(url, params):
        res = phantom.requests.get(uri=url, params=params, verify=False).json()
        data = res.get('data', [])
        num_pages = int(res.get('num_pages', 1))
        for page in range(1, num_pages):
            params['page'] = page
            res = phantom.requests.get(uri=url, params=params, verify=False).json()
            data.extend(res.get('data', []))
        return data

    all_ab_raw_list = make_request_and_get_data(url, params)

    # Process the retrieved data
    brokers_dict_by_name = {}
    brokers_dict_by_id = {}
    brokers_active_list = []
    brokers_inactive_list = []
    
    # Parse selectable brokers list
    if selectable_brokers:
        phantom.debug(f'selectable_brokers: {selectable_brokers}')
        selectable_brokers_list = [broker.strip() for broker in selectable_brokers.split(",")]
    else:
        selectable_brokers_list = []
                                                              
    for ab in all_ab_raw_list:
        ab_name = ab.get("name")
        
        # If selectable_brokers_list is not empty, check if the broker is in the list
        if selectable_brokers_list and ab_name not in selectable_brokers_list:
            continue
        
        ab_id = ab.get("id")
        ab_last_seen_status = ab.get("_pretty_last_seen_status", {}).get("combined_status", "inactive")
        ab_version = ab.get("version")
        ab_rest_healthcheck_time = ab.get("rest_healthcheck_time")
        ab_ws_healthcheck_time = ab.get("ws_healthcheck_time")

        # Add dict by id
        brokers_dict_by_id[ab_id] = {
            "name": ab_name,
            "id": ab_id,
            "last_seen_status": ab_last_seen_status,
            "version": ab_version,
            "rest_healthcheck_time": ab_rest_healthcheck_time,
            "ws_healthcheck_time": ab_ws_healthcheck_time,
        }        
        
        # Add dict by name
        brokers_dict_by_name[ab_name] = {
            "name": ab_name,
            "id": ab_id,
            "last_seen_status": ab_last_seen_status,
            "version": ab_version,
            "rest_healthcheck_time": ab_rest_healthcheck_time,
            "ws_healthcheck_time": ab_ws_healthcheck_time,
        }
        
        if ab_name not in brokers_active_list and ab_last_seen_status == 'active':
            brokers_active_list.append(ab_name)
        
        if ab_name not in brokers_inactive_list and ab_last_seen_status != 'active':
            brokers_inactive_list.append(ab_name)        
            
    phantom.debug(f'Terminated requesting endpoint="/rest/automation_proxy", {len(brokers_dict_by_id)} eligible Automation Broker(s) were found: {json.dumps(brokers_dict_by_id)}')

    phantom.debug(json.dumps(brokers_dict_by_id, indent=2))
    phantom.debug(json.dumps(brokers_dict_by_name, indent=2))

    # Prepare the output
    outputs = {
        "brokers_dict_by_id": brokers_dict_by_id, 
        "brokers_dict_by_name": brokers_dict_by_name, 
        "brokers_active_list": brokers_active_list,
        "brokers_active_count": len(brokers_active_list),
        "brokers_inactive_list": brokers_inactive_list,
        "brokers_inactive_count": len(brokers_inactive_list),        
    }
        
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
