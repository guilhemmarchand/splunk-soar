def get_assets_for_automation_brokers(**kwargs):
    """
    This function is designed to be used for the purposes of handling High Availability concepts with the Automation Brokers. It returns the list of assets with Automation Brokers associations in a programmatic manner.
    
    Returns a JSON-serializable object that implements the configured data paths:
        assets_dict: Assets and automation brokers association dictionnary 
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}

    url = phantom.build_phantom_rest_url('asset')
    params = {'pretty': True, 'page_size': 0}

    phantom.debug(f'Starting get assets, requesting endpoint="/rest/asset"')

    # Function to make the request and handle pagination
    def make_request_and_get_data(url, params):
        res = phantom.requests.get(uri=url, params=params, verify=False).json()
        data = res.get('data', [])
        num_pages = int(res.get('num_pages', 1))
        for page in range(2, num_pages + 1):
            params['page'] = page
            res = phantom.requests.get(uri=url, params=params, verify=False).json()
            data.extend(res.get('data', []))
        return data

    all_assets_raw_list = make_request_and_get_data(url, params)

    # Process the retrieved data
    all_assets_dict = {}
    assets_with_ab_list = []

    for asset in all_assets_raw_list:
        asset_name = asset.get("name")
        asset_id = asset.get("id")
        asset_automation_broker = asset.get("automation_broker", None)

        # If associated with an automation broker, add to our dict
        if asset_automation_broker:
            if asset_automation_broker not in all_assets_dict:
                all_assets_dict[asset_automation_broker] = []
            all_assets_dict[asset_automation_broker].append({
                "name": asset_name,
                "id": asset_id,
                "automation_broker": asset_automation_broker,
            })
            if asset_name not in assets_with_ab_list:
                assets_with_ab_list.append(asset_name)

    phantom.debug(f'{json.dumps(all_assets_dict, indent=2)}')
    phantom.debug(f'Terminated requesting endpoint="/rest/asset", {len(assets_with_ab_list)} eligible asset(s) using an automation broker were found')

    # Prepare the output
    outputs = {"assets_dict": all_assets_dict}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
