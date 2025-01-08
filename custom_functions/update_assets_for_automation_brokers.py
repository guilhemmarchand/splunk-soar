def update_assets_for_automation_brokers(brokers_dict_by_id=None, brokers_dict_by_name=None, assets_dict=None, mode=None, **kwargs):
    """
    This function is designed to be used for the purposes of handling High Availability concepts with the Automation Brokers. This functions updates assets accordingly.
    
    Args:
        brokers_dict_by_id: The dictionnary containing the list of Automation Brokers to be inspected, ordered by id
        brokers_dict_by_name: The dictionnary containing the list of Automation Brokers to be inspected, ordered by name
        assets_dict: The dictionnaru containing the list of Assets and their Automation Broker association.
        mode: In simulation, we will simulate actions which would be achieved, in live assets will be updated effectively.
    
    Returns a JSON-serializable object that implements the configured data paths:
        response: The response summary for actions.
        update_count: Number of updates attenpted or performed, if the counter is positive, this means we have performed active changes which for which you may want to receive a notification.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import random
    import ast
    
    outputs = {}
    
    # Write your custom code here...
    phantom.debug("Starting function update_assets_for_automation_brokers")
    
    # Function to remove fields with values starting with "salt:", these are SOAR secrets
    def remove_salt_fields(data):
        if isinstance(data, dict):
            cleaned_data = {}
            for k, v in data.items():
                if isinstance(v, str) and v.startswith("salt:"):
                    continue
                cleaned_data[k] = remove_salt_fields(v)
            return cleaned_data
        elif isinstance(data, list):
            return [remove_salt_fields(item) for item in data]
        else:
            return data    
    
    # Function to remove fields which are included in the forbidden fields list
    def remove_forbidden_fields(data, forbidden_fields):
        if isinstance(data, dict):
            cleaned_data = {}
            for k, v in data.items():
                if k in forbidden_fields:
                    continue
                cleaned_data[k] = remove_forbidden_fields(v, forbidden_fields)
            return cleaned_data
        elif isinstance(data, list):
            return [remove_forbidden_fields(item, forbidden_fields) for item in data]
        else:
            return data

    # Check inputs
    if not brokers_dict_by_id or not brokers_dict_by_name or not assets_dict:
        raise Exception('brokers_dict_by_id, brokers_dict_by_name and assets_dict are required inputs')
        
    if not mode:
        phantom.debug('mode has not been set, using simulation mode.')
    
    brokers_dict_by_id = brokers_dict_by_id[0]
    brokers_dict_by_name = brokers_dict_by_name[0]
    assets_dict = assets_dict[0]
    mode = mode[0]
    
    # Log types of inputs
    phantom.debug(f'Type of brokers_dict_by_id: {type(brokers_dict_by_id)}')
    phantom.debug(f'Type of brokers_dict_by_name: {type(brokers_dict_by_name)}')
    phantom.debug(f'Type of assets_dict: {type(assets_dict)}')

    # Check if inputs are dictionaries, and convert if necessary
    if not isinstance(brokers_dict_by_id, dict):
        phantom.debug(f'brokers_dict_by_id is not a dictionary, it is a {type(brokers_dict_by_id)}')
        try:
            brokers_dict_by_id = ast.literal_eval(brokers_dict_by_id)
        except Exception as e:
            raise Exception(f'failed to load brokers_dict_by_id, exception="{str(e)}", content={brokers_dict_by_id}')
                
    if not isinstance(brokers_dict_by_name, dict):
        phantom.debug(f'brokers_dict_by_name is not a dictionary, it is a {type(brokers_dict_by_name)}')
        try:
            brokers_dict_by_name = ast.literal_eval(brokers_dict_by_name)
        except Exception as e:
            raise Exception(f'failed to load brokers_dict_by_name, exception="{str(e)}", content={brokers_dict_by_name}')
                
    if not isinstance(assets_dict, dict):
        phantom.debug(f'assets_dict is not a dictionary, it is a {type(assets_dict)}')
        try:
            assets_dict = ast.literal_eval(assets_dict)
        except Exception as e:
            raise Exception(f'failed to load assets_dict, exception="{str(e)}", content={assets_dict}')
            
    phantom.debug(f'mode is: {mode}')
                
    # Get the list of active brokers
    active_ab_list = [broker_id for broker_id, broker_info in brokers_dict_by_id.items() if broker_info["last_seen_status"] == "active"]
    
    # Prepare the final response
    final_response = []
    update_count = 0

    # Process each broker
    for ab_id, ab_info in brokers_dict_by_id.items():
        update_assets = []
        update_messages = []
        update_error_count = 0
        associated_assets = []

        ab_response = {}

        for asset in assets_dict.get(ab_id, []):
            asset_name = asset["name"]
            asset_id = asset["id"]
            automation_broker_status = ab_info["last_seen_status"]
            automation_broker_name = ab_info["name"]

            phantom.debug(f"Processing asset={asset_name}, id={asset_id} associated with automation_broker={automation_broker_name}, id={ab_id}, status={automation_broker_status}")

            # If the automation broker is not active, and we have at least one active automation broker, we can act and update the asset
            if automation_broker_status != "active" and len(active_ab_list) > 0:
                update_count+=1
                phantom.debug(f"Asset {asset_name} (id={asset_id}) will be updated as the associated broker {automation_broker_name} (id={ab_id}) is inactive")

                asset_config = phantom.requests.get(uri=phantom.build_phantom_rest_url(f"asset/{asset_id}"), verify=False).json()
                target_automation_broker = random.choice(active_ab_list)
                target_automation_broker_name = brokers_dict_by_id[target_automation_broker]["name"]
                target_automation_broker_status = brokers_dict_by_id[target_automation_broker]["last_seen_status"]

                phantom.debug(f"Associating asset {asset_name} (id={asset_id}) with automation_broker={target_automation_broker_name}, id={target_automation_broker}")

                asset_config["automation_broker_id"] = target_automation_broker
                
                # Remove any secret before updating
                no_secrets_asset_config_json = remove_salt_fields(
                    asset_config
                )
                
                # Remove any forbidden fields before updating
                assets_update_forbidden_fields = "apikey,api_key,password,auth_token,client_secret"
                assets_update_forbidden_fields = assets_update_forbidden_fields.split(",")
                no_forbidden_fields_asset_config_json = remove_forbidden_fields(
                    no_secrets_asset_config_json,
                    assets_update_forbidden_fields,
                )                

                # Update the asset configuration
                endpoint = f"asset/{asset_id}"
                if mode == "live":
                    try:
                        phantom.debug(f"**Live** Associating asset {asset_name} (id={asset_id}) with automation_broker={target_automation_broker_name}, id={target_automation_broker}")
                        asset_config_update = phantom.requests.post(uri=phantom.build_phantom_rest_url(endpoint), json=no_forbidden_fields_asset_config_json, verify=False).json()
                        update_assets.append(asset_name)
                        msg = f'Asset {asset_name} (id={asset_id}) automation broker updated from {automation_broker_name} (id={ab_id}) to {target_automation_broker_name} (id={target_automation_broker}), status={target_automation_broker_status}'
                        phantom.debug(msg)
                        update_messages.append(msg)
                    except Exception as e:
                        error_msg = f'**Live** Asset {asset_name} (id={asset_id}) failed to simulate update: {str(e)}'
                        error_msg = f'Asset {asset_name} (id={asset_id}) failed to update: {str(e)}'
                        phantom.error(error_msg)
                        update_error_count += 1
                        update_messages.append(error_msg)
                elif mode == "simulation":
                    try:
                        phantom.debug(f"**Simulation only** Associating asset {asset_name} (id={asset_id}) with automation_broker={target_automation_broker_name}, id={target_automation_broker}")
                        update_assets.append(asset_name)
                        msg = f'**Simulation only** Asset {asset_name} (id={asset_id}) automation broker would be updated from {automation_broker_name} (id={ab_id}) to {target_automation_broker_name} (id={target_automation_broker}), status={target_automation_broker_status}'
                        phantom.debug(msg)
                        update_messages.append(msg)
                    except Exception as e:
                        error_msg = f'**Simulation only** Asset {asset_name} (id={asset_id}) failed to simulate update: {str(e)}'
                        phantom.error(error_msg)
                        update_error_count += 1
                        update_messages.append(error_msg)

            # The associated broker is inactive, but there are no other brokers available
            elif automation_broker_status != "active" and len(active_ab_list) == 0:
                error_msg = f"Asset {asset_name} (id={asset_id}) is associated with automation_broker {automation_broker_name} (id={ab_id}), status={automation_broker_status}, no other active automation broker is available to update the asset."
                phantom.error(error_msg)
                update_error_count += 1
                update_messages.append(error_msg)

            # Add the associated asset to the list
            associated_assets.append(asset_name)

        # Set response for the broker
        ab_response = {
            "id": ab_id,
            "name": ab_info["name"],
            "last_seen_status": ab_info["last_seen_status"],
            "associated_assets": associated_assets,
            "associated_assets_count": len(associated_assets),
            "update_messages": update_messages,
            "update_error_count": update_error_count,
            "updated_assets": update_assets,
            "version": ab_info["version"],
            "rest_healthcheck_time": ab_info["rest_healthcheck_time"],
            "ws_healthcheck_time": ab_info["ws_healthcheck_time"],
        }

        # Add to final response
        final_response.append(ab_response)

    # log
    phantom.debug(f'response: \n{json.dumps(final_response, indent=2)}\n')
        
    # Prepare the output
    outputs = {"response": json.dumps(final_response, indent=2), "update_count": update_count}    
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
