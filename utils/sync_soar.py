import os, sys
import requests
import argparse
import json
import base64
import tarfile
import logging

# Disable insecure request warnings
requests.packages.urllib3.disable_warnings()

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


# cd context manager
class cd:
    """Context manager for changing the current working directory"""

    def __init__(self, newPath):
        self.newPath = os.path.expanduser(newPath)

    def __enter__(self):
        self.savedPath = os.getcwd()
        os.chdir(self.newPath)

    def __exit__(self, etype, value, traceback):
        os.chdir(self.savedPath)


def list_files_in_directory(directory, file_types=(".json", ".py")):
    """List all file pairs in the specified directory with the given file extensions."""
    files_dict = {}
    for file in os.listdir(directory):
        name, ext = os.path.splitext(file)
        if ext in file_types:
            if name not in files_dict:
                files_dict[name] = []
            files_dict[name].append(file)
    return {k: v for k, v in files_dict.items() if len(v) == 2}


def fetch_scm_id(api_url, token):
    """Fetch SCM ID for the 'local' configuration."""
    headers = {"ph-auth-token": f"{token}"}
    url = f"{api_url}/rest/scm"
    response = requests.get(url, headers=headers, verify=False)
    data = response.json()
    for scm in data["data"]:
        if scm["name"] == "local":
            return int(scm["id"])
    logging.error("Local SCM not found.")
    return None


def fetch_soar_items(api_url, token, item_type):
    """Fetch a list of items (playbooks or custom functions) from SOAR with pagination."""

    # get the sscm target id
    target_scm_id = fetch_scm_id(api_url, token)

    headers = {"ph-auth-token": f"{token}"}
    params = {"page": 0, "page_size": 100}
    url = f"{api_url}/rest/{item_type}"
    res = requests.get(url, headers=headers, params=params, verify=False)
    res_json = res.json()

    # final response
    response_list = []

    if "count" in res_json and "num_pages" in res_json:
        no_pages = int(res_json.get("num_pages", 1))
        for entry in res_json["data"]:
            response_list.append(entry)
        for page_number in range(
            1, no_pages
        ):  # start from page 1 (which is actually the second page)
            params["page"] = page_number
            res = requests.get(url, headers=headers, params=params, verify=False)
            res_json = res.json()
            for entry in res_json["data"]:
                response_list.append(entry)

    remote_objects_list = {}

    for item in response_list:
        if int(item["scm"]) == target_scm_id:
            object_name = item["name"]
            object_id = item["id"]
            object_scm_id = item["scm"]

            # add to the dict
            remote_objects_list[object_name] = {
                "id": object_id,
                "scm_id": object_scm_id,
            }

    return remote_objects_list


def replace_scm_references(file_path, src_scm_name, dest_scm_name):
    """Replace source SCM references with destination SCM references in JSON and Python files."""
    with open(file_path, "r") as file:
        content = file.read()

    if file_path.endswith(".json"):
        updated_content = content.replace(f'"{src_scm_name}"', f'"{dest_scm_name}"')
    elif file_path.endswith(".py"):
        updated_content = content.replace(
            f'"{src_scm_name}/',
            f'"{dest_scm_name}/',
        )

    with open(file_path, "w") as file:
        file.write(updated_content)


def sync_soar_object(dest_target, dest_token, object_type, file_path, scm_name, mode):
    headers = {"ph-auth-token": f"{dest_token}"}

    # Encode the file in base64
    tar_files_list = []
    try:
        with open(file_path, "rb") as f:
            file_content = f.read()
            encoded_content = base64.b64encode(file_content).decode("utf-8")

        # Open the tar file again to list its contents
        with tarfile.open(file_path, "r:gz") as tar:
            tar_files_list = tar.getnames()  # Get all member names from the tar file
            logging.info(f"Files in the tarball: {tar_files_list}")

    except IOError as e:
        logging.error(f"Failed to read file due to: {e}")
        sys.exit(1)

    if object_type == "playbook":
        endpoint = f"{dest_target}/rest/import_playbook"
    elif object_type == "custom_function":
        endpoint = f"{dest_target}/rest/import_custom_function"
    else:
        logging.error(f"Unsupported object type: {object_type}")
        sys.exit(1)

    data = {
        object_type: encoded_content,
        "scm": scm_name,
        "force": True,
    }

    if mode == "dryrun":
        logging.info(
            f"Simulation mode: Would have called {endpoint} with data keys: {list(data.keys())}"
        )
        return True
    else:
        logging.info(
            f"Running call to SOAR API, endpoint: {endpoint}, content: {json.dumps(tar_files_list, indent=0)}"
        )
        try:
            response = requests.post(endpoint, headers=headers, json=data, verify=False)
            response.raise_for_status()
            return True
        except requests.RequestException as e:
            logging.error(f"Import failed with error: {str(e)}")
            sys.exit(1)


def delete_soar_playbooks(api_url, token, items_list, mode):
    """Delete a list of items based."""
    headers = {"ph-auth-token": f"{token}"}
    data = {"ids": items_list, "delete": "true"}

    # Attention: data must be sent via json.dumps
    url = f"{api_url}/playbooks"

    if mode == "dryrun":
        logging.info(f"Dry run mode: Would have deleted playbooks with data: {data}")
        return 200, "Dry run delete"
    else:
        response = requests.post(
            url, headers=headers, data=json.dumps(data), verify=False
        )
        return response.status_code, response.text


def delete_soar_custom_function(api_url, token, item_id, mode):
    """Delete a custom function based."""
    headers = {"ph-auth-token": f"{token}"}
    url = f"{api_url}/rest/custom_functions/{item_id}"

    if mode == "dryrun":
        logging.info(
            f"Simulation mode: Would have deleted custom function with ID: {item_id}"
        )
        return 200, "Simulated delete"
    else:
        response = requests.delete(url, headers=headers, verify=False)
        return response.status_code, response.text


def main():
    parser = argparse.ArgumentParser(description="Sync Git repository with SOAR.")
    parser.add_argument(
        "--dest_target", required=True, help="The target URL of the SOAR service."
    )
    parser.add_argument(
        "--dest_token", required=True, help="The API token for the SOAR service."
    )
    parser.add_argument(
        "--dest_scm_name", required=True, help="The SCM name for the SOAR environment."
    )
    parser.add_argument(
        "--src_scm_name",
        required=True,
        help="The SCM name for the source SOAR environment.",
    )
    parser.add_argument(
        "--mode",
        choices=["dryrun", "live"],
        default="dryrun",
        help="Mode of operation: dryrun or live (default: dryrun)",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    if not args.verbose:
        logger.disabled = True

    local_playbooks = list_files_in_directory(".")
    local_custom_functions = list_files_in_directory("./custom_functions")
    remote_playbooks = fetch_soar_items(args.dest_target, args.dest_token, "playbook")
    remote_custom_functions = fetch_soar_items(
        args.dest_target, args.dest_token, "custom_function"
    )

    # log the run parameters
    logging.info("################## Start run parameters ##################")
    logging.info(f"dest_target={args.dest_target}")
    logging.info(f"dest_scm_name={args.dest_scm_name}")
    logging.info(f"src_scm_name={args.src_scm_name}")
    logging.info(f"mode={args.mode}")
    logging.info("################## End run parameters ##################")

    # log the number of local playbooks found
    logging.info("################## Start job information ##################")
    logging.info(f"Found {len(local_playbooks)} local playbooks.")
    logging.info(f"local_playbooks={json.dumps(local_playbooks, indent=2)}")
    # log the number of local custom functions found
    logging.info(f"Found {len(local_custom_functions)} local custom functions.")
    logging.info(
        f"local_custom_functions={json.dumps(local_custom_functions, indent=2)}"
    )
    # log the number of remote playbooks found
    logging.info(f"Found {len(remote_playbooks)} remote playbooks.")
    logging.info(f"remote_playbooks={json.dumps(remote_playbooks, indent=2)}")
    # log the number of remote custom functions found
    logging.info(f"Found {len(remote_custom_functions)} remote custom functions.")
    logging.info(
        f"remote_custom_functions={json.dumps(remote_custom_functions, indent=2)}"
    )
    logging.info("################## End job information ##################")

    # Initialize result structure
    result = {
        "synced_playbooks": [],
        "synced_custom_functions": [],
        "deleted_playbooks": [],
        "deleted_custom_functions": [],
    }

    #
    # Sync playbooks
    #

    logging.info("************ Start Syncing playbooks ************ ")

    for name, files in local_playbooks.items():

        logging.info(f'Processing playbook "{name}", files={files}')

        # Update SCM references in the JSON and Python files
        for file in files:
            replace_scm_references(file, args.src_scm_name, args.dest_scm_name)

        # create a gzip compressed tar file using name (remove spaces) as the filename, and the content are the files in files
        tarfile_name = f"{name.replace(' ', '')}.tgz"
        with tarfile.open(f"{tarfile_name}", "w:gz") as tar:
            for file in files:
                tar.add(file)

        imported = sync_soar_object(
            args.dest_target,
            args.dest_token,
            "playbook",
            tarfile_name,
            args.dest_scm_name,
            args.mode,
        )

        if imported:
            logging.info(
                f"Playbook {name} was successfully synchronized to the destination target!"
            )
            result["synced_playbooks"].append(name)
        else:
            logging.error(f"Playbook {name} has failed to be synchronized.")
            sys.exit(1)

    logging.info("************ End Syncing playbooks ************ ")

    logging.info("************ Start Syncing custom functions ************ ")

    #
    # Sync custom functions
    #

    for name, files in local_custom_functions.items():

        logging.info(f'Processing custom function "{name}", files={files}')

        with cd("custom_functions"):
            # Update SCM references in the JSON and Python files
            for file in files:
                replace_scm_references(file, args.src_scm_name, args.dest_scm_name)

            # create a gzip compressed tar file using name (remove spaces) as the filename, and the content are the files in files
            tarfile_name = f"{name.replace(' ', '')}.tgz"
            with tarfile.open(f"{tarfile_name}", "w:gz") as tar:
                for file in files:
                    tar.add(file)

            imported = sync_soar_object(
                args.dest_target,
                args.dest_token,
                "custom_function",
                tarfile_name,
                args.dest_scm_name,
                args.mode,
            )

            if imported:
                logging.info(
                    f"Custom function {name} was successfully synchronized to the destination target!"
                )
                result["synced_custom_functions"].append(name)
            else:
                logging.error(f"Custom function {name} has failed to be synchronized.")
                sys.exit(1)

    logging.info("************ End Syncing custom functions ************ ")

    logging.info("************ Start Purging remote playbooks ************ ")

    # Delete playbooks not found locally
    playbooks_ids_to_delete = []
    for name, id in remote_playbooks.items():
        if name not in local_playbooks:
            logging.info(
                f'Deleting playbook "{name}" with ID {id} as it is not available in the source sync repository.'
            )
            playbooks_ids_to_delete.append(id.get("id"))

    # proceed with deletion
    if len(playbooks_ids_to_delete) > 0:
        logging.info(f'Deleting playbooks with IDs "{playbooks_ids_to_delete}"')
        response_code, response_text = delete_soar_playbooks(
            args.dest_target, args.dest_token, playbooks_ids_to_delete, args.mode
        )
        # if response_code != 2*, log an error
        if response_code < 200 or response_code >= 300:
            logging.error(
                f"Failed to delete playbooks with IDs {playbooks_ids_to_delete}, response_code={response_code}, response_text={response_text}."
            )
        else:
            for name in playbooks_ids_to_delete:
                result["deleted_playbooks"].append(name)
    else:
        logging.info("No playbooks to be deleted on the remote SOAR.")

    logging.info("************ End Purging remote playbooks ************ ")

    logging.info("************ Start Purging remote custom functions ************ ")

    # Delete custom functions not found locally
    custom_functions_ids_to_delete = []
    for name, id in remote_custom_functions.items():
        if name not in local_custom_functions:
            logging.info(
                f'Deleting custom function "{name}" with ID {id} as it is not available in the source sync repository.'
            )
            custom_functions_ids_to_delete.append(id.get("id"))

    # proceed with deletion
    if len(custom_functions_ids_to_delete) > 0:
        for custom_function_id in custom_functions_ids_to_delete:

            logging.info(
                f'Deleting custom functions with IDs "{custom_functions_ids_to_delete}"'
            )
            response_code, response_text = delete_soar_custom_function(
                args.dest_target,
                args.dest_token,
                custom_function_id,
                args.mode,
            )
            # if response_code != 2*, log an error
            if response_code < 200 or response_code >= 300:
                logging.error(
                    f"Failed to delete custom functions with IDs {custom_functions_ids_to_delete}, response_code={response_code}, response_text={response_text}."
                )
            else:
                result["deleted_custom_functions"].append(custom_function_id)
    else:
        logging.info("No custom functions to be deleted on the remote SOAR.")

    logging.info("************ End Purging remote custom functions ************ ")

    # log end
    logging.info("SOAR Sync completed successfully.")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
