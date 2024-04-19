import sys
import requests
import argparse
import base64
import logging
import urllib3
import json

# Disable insecure request warnings for urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up logging
logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.INFO)


def import_to_dest(dest_target, dest_token, object_type, file_path, scm_name):
    headers = {"ph-auth-token": f"{dest_token}"}

    # Encode the file in base64
    tar_files_list = []
    try:
        with open(file_path, "rb") as f:
            file_content = f.read()
            encoded_content = base64.b64encode(file_content).decode("utf-8")
            # for each file in the tar, add the name of the file to tar_files_list
            tar_content = json.loads(file_content)
            for file in tar_content:
                tar_files_list.append(file)

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

    data = {object_type: encoded_content, "scm": scm_name, "force": "true"}

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


def main():
    parser = argparse.ArgumentParser(
        description="Import a playbook/custom_function from an input tgz file."
    )
    parser.add_argument(
        "--input_file", required=True, help="Path to the tgz input file."
    )
    parser.add_argument(
        "--object_type",
        choices=["playbook", "custom_function"],
        required=True,
        help="Type of object in the input file: playbook or custom_function.",
    )
    parser.add_argument(
        "--dest_target",
        required=True,
        help="The target URL of the destination service.",
    )
    parser.add_argument(
        "--dest_token", required=True, help="The token for the destination service."
    )
    parser.add_argument(
        "--dest_scm_name",
        required=True,
        help="The SCM name for the destination service.",
    )

    args = parser.parse_args()

    imported = import_to_dest(
        args.dest_target,
        args.dest_token,
        args.object_type,
        args.input_file,
        args.dest_scm_name,
    )
    if imported:
        logging.info(
            f"{args.object_type} was successfully imported to the destination target!"
        )
    else:
        logging.error(
            f"Failed to import the {args.object_type} to the destination target."
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
