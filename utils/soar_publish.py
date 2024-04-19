import sys
import requests
import argparse
import base64
import logging
import urllib3

# Disable insecure request warnings for urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up logging
logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.INFO)


def import_to_dest(dest_target, dest_token, object_type, file_path, scm_name):
    headers = {"ph-auth-token": f"{dest_token}"}

    # Encode the file in base64
    try:
        with open(file_path, "rb") as f:
            file_content = f.read()
            encoded_content = base64.b64encode(file_content).decode("utf-8")
    except IOError as e:
        logging.error(f"Failed to read file due to: {e}")
        sys.exit(1)

    if object_type == "custom_function":
        endpoint = f"{dest_target}/rest/import_custom_function"
    else:
        logging.error("Unsupported object type for .py files")
        sys.exit(1)

    data = {"custom_function": encoded_content, "scm": scm_name, "force": "true"}

    try:
        response = requests.post(endpoint, headers=headers, json=data, verify=False)
        response.raise_for_status()
        logging.info(f"Successfully imported {file_path} to {dest_target}")
    except requests.RequestException as e:
        logging.error(f"Import failed with error: {str(e)}")
        logging.error(f"Response body: {response.text}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Import a custom function from the specified Python file."
    )
    parser.add_argument("--input_file", required=True, help="Path to the .py file.")
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

    # Import the Python file as a custom function
    import_to_dest(
        args.dest_target,
        args.dest_token,
        "custom_function",
        args.input_file,
        args.dest_scm_name,
    )


if __name__ == "__main__":
    main()
