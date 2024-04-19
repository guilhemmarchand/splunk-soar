import sys
import requests
import argparse
import logging
import urllib3
import json

# Disable insecure request warnings for urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up logging
logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.INFO)


class SOARClient:
    def __init__(self, server_url, auth_token, verify=False):
        self.server_url = server_url
        self.auth_token = auth_token
        self.verify = verify

    def make_request(self, endpoint, method="GET", data=None, page=0, page_size=100):
        url = f"{self.server_url}/rest/{endpoint}"
        headers = {"Accept": "application/json", "ph-auth-token": self.auth_token}
        params = {"page": page, "page_size": page_size}

        if data and method.upper() == "POST":
            response = requests.post(
                url, headers=headers, json=data, params=params, verify=self.verify
            )
        else:
            response = requests.get(
                url, headers=headers, params=params, verify=self.verify
            )

        response.raise_for_status()
        return response.json()

    def fetch_all_items(self, endpoint):
        response = []
        page = 0
        while True:
            res_json = self.make_request(endpoint, page=page)
            response.extend(res_json["data"])
            if "next" not in res_json or not res_json["next"]:
                break
            page += 1
        return response

    def delete_object(self, endpoint, object_id):
        data = {"ids": [object_id], "delete": True}
        self.make_request(f"{endpoint}/{object_id}", method="POST", data=data)


def find_and_delete_object(soar_client, object_type, object_name):
    objects = soar_client.fetch_all_items(
        object_type + "s"
    )  # assuming endpoint is 'playbooks' or 'custom_functions'
    object_info = next((obj for obj in objects if obj["name"] == object_name), None)

    if object_info:
        soar_client.delete_object(object_type, object_info["id"])
        logging.info(
            f"Deleted {object_type} '{object_name}' with ID {object_info['id']}"
        )
    else:
        logging.error(f"No {object_type} found with name '{object_name}'")


def main():
    parser = argparse.ArgumentParser(
        description="Delete a playbook or custom function from SOAR."
    )
    parser.add_argument(
        "--object_type",
        required=True,
        help="Type of object to delete (playbook or custom_function).",
    )
    parser.add_argument(
        "--object_name", required=True, help="Name of the object to delete."
    )
    parser.add_argument(
        "--dest_target",
        required=True,
        help="The target URL of the destination service.",
    )
    parser.add_argument(
        "--dest_token", required=True, help="The token for the destination service."
    )
    args = parser.parse_args()

    soar_client = SOARClient(args.dest_target, args.dest_token)
    find_and_delete_object(soar_client, args.object_type, args.object_name)


if __name__ == "__main__":
    main()
