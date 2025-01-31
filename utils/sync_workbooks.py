import requests
import json
import logging
import argparse

# Disable insecure request warnings (if verify=False)
requests.packages.urllib3.disable_warnings()

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def fetch_full_workbook_details(api_url, token, workbook_id, timeout, verify):
    """Fetch full details of a workbook including its phases and tasks."""
    headers = {"ph-auth-token": f"{token}"}

    # Fetch workbook metadata
    workbook_url = f"{api_url}/rest/workbook_template/{workbook_id}"
    response = requests.get(workbook_url, headers=headers, timeout=timeout, verify=verify)
    response.raise_for_status()
    workbook_details = response.json()

    # Fetch workbook phases and tasks
    phases_url = f"{api_url}/rest/workbook_phase_template/?_filter_template={workbook_id}"
    response = requests.get(phases_url, headers=headers, timeout=timeout, verify=verify)
    response.raise_for_status()
    phases_data = response.json()
    workbook_details["phases"] = phases_data.get("data", [])

    return workbook_details


def fetch_workbook_id(api_url, token, workbook_name, timeout, verify):
    """Fetch the workbook ID by its name from the destination."""
    headers = {"ph-auth-token": f"{token}"}
    params = {"page": 0, "page_size": 100}
    url = f"{api_url}/rest/workbook_template"

    workbook_id = None

    while True:
        response = requests.get(url, headers=headers, params=params, timeout=timeout, verify=verify)
        res_json = response.json()

        if "data" in res_json:
            for workbook in res_json["data"]:
                if workbook["name"] == workbook_name:
                    workbook_id = workbook["id"]
                    break

        if workbook_id or "next_page" not in res_json or not res_json["next_page"]:
            break

        params["page"] += 1

    return workbook_id


def delete_workbook(dest_api_url, dest_token, workbook_id, timeout, verify):
    """Delete a workbook from the destination."""
    headers = {"ph-auth-token": f"{dest_token}"}
    url = f"{dest_api_url}/rest/workbook_template/{workbook_id}"

    response = requests.delete(url, headers=headers, timeout=timeout, verify=verify)

    if response.status_code == 200:
        logging.info(f"Deleted workbook ID {workbook_id} on the destination.")
    else:
        logging.error(f"Failed to delete workbook ID {workbook_id}: {response.text}")
        response.raise_for_status()


def should_resync_workbook(source_workbook, dest_workbook):
    """Check if the workbook needs to be resynced by comparing phases count and modified time."""
    source_phases = source_workbook.get("phases", [])
    dest_phases = dest_workbook.get("phases", [])

    if len(source_phases) != len(dest_phases):
        logging.info("Phase count mismatch detected, resyncing workbook.")
        return True

    dest_phase_map = {phase["name"]: phase for phase in dest_phases}

    for source_phase in source_phases:
        dest_phase = dest_phase_map.get(source_phase["name"])
        if not dest_phase or source_phase["modified_time"] > dest_phase["modified_time"]:
            logging.info(f"Phase '{source_phase['name']}' is newer on source, resyncing workbook.")
            return True

    return False


def create_or_update_workbook(dest_api_url, dest_token, workbook_name, description, timeout, verify):
    """Ensure that the workbook exists, creating it if necessary."""
    headers = {"ph-auth-token": f"{dest_token}", "Content-Type": "application/json"}
    existing_id = fetch_workbook_id(dest_api_url, dest_token, workbook_name, timeout, verify)

    if existing_id:
        logging.info(f"Workbook '{workbook_name}' already exists with ID {existing_id}. Updating...")
        url = f"{dest_api_url}/rest/workbook_template/{existing_id}"
    else:
        logging.info(f"Creating new workbook: {workbook_name}")
        url = f"{dest_api_url}/rest/workbook_template"

    workbook_data = {
        "name": workbook_name,
        "description": description,
        "status": "published",
        "is_default": False,
        "is_note_required": False,
        "phases": []
    }

    response = requests.post(url, headers=headers, json=workbook_data, timeout=timeout, verify=verify)
    response.raise_for_status()
    return response.json()["id"]


def format_task(task):
    """Format the task object to include playbook suggestions if available."""
    return {
        "name": task["name"],
        "order": task["order"],
        "description": task.get("description", ""),
        "is_note_required": task.get("is_note_required", False),
        "sla": task.get("sla"),
        "sla_type": task.get("sla_type", "minutes"),
        "playbooks": task.get("suggestions", {}).get("playbooks", [])
    }


def sync_workbook_to_destination(src_workbook, dest_api_url, dest_token, timeout, verify):
    """Sync the workbook content (including phases and tasks) from source to destination."""
    workbook_name = src_workbook["name"]
    workbook_description = src_workbook.get("description", "")

    logging.info(f"Syncing workbook: {workbook_name}")

    workbook_id = fetch_workbook_id(dest_api_url, dest_token, workbook_name, timeout, verify)

    if workbook_id:
        dest_workbook_details = fetch_full_workbook_details(dest_api_url, dest_token, workbook_id, timeout, verify)

        if should_resync_workbook(src_workbook, dest_workbook_details):
            logging.info(f"Workbook '{workbook_name}' requires resync. Deleting and recreating...")
            delete_workbook(dest_api_url, dest_token, workbook_id, timeout, verify)
            workbook_id = None  # Reset so it gets recreated

    if not workbook_id:
        workbook_id = create_or_update_workbook(dest_api_url, dest_token, workbook_name, workbook_description, timeout, verify)

    # Sync phases and tasks
    for phase in src_workbook.get("phases", []):
        create_or_update_phase(dest_api_url, dest_token, phase, workbook_id, timeout, verify)

    logging.info(f"Workbook '{workbook_name}' fully synced.")


def create_or_update_phase(dest_api_url, dest_token, phase, workbook_id, timeout, verify):
    """Create or update a workbook phase, ensuring it is linked to a workbook."""
    headers = {"ph-auth-token": f"{dest_token}", "Content-Type": "application/json"}

    # Fetch existing phases for the workbook
    phases_url = f"{dest_api_url}/rest/workbook_phase_template/?_filter_template={workbook_id}"
    response = requests.get(phases_url, headers=headers, timeout=timeout, verify=verify)
    response.raise_for_status()
    existing_phases = {p["name"]: p for p in response.json().get("data", [])}

    phase_name = phase["name"]
    existing_phase = existing_phases.get(phase_name)

    # Format tasks properly
    formatted_tasks = [format_task(task) for task in phase.get("tasks", [])]

    if existing_phase:
        # Compare tasks and update phase if necessary
        existing_tasks = {t["name"]: t for t in existing_phase.get("tasks", [])}

        # If task count is different or any task is different, we update the phase
        needs_update = len(existing_tasks) != len(formatted_tasks)
        if not needs_update:
            for task in formatted_tasks:
                existing_task = existing_tasks.get(task["name"])
                if not existing_task or task != format_task(existing_task):
                    needs_update = True
                    break

        if needs_update:
            logging.info(f"Updating phase '{phase_name}' for workbook ID {workbook_id}.")
            phase_data = {
                "name": phase_name,
                "order": phase["order"],
                "template_id": workbook_id,
                "tasks": formatted_tasks
            }
            phase_url = f"{dest_api_url}/rest/workbook_phase_template/{existing_phase['id']}"
            response = requests.post(phase_url, headers=headers, json=phase_data, timeout=timeout, verify=verify)
            response.raise_for_status()
            logging.info(f"Updated phase '{phase_name}' (ID {existing_phase['id']}) for workbook ID {workbook_id}.")
    else:
        # Phase does not exist, create it
        logging.info(f"Creating phase '{phase_name}' for workbook ID {workbook_id}.")
        phase_data = {
            "name": phase_name,
            "order": phase["order"],
            "template_id": workbook_id,
            "tasks": formatted_tasks
        }
        url = f"{dest_api_url}/rest/workbook_phase_template"
        response = requests.post(url, headers=headers, json=phase_data, timeout=timeout, verify=verify)
        response.raise_for_status()
        logging.info(f"Created phase '{phase_name}' for workbook ID {workbook_id}.")


def sync_workbooks(src_api_url, src_token, dest_api_url, dest_token, workbooks_list, timeout, verify):
    """Sync workbooks from source to destination."""
    workbooks = fetch_workbooks_from_source(src_api_url, src_token, timeout, verify)

    logging.debug(f"Selectable list of workbooks: {workbooks_list}")

    for workbook in workbooks:
        workbook_details = fetch_full_workbook_details(src_api_url, src_token, workbook["id"], timeout, verify)

        workbook_name = workbook_details["name"]
        process_workbook = not workbooks_list or workbook_name in workbooks_list

        if process_workbook:
            logging.debug(f"Fetched workbook details: {json.dumps(workbook_details, indent=2)}")
            logging.info(f"Processing workbook: {workbook_name}")
            sync_workbook_to_destination(workbook_details, dest_api_url, dest_token, timeout, verify)
        else:
            logging.debug(f"Skipping workbook, not in selectable list: {workbook_name}")

    logging.info("Workbooks sync completed.")


def fetch_workbooks_from_source(src_api_url, src_token, timeout, verify):
    """Fetch all workbooks from the source SOAR instance."""
    headers = {"ph-auth-token": f"{src_token}"}
    params = {"page": 0, "page_size": 100}
    url = f"{src_api_url}/rest/workbook_template"

    response = requests.get(url, headers=headers, params=params, timeout=timeout, verify=verify)
    response.raise_for_status()
    return response.json().get("data", [])


def main():
    
    parser = argparse.ArgumentParser(description="Sync workbooks between two Splunk SOAR instances.")
    parser.add_argument("--soar_src_url", required=True)
    parser.add_argument("--soar_src_token", required=True)
    parser.add_argument("--soar_dest_url", required=True)
    parser.add_argument("--soar_dest_token", required=True)
    parser.add_argument(
        "--workbooks_list",
        type=str,
        default="",
        help="Comma-separated list of workbooks to sync (e.g., 'test 001 workbook,test 002 workbook')",
    )
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--verify", action="store_true", default=False)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--debug", action="store_true")  
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.INFO)
    
    if args.debug:
        logger.setLevel(logging.DEBUG)

    # workbooks_list
    workbooks_list = [wb.strip() for wb in args.workbooks_list.split(",")] if args.workbooks_list else []

    # process
    sync_workbooks(args.soar_src_url, args.soar_src_token, args.soar_dest_url, args.soar_dest_token, workbooks_list, args.timeout, args.verify)


if __name__ == "__main__":
    main()
