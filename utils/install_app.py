import base64
import requests
import sys

def convert_file_to_base64(tarfile_name):
    """Convert the tarball into a base64-encoded string."""
    try:
        with open(tarfile_name, "rb") as tarfile:
            tar_content = tarfile.read()
            base64_encoded = base64.b64encode(tar_content).decode("utf-8")
        print(f"Tarball {tarfile_name} successfully encoded to base64.")
        return base64_encoded
    except IOError as e:
        print(f"Failed to read tarball {tarfile_name} due to: {e}")
        sys.exit(1)

def install_app(api_url, token, base64_app_data):
    """Install an application via the REST API."""
    headers = {"ph-auth-token": f"{token}", "Content-Type": "application/json"}
    url = f"{api_url}/rest/app"
    data = {"app": base64_app_data}
    
    try:
        response = requests.post(url, headers=headers, json=data, verify=False)
        response.raise_for_status()
        print("Application installed successfully.")
        return True
    except requests.RequestException as e:
        print(f"Failed to install the application: {str(e)}")
        sys.exit(1)

api_url = None
token = None

# take the tarfile_name as an argument from the command line
tarfile_name = sys.argv[1]

# api_url is arg 2, token 3
if len(sys.argv) > 2:
    api_url = sys.argv[2]
if len(sys.argv) > 3:
    token = sys.argv[3]

# Convert the tarball to a base64-encoded string
base64_app_data = convert_file_to_base64(tarfile_name)

# Install the application via the REST API
install_app(api_url, token, base64_app_data)
