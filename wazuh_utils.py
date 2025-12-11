import json
import os
import sys
from base64 import b64encode

import requests
import urllib3
from loguru import logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def code_desc(http_status_code):
    return requests.status_codes._codes[http_status_code][0]


def wazuh_request(method, resource, auth_context, data=None):
    """
    Executes a request to the Wazuh API.
    
    :param method: HTTP method (get, post, put, delete)
    :param resource: API resource path
    :param auth_context: Dictionary containing login_url, base_url, auth, and verify
    :param data: Data to send (optional)
    :return: (status_code, response_json)
    """
    login_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {b64encode(auth_context['auth']).decode()}",
    }
    
    try:
        # Initial login to get token
        response = requests.get(
            auth_context['login_url'], 
            headers=login_headers, 
            verify=auth_context['verify']
        )
        # Check if login was successful
        if response.status_code != 200:
             logger.error(f"Login failed: {response.status_code} {response.text}")
             sys.exit(1)

        token = json.loads(response.content.decode())["data"]["token"]
        
        requests_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }
        
        url = f"{auth_context['base_url']}/{resource}"
        requests.packages.urllib3.disable_warnings()

        method_lower = method.lower()
        verify = auth_context['verify']

        if method_lower == "post":
            r = requests.post(url, headers=requests_headers, data=json.dumps(data), verify=verify)
        elif method_lower == "put":
            r = requests.put(url, headers=requests_headers, data=data, verify=verify)
        elif method_lower == "delete":
            r = requests.delete(url, headers=requests_headers, data=data, verify=verify)
        else:
            r = requests.get(url, headers=requests_headers, params=data, verify=verify)

        return r.status_code, r.json()

    except Exception as exception:
        logger.error(f"Error: {resource} {exception}")
        sys.exit(1)


def get_auth_context():
    """Retrieves authentication details from environment variables."""
    try:
        host = os.environ.get("JOIN_MANAGER_MASTER_HOST")
        port = os.environ.get("JOIN_MANAGER_API_PORT")
        protocol = os.environ.get("JOIN_MANAGER_PROTOCOL")
        user = os.environ.get("JOIN_MANAGER_USER")
        password = os.environ.get("JOIN_MANAGER_PASSWORD")
        
        if not all([host, port, protocol, user, password]):
             # Just return existing env vars, let the caller validation handle missing ones if needed
             # But strictly speaking, the caller's validation logic might differ.
             # We will stick to creating the context object.
             pass

        login_endpoint = "security/user/authenticate"
        base_url = f"{protocol}://{host}:{port}"
        login_url = f"{protocol}://{host}:{port}/{login_endpoint}"
        auth = f"{user}:{password}".encode()
        verify = os.environ.get("WAZUH_API_SSL_VERIFY", "False").lower() in ("true", "1", "yes")
        
        return {
            "base_url": base_url,
            "login_url": login_url,
            "auth": auth,
            "verify": verify
        }
    except Exception as e:
        logger.error(f"Error creating auth context: {e}")
        sys.exit(2)
