import json
import os
import sys
from base64 import b64encode

from http import HTTPStatus
import requests
import urllib3
from loguru import logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def code_desc(http_status_code: int) -> str:
    try:
        return HTTPStatus(http_status_code).phrase
    except ValueError:
        return "Unknown Status"


try:
    DEFAULT_TIMEOUT = float(os.environ.get("WAZUH_API_TIMEOUT", "10.0"))
except ValueError:
    DEFAULT_TIMEOUT = 10.0


def wazuh_request(method, resource, auth_context, data=None, timeout: float | None = None):
    """
    Executes a request to the Wazuh API.
    
    :param method: HTTP method (get, post, put, delete)
    :param resource: API resource path
    :param auth_context: Dictionary containing login_url, base_url, auth, and verify
    :param data: Data to send (optional)
    :param timeout: Timeout for the request in seconds (optional)
    :return: (status_code, response_json)
    """
    login_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {b64encode(auth_context['auth']).decode()}",
    }
    
    try:
        effective_timeout = timeout or DEFAULT_TIMEOUT
        # Initial login to get token
        response = requests.get(
            auth_context['login_url'], 
            headers=login_headers, 
            verify=auth_context['verify'],
            timeout=effective_timeout
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
        method_lower = method.lower()
        verify = auth_context['verify']

        if method_lower == "post":
            r = requests.post(url, headers=requests_headers, data=json.dumps(data), verify=verify, timeout=effective_timeout)
        elif method_lower == "put":
            r = requests.put(url, headers=requests_headers, data=json.dumps(data) if data else None, verify=verify, timeout=effective_timeout)
        elif method_lower == "delete":
            r = requests.delete(url, headers=requests_headers, data=json.dumps(data) if data else None, verify=verify, timeout=effective_timeout)
        else:
            r = requests.get(url, headers=requests_headers, params=data, verify=verify, timeout=effective_timeout)

        return r.status_code, r.json()

    except (requests.RequestException, json.JSONDecodeError, KeyError) as exception:
        logger.error(f"Error handling request for resource {resource}: {exception}")
        sys.exit(1)


def get_auth_context():
    """Retrieves authentication details from environment variables."""
    try:
        host = os.environ.get("JOIN_MANAGER_MASTER_HOST")
        port = os.environ.get("JOIN_MANAGER_API_PORT")
        protocol = os.environ.get("JOIN_MANAGER_PROTOCOL")
        user = os.environ.get("JOIN_MANAGER_USER")
        password = os.environ.get("JOIN_MANAGER_PASSWORD")
        
        missing = [name for name, value in [
            ("JOIN_MANAGER_MASTER_HOST", host),
            ("JOIN_MANAGER_API_PORT", port),
            ("JOIN_MANAGER_PROTOCOL", protocol),
            ("JOIN_MANAGER_USER", user),
            ("JOIN_MANAGER_PASSWORD", password),
        ] if not value]
        
        if missing:
            logger.error(f"Missing required environment variables: {', '.join(missing)}")
            sys.exit(2)

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
    except (TypeError, AttributeError) as e:
        logger.error(f"Error creating auth context: {e}")
        sys.exit(2)


def process_deleted_agents(response, auth_context):
    """
    Iterates over affected_items in the response and deletes them using the Wazuh API.
    """
    if "data" in response and "affected_items" in response["data"]:
        for items in response["data"]["affected_items"]:
            status_code, response_del = wazuh_request(
                "delete",
                f"agents?pretty=true&older_than=0s&agents_list={items['id']}&status=all",
                auth_context
            )
            msg = json.dumps(response_del, indent=4, sort_keys=True)
            code = f"Status: {status_code} - {code_desc(status_code)}"
            logger.info(f"DELETE AGENT:\n{code}\n{msg}")
