import json
import os
import sys
from base64 import b64encode

import urllib3
from loguru import logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
try:
    import requests
except ModuleNotFoundError as e:
    logger.error("No module 'requests' found. Install: pip install requests")
    sys.exit(1)


def code_desc(http_status_code):
    return requests.status_codes._codes[http_status_code][0]


def req(method, resource, data=None):
    login_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {b64encode(auth).decode()}",
    }
    response = requests.get(login_url, headers=login_headers, verify=False)  # nosec
    token = json.loads(response.content.decode())["data"]["token"]
    requests_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    url = f"{base_url}/{resource}"
    try:
        requests.packages.urllib3.disable_warnings()

        if method.lower() == "post":
            r = requests.post(
                url, headers=requests_headers, data=json.dumps(data), verify=verify
            )
        elif method.lower() == "put":
            r = requests.put(url, headers=requests_headers, data=data, verify=verify)
        elif method.lower() == "delete":
            r = requests.delete(url, headers=requests_headers, data=data, verify=verify)
        else:
            r = requests.get(url, headers=requests_headers, params=data, verify=verify)

        code = r.status_code
        res_json = r.json()

    except Exception as exception:
        logger.error(f"Error: {resource} {exception}")
        sys.exit(1)

    return code, res_json


def delete_agent(agt_name):
    status_code, response = req("get", f"agents?pretty=true&q=name={agt_name}")
    for items in response["data"]["affected_items"]:
        status_code, response = req(
            "delete",
            f"agents?pretty=true&older_than=0s&agents_list={items['id']}&status=all",
        )
        msg = json.dumps(response, indent=4, sort_keys=True)
        code = f"Status: {status_code} - {code_desc(status_code)}"
        logger.error(f"INFO - DELETE AGENT:\n{code}\n{msg}")
    status_code, response = req(
        "delete",
        "agents?pretty=true&older_than=21d&agents_list=all&status=never_connected,disconnected",
    )
    for items in response["data"]["affected_items"]:
        status_code, response = req(
            "delete",
            f"agents?pretty=true&older_than=0s&agents_list={items['id']}&status=all",
        )
        msg = json.dumps(response, indent=4, sort_keys=True)
        code = f"Status: {status_code} - {code_desc(status_code)}"
        logger.error(f"INFO - DELETE AGENT:\n{code}\n{msg}")


if __name__ == "__main__":
    try:
        host = os.environ.get("JOIN_MANAGER_MASTER_HOST")
        port = os.environ.get("JOIN_MANAGER_API_PORT")
        protocol = os.environ.get("JOIN_MANAGER_PROTOCOL")
        user = os.environ.get("JOIN_MANAGER_USER")
        password = os.environ.get("JOIN_MANAGER_PASSWORD")
        node_name = os.environ.get("NODE_NAME")
        login_endpoint = "security/user/authenticate"
        base_url = f"{protocol}://{host}:{port}"
        login_url = f"{protocol}://{host}:{port}/{login_endpoint}"
        auth = f"{user}:{password}".encode()
        if not node_name:
            node_name = os.environ.get("HOSTNAME")
    except KeyError as error:
        logger.error(f"Please check system variable {error}")
        exit(2)
    verify = False
    logger.info(f"Delete agent {node_name}")
    delete_agent(node_name)
