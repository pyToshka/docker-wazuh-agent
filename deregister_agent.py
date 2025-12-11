import json
import os
from loguru import logger
from wazuh_utils import wazuh_request, code_desc, get_auth_context

def delete_agent(agt_name, auth_context):
    status_code, response = wazuh_request("get", f"agents?pretty=true&q=name={agt_name}", auth_context)
    # Check if 'data' and 'affected_items' exist to avoid KeyErrors if response structure differs on error
    if "data" in response and "affected_items" in response["data"]:
        for items in response["data"]["affected_items"]:
            status_code, response = wazuh_request(
                "delete",
                f"agents?pretty=true&older_than=0s&agents_list={items['id']}&status=all",
                auth_context
            )
            msg = json.dumps(response, indent=4, sort_keys=True)
            code = f"Status: {status_code} - {code_desc(status_code)}"
            logger.error(f"INFO - DELETE AGENT:\n{code}\n{msg}")

    status_code, response = wazuh_request(
        "delete",
        "agents?pretty=true&older_than=21d&agents_list=all&status=never_connected,disconnected",
        auth_context
    )
    if "data" in response and "affected_items" in response["data"]:
        for items in response["data"]["affected_items"]:
            status_code, response = wazuh_request(
                "delete",
                f"agents?pretty=true&older_than=0s&agents_list={items['id']}&status=all",
                auth_context
            )
            msg = json.dumps(response, indent=4, sort_keys=True)
            code = f"Status: {status_code} - {code_desc(status_code)}"
            logger.error(f"INFO - DELETE AGENT:\n{code}\n{msg}")


if __name__ == "__main__":
    try:
        auth_context = get_auth_context()
        node_name = os.environ.get("NODE_NAME") or os.environ.get("HOSTNAME")
        
        if not node_name:
             logger.error("NODE_NAME or HOSTNAME not set")
             exit(2)

    except KeyError as error:
        logger.error(f"Please check system variable {error}")
        exit(2)

    logger.info(f"Delete agent {node_name}")
    delete_agent(node_name, auth_context)
