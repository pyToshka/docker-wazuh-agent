import json
import os
import sys
from loguru import logger
from wazuh_utils import wazuh_request, code_desc, get_auth_context, process_deleted_agents

def delete_agent(agt_name, auth_context):
    _, response = wazuh_request("get", f"agents?pretty=true&q=name={agt_name}", auth_context)
    process_deleted_agents(response, auth_context)

    _, response = wazuh_request(
        "delete",
        "agents?pretty=true&older_than=21d&agents_list=all&status=never_connected,disconnected",
        auth_context
    )
    process_deleted_agents(response, auth_context)


if __name__ == "__main__":
    auth_context = get_auth_context()
    node_name = os.environ.get("NODE_NAME") or os.environ.get("HOSTNAME")
    
    if not node_name:
         logger.error("NODE_NAME or HOSTNAME not set")
         sys.exit(2)

    logger.info(f"Delete agent {node_name}")
    delete_agent(node_name, auth_context)
