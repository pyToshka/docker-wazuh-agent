import json
import os
from loguru import logger
from wazuh_utils import wazuh_request, code_desc, get_auth_context, process_deleted_agents

def cleanup_agent(older, auth_context):
    _, response = wazuh_request(
        "delete",
        f"agents?pretty=true&older_than={older}&agents_list=all&status=never_connected,"
        f"disconnected",
        auth_context
    )
    process_deleted_agents(response, auth_context)


if __name__ == "__main__":
    auth_context = get_auth_context()
    older_than = os.environ.get("OLDER_THAN") or "21d"
    
    cleanup_agent(older_than, auth_context)
