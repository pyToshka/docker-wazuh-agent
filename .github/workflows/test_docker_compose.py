import json
import urllib3
import argparse

import requests
from base64 import b64encode, b64decode

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
protocol = "https"
host = "localhost"
port = 55000
user = "wazuh-wui"
password = "MyS3cr37P450r.*-"
login_endpoint = "security/user/authenticate"


def get_token():
    login_url = f"{protocol}://{host}:{port}/{login_endpoint}"
    basic_auth = f"{user}:{password}".encode()
    login_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {b64encode(basic_auth).decode()}",
    }

    response = requests.post(login_url, headers=login_headers, verify=False)
    token = json.loads(response.content.decode())["data"]["token"]
    return token


def test_list_agents():
    agents = []
    requests_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {get_token()}",
    }
    response = requests.get(
        f"{protocol}://{host}:{port}/agents?status=active",
        headers=requests_headers,
        verify=False,
    )
    for agent in response.json()["data"].get("affected_items"):
        if agent.get("name") == "wazuh.manager":
            pass
        else:
            agents.append((agent["name"]))
    assert response.status_code == 200
    assert len(agents) == 3, "Expected at least 3 agents, got {}".format(len(agents))
    assert (
        "wazuh-agent-minideb" in agents
    ), "Expected wazuh-agent-minideb to be in agent list"
    assert (
        "wazuh-agent-ubuntu" in agents
    ), "Expected wazuh-agent-ubuntu to be in agent list"
    assert (
        "wazuh-agent-amazonlinux" in agents
    ), "Expected wazuh-agent-amazonlinux to be in agent list"


def test_create_group():
    new_group = {"group_id": "wazuh-group"}

    requests_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {get_token()}",
    }

    response = requests.post(
        f"{protocol}://{host}:{port}/groups",
        headers=requests_headers,
        verify=False,
        json=new_group,
    )
    if response.status_code == 400:
        requests.delete(
            f"{protocol}://{host}:{port}/groups?groups_list=wazuh-group",
            headers=requests_headers,
            verify=False,
            json=new_group,
        )
        response = requests.post(
            f"{protocol}://{host}:{port}/groups",
            headers=requests_headers,
            verify=False,
            json=new_group,
        )
        print(response.content)
        assert response.status_code == 200
    else:
        assert response.status_code == 200


def test_agent_not_in_group():
    requests_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {get_token()}",
    }

    response = requests.get(
        f"{protocol}://{host}:{port}/agents/no_group",
        headers=requests_headers,
        verify=False,
    )
    assert response.status_code == 200


def test_add_agent_group():
    requests_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {get_token()}",
    }
    response = requests.get(
        f"{protocol}://{host}:{port}/agents?status=active",
        headers=requests_headers,
        verify=False,
    )
    for agent in response.json()["data"].get("affected_items"):
        if agent.get("name") == "wazuh.manager":
            pass
        else:
            response = requests.put(
                f'{protocol}://{host}:{port}/agents/{agent["id"]}/group/wazuh-group',
                headers=requests_headers,
                verify=False,
            )
            assert response.status_code == 200


def test_reset_agent_group():
    requests_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {get_token()}",
    }
    response = requests.get(
        f"{protocol}://{host}:{port}/agents?status=active",
        headers=requests_headers,
        verify=False,
    )
    for agent in response.json()["data"].get("affected_items"):
        if agent.get("name") == "wazuh.manager":
            pass
        else:
            response = requests.delete(
                f'{protocol}://{host}:{port}/agents/{agent["id"]}/group/wazuh-group',
                headers=requests_headers,
                verify=False,
            )
            assert response.status_code == 200
