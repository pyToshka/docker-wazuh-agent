#!/usr/bin/env python3

import json
import os
import sys
from subprocess import PIPE, Popen  # nosec

import psutil
import urllib3
from base64 import b64encode
from flask import Flask
from healthcheck import HealthCheck, EnvironmentDump
from jinja2 import Template
from loguru import logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
try:
    import requests
except ModuleNotFoundError as e:
    logger.error("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

app = Flask(__name__)
health = HealthCheck()
envs = EnvironmentDump()


def create_config_file():
    with open("ossec.jinja2") as file_:
        template = Template(file_.read())
        config = template.render(
            join_manager_hostname=join_manager_worker,
            join_manager_port=join_manager_port,
            virus_total_key=virus_total_key,
        )
    wazuh_config_file = open("/var/ossec/etc/ossec.conf", "w")
    wazuh_config_file.write(f"{config} \n")
    wazuh_config_file.close()
    open("/var/ossec/etc/local_internal_options.conf", "wb").write(
        open("local_internal_options.jinja2", "rb").read()
    )


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
        logger.error(f"Error: {resource}")
        sys.exit(1)

    return code, res_json


def application_data():
    return dict(maintainer="Yuriy Medvedev", git="https://github.com/pyToshka")


def check_ossec_agentd():
    process_name = health_checks.split(",")
    processes_name_list = {}
    for proc in psutil.process_iter():
        for process in process_name:
            if process in proc.name():
                processes_name_list[process] = "ok"
    return True, f"{processes_name_list}"


def check_self():
    process_name = os.path.basename(__file__)
    for proc in psutil.process_iter():
        for process in process_name:
            if process in proc.name():
                return True, "register_agent ok"


health.add_check(check_ossec_agentd)
health.add_check(check_self)
envs.add_section("application", application_data)
app.add_url_rule("/healz", "healthcheck", view_func=lambda: health.run())
app.add_url_rule("/envs", "environment", view_func=lambda: envs.run())


def code_desc(http_status_code):
    return requests.status_codes._codes[http_status_code][0]


def add_agent(agt_name, agt_ip=None):
    if agt_ip:
        status_code, response = req(
            "post", "agents", {"name": agt_name, "ip": agt_ip}
        )
    else:
        status_code, response = req(
            "post", "agents", {"name": str(agt_name)}
        )

    if status_code == 200 and response["error"] == 0:
        r_id = response["data"]["id"]
        r_key = response["data"]["key"]
        return r_id, r_key
    elif status_code == 400:
        status_code, response = req("get", f"agents?pretty=true&q=name={agt_name}")
        for items in response["data"]["affected_items"]:
            status_code, response = req("delete", f"agents?pretty=true&older_than=0s&agents_list={items['id']}&status=all")
            msg = json.dumps(response, indent=4, sort_keys=True)
            code = f"Status: {status_code} - {code_desc(status_code)}"
            logger.error(f"INFO - DELETE AGENT:\n{code}\n{msg}")
    else:
        msg = json.dumps(response, indent=4, sort_keys=True)
        code = f"Status: {status_code} - {code_desc(status_code)}"
        logger.error(f"ERROR - ADD AGENT:\n{code}\n{msg}")


def info_agent(agt_name, pretty=None):
    if pretty:
        status_code, response = req("get", f"agents?pretty=true&q=name={agt_name}")
    else:
        status_code, response = req("get", f"agents?q=name={agt_name}")
    if status_code == 200 and response["error"] == 0:
        for items in response["data"]["affected_items"]:
            name = items["name"]
            status = items["status"]
        return name, status
    else:
        msg = json.dumps(response, indent=4, sort_keys=True)
        code = f"Status: {status_code} - {code_desc(status_code)}"
        logger.error(f"ERROR - ADD AGENT:\n{code}\n{msg}")
        exit(1)


def import_key(agent_key):
    cmd = "/var/ossec/bin/manage_agents"
    std_out, std_err, r_code = execute([cmd, "-i", agent_key], "y\n\n")
    if r_code != 0:
        logger.error(f"ERROR - Import key:{std_err}")
        exit(1)
    else:
        logger.info(f"INFO - Key has been imported {std_out}")


def execute(cmd_list, stdin=None):
    p = Popen(
        cmd_list,
        stdin=PIPE,
        stdout=PIPE,
        stderr=PIPE,
        encoding="utf8",
        shell=False,  # nosec
    )
    std_out, std_err = p.communicate(stdin)
    return_code = p.returncode
    return std_out, std_err, return_code


def restart_ossec():
    cmd = "/var/ossec/bin/wazuh-control"
    std_out, std_err, r_code = execute([cmd, "restart"])
    restarted = False

    for line_output in std_out.split(os.linesep):
        if "Completed." in line_output:
            restarted = True
            logger.info("INFO - Restart completed")
            break

    if not restarted:
        logger.error(f"ERROR - Restarting OSSEC:{std_err}")
        exit(1)


def status_ossec():
    cmd = "/var/ossec/bin/wazuh-control"
    std_out, std_err, r_code = execute([cmd, "status"])
    status = False
    for line_output in std_out.split(os.linesep):
        if "running." in line_output:
            status = True
            logger.info("INFO - OSSEC up and running")
            break
    if not status:
        logger.error(f"ERROR - OSSEC STATUS:{std_err}")
        exit(1)


if __name__ == "__main__":
    try:
        protocol = os.environ.get("JOIN_MANAGER_PROTOCOL")
        host = os.environ.get("JOIN_MANAGER_MASTER_HOST")
        user = os.environ.get("JOIN_MANAGER_USER")
        password = os.environ.get("JOIN_MANAGER_PASSWORD")
        node_name = os.environ.get("NODE_NAME")
        port = os.environ.get("JOIN_MANAGER_API_PORT")
        join_manager_port = os.environ.get("JOIN_MANAGER_PORT")
        groups = os.environ.get("WAZUH_GROUPS")
        health_checks = os.environ.get("HEALTH_CHECK_PROCESSES")
        virus_total_key = os.environ.get("VIRUS_TOTAL_KEY")
        join_manager_worker = os.environ.get("JOIN_MANAGER_WORKER_HOST")
        flask_bind = os.environ.get("FLASK_BIND")
        if "," not in groups:
            groups = "default,"
            group_list = list(groups.split(","))
        else:
            group_list = list(groups.split(","))
        if not node_name:
            node_name = os.environ.get("HOSTNAME")
        if not protocol:
            protocol = "https"
        if not (
            protocol and host and user and node_name and join_manager_port,
            groups,
            join_manager_worker,
        ):
            raise KeyError

    except KeyError as error:
        logger.error(f"Please check system variable {error}")
        exit(2)

    login_endpoint = "security/user/authenticate"
    base_url = f"{protocol}://{host}:{port}"
    login_url = f"{protocol}://{host}:{port}/{login_endpoint}"
    auth = f"{user}:{password}".encode()

    verify = False
    logger.info(f"Adding agent with name {node_name}")
    agent_id, agent_key = add_agent(node_name)
    logger.info(f"Agent '{node_name}' with ID '{agent_id}' added.")
    logger.info(f"Importing authentication key for agent {node_name}")
    import_key(agent_key.encode())
    logger.info(f"Create OSSEC configuration for agent {node_name}")
    create_config_file()
    logger.info(f"Restarting. Agent {node_name}.....")
    restart_ossec()
    logger.info(f"Getting status of OSSEC processes for agent {node_name}......")
    status_ossec()
    status = True
    while status:
        agent_name, agent_status = info_agent(node_name)
        if agent_status == "active":
            logger.info(
                f"Agent '{agent_name}' is ready and connected,  status - '{agent_status}......"
            )
            logger.info(
                f"Agent {agent_name} has been connected to server {join_manager_worker}......"
            )
            status = False
        else:
            logger.info(
                f"Waiting for agent {agent_name} become ready current status is {agent_status}......"
            )
    app.run(host=flask_bind)
