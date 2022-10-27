
# docker-wazuh-agent

Wazuh is a free, open source and enterprise-ready security monitoring
solution for threat detection, integrity monitoring, incident response and compliance.

## Description

Wazuh Agent as Docker Image with auto registration on Wazuh server.

As well as local docker You can deploy the image to Kubernetes as DaemonSet.

Current agent version is `4.3.9`

## Structure

`register_agent.py` - Simple script for auto register docker based agent

`cleanup_agents.py` - Cleanup disconnected or never connected agents older than n days

`deregister_agent.py` - Simple de-registration of agent

## Environments

`JOIN_MANAGER_PROTOCOL` - http or https, default `https`

`JOIN_MANAGER_MASTER_HOST` - Ip address or Domain name of Wazuh server

`JOIN_MANAGER_WORKER_HOST` - Ip address or Domain name of Wazuh worker

`JOIN_MANAGER_USER` - Username for authorization on Wazuh server

`JOIN_MANAGER_PASSWORD` - Password for authorization

`JOIN_MANAGER_API_PORT` - Wazuh server api port, default `55000`

`JOIN_MANAGER_PORT` - Wazuh server port for communication between agent and server,
defaul `1514`

`NODE_NAME` - Node name if not present image will use `HOSTNAME` system variable

`HEALTH_CHECK_PROCESSES` - process list for health checks determinate by comma

`VIRUS_TOTAL_KEY` - Api key for VirusTotal integration

`FLASK_DEBUG` - Switch on Flask debug, default `0`

## Run as docker image

The Simplest way of running the container

```shell
docker run --rm kennyopennix/wazuh-agent:latest
```

Advanced usage

```bash
docker run -d --name wazuh -v /:/rootfs:ro --net host --hostname ${HOSTNAME} \
-e JOIN_MANAGER_MASTER_HOST=172.17.0.1 -e JOIN_MANAGER_WORKER_HOST=172.17.0.1 \
-e JOIN_PASSWORD=test123 -e JOIN_MANAGER_USER=user \
-v /etc/os-release:/etc/os-release -v /var/run/docker.sock:/var/run/docker.sock \
 kennyopennix/wazuh-agent:latest

```

## Run as Kubernetes DaemonSet

Setup environments in `wazuh-daemon-sets.yaml` like above.

Example:

```yaml
env:
    - name: JOIN_MANAGER_MASTER_HOST
      value: "wazuh.wazuh.svc.cluster.local"
    - name: JOIN_MANAGER_WORKER_HOST
      value: "wazuh-workers.wazuh.svc.cluster.local"
    - name: JOIN_MANAGER_PROTOCOL
      value: "https"
    - name: NODE_NAME
      valueFrom:
        fieldRef:
          fieldPath: spec.nodeName
    - name: WAZUH_GROUPS
      value: default
    - name: JOIN_MANAGER_USER
      valueFrom:
       secretKeyRef:
         name: wazuh-api-cred
         key: username
    - name: JOIN_MANAGER_PASSWORD
      valueFrom:
        secretKeyRef:
          name: wazuh-api-cred
          key: password
    - name: JOIN_MANAGER_API_PORT
      value: "55000"
    - name: JOIN_MANAGER_PORT
      value: "1514"
    - name: HEALTH_CHECK_PROCESSES
      value: "ossec-execd,ossec-syscheckd,ossec-logcollector,wazuh-modulesd,ossec-authd"

```

And apply template ```kubectl -f wazuh-daemon-sets.yaml```
DaemonSet will deploy to wazuh namespace.

## Build docker image

```bash
docker build . -t wazuh-agent:latest
```
