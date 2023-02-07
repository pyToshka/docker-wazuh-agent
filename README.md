
# docker-wazuh-agent

Wazuh is a free, open source and enterprise-ready security monitoring
solution for threat detection, integrity monitoring, incident response and compliance.

## Description

Wazuh Agent as Docker Image with auto registration on Wazuh server.

Current implementation could be run as standalone docker container as well as Kubernete DaemonSet

 Agent version is `v4.3.10`



## Structure

`register_agent.py` - Auto register docker based agent

`cleanup_agents.py` - Cleanup disconnected or never connected agents older than n days

`deregister_agent.py` -  De-registration of agent

## Environments

| Name                       | Type     | Description                                                  | Default   | Required |
| -------------------------- | -------- | ------------------------------------------------------------ | --------- | -------- |
| `JOIN_MANAGER_PROTOCOL`    | `string` | Http or https protocol for Wazuh restapi connection          | `https`   | `Yes`    |
| `JOIN_MANAGER_MASTER_HOST` | `string` | Ip address or Domain name of Wazuh server using for restapi calls | `None`    | `Yes`    |
| `JOIN_MANAGER_WORKER_HOST` | `string` | Ip address or Domain name of Wazuh worker for agent connection, if using ALL in One installation the same value as for `JOIN_MANAGER_MASTER_HOST` | `None`    | `Yes`    |
| `JOIN_MANAGER_USER`        | `string` | Username for Wazuh API autorization                          | `None`    | `Yes`    |
| `JOIN_MANAGER_PASSWORD`    | `string` | Password for Wazuh API autorization                          | `None`    | `Yes`    |
| `JOIN_MANAGER_API_PORT`    | `string` | Port where the Wazuh API listened                            | `55000`   | `Yes`    |
| `JOIN_MANAGER_PORT`        | `string` | Wazuh server port for communication between agent and server | `1514`    | `Yes`    |
| `NODE_NAME`                | `string` | Node name if not present image will use `HOSTNAME` system variable | `None`    | `No`     |
| `VIRUS_TOTAL_KEY`          | `string` | Api key for VirusTotal integration                           | `None`    | `No`     |
| `WAZUH_GROUPS`             | `string` | Group(s) name comma separated for auto adding agent,         | `default` | `No`     |

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

```

And apply template ```kubectl -f wazuh-daemon-sets.yaml```
DaemonSet will deploy to wazuh namespace.

## Build docker image

```bash
docker build . -t wazuh-agent:latest
```
