# docker-wazuh-agent

<a href="https://www.buymeacoffee.com/pyToshka" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>

Wazuh is a free, open source and enterprise-ready security monitoring
solution for threat detection, integrity monitoring, incident response and compliance.

## Disclaimer
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Description

**Wazuh Agent Docker Image with Auto-Registration on Wazuh Server**

The Wazuh Agent, encapsulated within a Docker image, comes equipped with an automatic registration feature for seamless integration with the Wazuh server. This versatile implementation is designed to function not only as a standalone Docker container but also as a Kubernetes DaemonSet.

*Key Features:*
1. **Containerization:** The Wazuh Agent is encapsulated within a Docker image, promoting portability and ease of deployment across various environments.

2. **Auto-Registration:** The agent is configured to automatically register with the Wazuh server, streamlining the onboarding process and eliminating manual intervention.

3. **Standalone Deployment:** The Docker container can be deployed as a standalone entity, offering flexibility for environments that do not utilize orchestration tools.

4. **Kubernetes Compatibility:** Integrated as a Kubernetes DaemonSet, the Wazuh Agent seamlessly scales across nodes within a Kubernetes cluster, ensuring comprehensive security coverage.


*Note:*
Always refer to the [official documentation](https://documentation.wazuh.com/current/getting-started/index.html) for detailed configuration options and additional customization possibilities.

This implementation offers a seamless and adaptable solution for incorporating Wazuh security monitoring into both standalone and orchestrated environments.

## Wazuh agent version

### Braking changes

*Wazuh agent v4.3.10* will reach its end of life (EOL) and the cessation of support on February 1, 2024.


>> Commencing on February 1, 2024, the main branch will incorporate the latest code.
>>
>> Exercise caution, as potential bugs may exist in this branch. It is crucial to migrate all your deployments to Docker image tags listed below for reference.


| GitHub branch/tag | Wazuh Agent version | EOL                | Docker image tag |
|-------------------|---------------------|--------------------|------------------|
| main              | v4.3.10             | v4.3.10 01.02.2024 | latest           |
| v4.7.2-1          | v4.7.2-1            | LTS                | 4.7.1            |
| v4.7.1-1          | v4.7.1-1            | LTS                | 4.7.1            |
| v4.6.0-1          | v4.6.0-1            | LTS                | 4.6.0            |
| v4.5.4-1          | v4.5.4-1            | LTS                | 4.5.4            |
| v4.4.5-1          | v4.4.5-1            | LTS                | 4.4.5            |

## DockerHub images

| Repository Name                                               | Description                                                 | Pull command                                     |
|---------------------------------------------------------------|-------------------------------------------------------------|--------------------------------------------------|
| https://hub.docker.com/r/opennix/wazuh-agent            | Wazuh agent based on Minideb                                | docker pull opennix/wazuh-agent                  |
| https://hub.docker.com/r/opennix/wazuh-agent-amazonlinux | Wazuh agent based on Amazon Linux version 2023.3.20231218.0 | docker pull opennix/wazuh-agent-amazonlinux |
| https://hub.docker.com/r/opennix/wazuh-agent-ubuntu     | Wazuh agent based on Ubuntu 24.04                           | docker pull opennix/wazuh-agent-ubuntu      |
|                                                               |                                                             |                                                  |


## Structure

`register_agent.py` - Auto register docker based agent

`cleanup_agents.py` - Cleanup disconnected or never connected agents older than N days

`deregister_agent.py` -  De-registration of agent

## Environments

| Name                       | Type     | Description                                                                                                                                       | Default   | Required |
|----------------------------|----------|---------------------------------------------------------------------------------------------------------------------------------------------------|-----------|----------|
| `JOIN_MANAGER_PROTOCOL`    | `string` | Http or https protocol for Wazuh restapi connection                                                                                               | `https`   | `Yes`    |
| `JOIN_MANAGER_MASTER_HOST` | `string` | Ip address or Domain name of Wazuh server using for restapi calls                                                                                 | `None`    | `Yes`    |
| `JOIN_MANAGER_WORKER_HOST` | `string` | Ip address or Domain name of Wazuh worker for agent connection, if using ALL in One installation the same value as for `JOIN_MANAGER_MASTER_HOST` | `None`    | `Yes`    |
| `JOIN_MANAGER_USER`        | `string` | Username for Wazuh API autorization                                                                                                               | `None`    | `Yes`    |
| `JOIN_MANAGER_PASSWORD`    | `string` | Password for Wazuh API autorization                                                                                                               | `None`    | `Yes`    |
| `JOIN_MANAGER_API_PORT`    | `string` | Port where the Wazuh API listened                                                                                                                 | `55000`   | `Yes`    |
| `JOIN_MANAGER_PORT`        | `string` | Wazuh server port for communication between agent and server                                                                                      | `1514`    | `Yes`    |
| `NODE_NAME`                | `string` | Node name if not present image will use `HOSTNAME` system variable                                                                                | `None`    | `No`     |
| `VIRUS_TOTAL_KEY`          | `string` | Api key for VirusTotal integration                                                                                                                | `None`    | `No`     |
| `WAZUH_GROUPS`             | `string` | Group(s) name comma separated for auto adding agent,                                                                                              | `default` | `No`     |
| `WAZUH_WAIT_TIME`          | `string` | Sleep for N second                                                                                                                                | `10`      | `No`     |

## Run as docker image

The Simplest way of running the container

```shell
docker run --rm opennix/wazuh-agent:latest
```
## Run docker-compose

Generate certificates
```shell
docker compose -f tests/single-node/generate-indexer-certs.yml run --rm generator
```

Run

```shell
docker compose up -d
```

Will run Wazuh cluster in single node mode and 3 agents

## Use Makefile
```shell
make
help                           Help for usage
build-minideb                  Build Wazuh Agent minideb based
build-amazon-linux             Build Wazuh Agent amazon linux based
build-ubuntu                   Build Wazuh Agent ubuntu linux based
docker-run                     Run Wazuh Agent docker image  minideb based
docker-push-minideb            Push Wazuh Agent docker image  minideb based
docker-push-amazon-linux       Push Wazuh Agent docker image amazon linux based
docker-push-ubuntu             Push Wazuh Agent docker image ubuntu linux based
run-local                      Run docker compose stack with all agents on board

```
## Advanced usage

```bash
docker run -d --name wazuh -v /:/rootfs:ro --net host --hostname ${HOSTNAME} \
-e JOIN_MANAGER_MASTER_HOST=172.17.0.1 -e JOIN_MANAGER_WORKER_HOST=172.17.0.1 \
-e JOIN_PASSWORD=test123 -e JOIN_MANAGER_USER=user \
-v /etc/os-release:/etc/os-release -v /var/run/docker.sock:/var/run/docker.sock \
 opennix/wazuh-agent

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

## Build local docker image

Building default image agent based on [Minideb](https://github.com/bitnami/minideb) with default Agent version `4.3.10-1`

```bash
docker build . -t wazuh-agent:latest
```

Building agent image based on [Amazon Linux](https://hub.docker.com/_/amazonlinux) with default Agent version `4.3.10-1`
```bash
docker build -f images/Dockerfile.amazonlinux . -t wazuh-agent:latest
```

Building agent image based on [Ubuntu 24.04](https://wiki.ubuntu.com/NobleNumbat) with default Agent version `4.3.10-1`
```bash
docker build -f images/Dockerfile.ubuntu . -t wazuh-agent:latest
```

Build agent image with custom agent version

```shell
 docker build -f path-to-docker-file . -t  wazuh-agent:<tag> --build-arg AGENT_VERSION=<wazuh-agent-version>
```

For example build minideb with Wazuh agent version `4.4.5-1`

```shell
 docker build . -t  wazuh-agent:latest --build-arg AGENT_VERSION=4.4.5-1
```
