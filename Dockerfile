FROM  bitnami/minideb@sha256:2c269eaa9fbb84eddaa738296b95b336487587e13b9012d20a9bf3165d7ae93e as builder
COPY requirements.txt /tmp
RUN install_packages python3-pip python3-setuptools python3-dev gcc && \
     python3 -m pip wheel -w /tmp/wheel -r /tmp/requirements.txt

FROM bitnami/minideb@sha256:2c269eaa9fbb84eddaa738296b95b336487587e13b9012d20a9bf3165d7ae93e
LABEL maintainer="support@opennix.ru"
LABEL description="Wazuh Docker Agent"
ARG AGENT_VERSION="4.3.10-1"
ENV JOIN_MANAGER_MASTER_HOST=""
ENV JOIN_MANAGER_WORKER_HOST=""
ENV VIRUS_TOTAL_KEY=""
ENV JOIN_MANAGER_PROTOCOL="https"
ENV JOIN_MANAGER_USER=""
ENV JOIN_MANAGER_PASSWORD=""
ENV JOIN_MANAGER_API_PORT="55000"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
RUN install_packages \
  procps curl apt-transport-https gnupg2 inotify-tools python3-docker python3-setuptools python3-pip && \
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && \
  echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list && \
  install_packages wazuh-agent=${AGENT_VERSION}  && \
  echo "deb http://deb.debian.org/debian-security/ bullseye-security main contrib non-free" >> /etc/apt/sources.list && \
  mkdir -p /usr/share/man/man1 && \
  install_packages openjdk-11-jdk

COPY *.py *.jinja2  /var/ossec/
WORKDIR /var/ossec/
COPY --from=builder /tmp/wheel /tmp/wheel
RUN pip3 install --break-system-packages --no-index /tmp/wheel/*.whl && \
  chmod +x /var/ossec/deregister_agent.py && \
  chmod +x /var/ossec/register_agent.py && \
  apt-get clean autoclean && \
  apt-get autoremove -y && \
  rm -rf /var/lib/{apt,dpkg,cache,log}/ && \
  rm -rf  /tmp/* /var/tmp/* /var/log/* && \
  chown -R wazuh:wazuh /var/ossec/
EXPOSE 5000
ENTRYPOINT ["./register_agent.py"]
