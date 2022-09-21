FROM  bitnami/minideb:latest-amd64
LABEL maintainer="medvedev.yp@gmail.com"
LABEL version="4.0.4"
LABEL description="Wazuh Docker Agent"
ENV JOIN_MANAGER_MASTER_HOST=""
ENV JOIN_MANAGER_WORKER_HOST=""
ENV VIRUS_TOTAL_KEY=""
ENV JOIN_MANAGER_PROTOCOL="https"
ENV JOIN_MANAGER_USER = ""
ENV JOIN_MANAGER_PASSWORD=""
ENV JOIN_MANAGER_API_PORT="55000"
ENV HEALTH_CHECK_PROCESSES=""
ENV FLASK_APP="register_agent.py"
ENV FLASK_ENV="development"
ENV FLASK_DEBUG=0
ENV FLASK_BIND=0.0.0.0
RUN install_packages \
  procps curl apt-transport-https gnupg2 inotify-tools python-docker python3-pip python3-setuptools python3-dev gcc && \
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && \
  echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list && \
  install_packages wazuh-agent && \
  echo "deb http://security.debian.org/debian-security stretch/updates main" >> /etc/apt/sources.list && \
  mkdir -p /usr/share/man/man1 && \
  install_packages openjdk-8-jdk
COPY . /var/ossec/
WORKDIR /var/ossec/
RUN pip3 --no-cache-dir install -r /var/ossec/requirements.txt && \
  rm -rf /var/ossec/requirements.txt && \
  chmod +x /var/ossec/register_agent.py && \
  apt-get remove --purge -y python3-dev gcc && \
  apt-get clean autoclean && \
  apt-get autoremove -y && \
  rm -rf /var/lib/{apt,dpkg,cache,log}/ && \
  rm -rf  /tmp/* /var/tmp/* /var/log/*
EXPOSE 5000
ENTRYPOINT ["./register_agent.py"]
