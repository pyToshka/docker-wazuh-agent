VERSION ?= v4.0.4

all: docker

docker:
	docker build -t kennyopennix/wazuh-agent:latest .  && \
	docker build -t kennyopennix/wazuh-agent:$(VERSION) .

docker-run:
	docker run kennyopennix/wazuh-agent:$(VERSION)

docker-push:
	docker push kennyopennix/wazuh-agent:latest && \
	docker push kennyopennix/wazuh-agent:$(VERSION)
