VERSION ?= v4.3.10

all: docker

docker:
	docker build -t kennyopennix/wazuh-agent:latest .  && \
	docker build -t kennyopennix/wazuh-agent:$(VERSION) .

docker-run:
	docker run kennyopennix/wazuh-agent:$(VERSION)

docker-push:
	docker push kennyopennix/wazuh-agent:latest && \
	docker push kennyopennix/wazuh-agent:$(VERSION)

docker-buildx:
	docker buildx build --push -t kennyopennix/wazuh-agent:$(VERSION) --cache-to type=local,dest=./tmp/ --cache-from type=local,src=./tmp/ .
