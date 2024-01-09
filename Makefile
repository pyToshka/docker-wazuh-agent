VERSION ?= v4.3.10
.PHONY: help
help: ## Help for usage
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
all: docker

build-minideb: ## Build Wazuh Agent minideb based
	docker build -t kennyopennix/wazuh-agent:latest .  && \
	docker tag kennyopennix/wazuh-agent:latest kennyopennix/wazuh-agent:$(VERSION)

build-amazon-linux: ## Build Wazuh Agent amazon linux based
	docker build -f ./images/Dockerfie.amazonlinux -t kennyopennix/wazuh-agent-amazonlinux:latest .  && \
	docker tag kennyopennix/wazuh-agent-amazonlinux:latest kennyopennix/wazuh-agent-amazonlinux:$(VERSION)

build-ubuntu: ## Build Wazuh Agent ubuntu linux based
	docker build -f ./images/Dockerfie.ubuntu -t kennyopennix/wazuh-agent-ubuntu:latest .  && \
	docker tag kennyopennix/wazuh-agent-ubuntu:latest kennyopennix/wazuh-agent-ubuntu:$(VERSION)

docker-run: ## Run Wazuh Agent docker image  minideb based
	docker run kennyopennix/wazuh-agent:$(VERSION)

docker-push-minideb: ## Push Wazuh Agent docker image  minideb based
	docker push kennyopennix/wazuh-agent:latest && \
	docker push kennyopennix/wazuh-agent:$(VERSION)

docker-push-amazon-linux: ## Push Wazuh Agent docker image amazon linux based
	docker push kennyopennix/wazuh-agent-amazonlinux:latest && \
	docker push kennyopennix/wazuh-agent-amazonlinux:$(VERSION)

docker-push-ubuntu: ## Push Wazuh Agent docker image ubuntu linux based
	docker push kennyopennix/wazuh-agent-ubuntu:latest && \
	docker push kennyopennix/wazuh-agent-ubuntu:$(VERSION)

docker-buildx:
	docker buildx build --push -t kennyopennix/wazuh-agent:$(VERSION) --cache-to type=local,dest=./tmp/ --cache-from type=local,src=./tmp/ .

run-local: ## Run docker compose stack with all agents on board
	docker compose -f tests/single-node/generate-indexer-certs.yml run --rm generator
	docker compose -f docker-compose.yml up -d --build
