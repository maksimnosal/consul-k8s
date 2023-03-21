#!/bin/bash

# Compile the control plane
make control-plane-dev-docker
docker tag consul-k8s-control-plane-dev tecke/consul-k8s-control-plane-dev
docker push tecke/consul-k8s-control-plane-dev

# Use Helm to install 
helm install consul ./charts/consul -f testvalues.yaml
