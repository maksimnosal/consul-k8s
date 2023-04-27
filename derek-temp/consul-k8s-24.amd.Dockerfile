FROM hashicorp/consul-k8s:0.24.0

COPY ./consul-k8s_linux_amd64 ./bin/consul-k8s
