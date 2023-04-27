set -e

docker build . -f consul-k8s-24.amd.Dockerfile -t hashiderek/consul-k8s:0.24.0-k8s1.22-amd64 --platform linux/amd64
docker build . -f consul-k8s-24.arm.Dockerfile -t hashiderek/consul-k8s:0.24.0-k8s1.22-arm64 --platform linux/arm64

#docker push hashiderek/consul-k8s:0.24.0-k8s1.22-amd64 
#docker push hashiderek/consul-k8s:0.24.0-k8s1.22-arm64

docker manifest create hashiderek/consul-k8s:0.24.0-k8s1.22 \
--amend hashiderek/consul-k8s:0.24.0-k8s1.22-amd64 \
--amend hashiderek/consul-k8s:0.24.0-k8s1.22-arm64

docker manifest push --purge hashiderek/consul-k8s:0.24.0-k8s1.22

#docker tag hashiderek/consul-k8s-control-plane:0.33.0-2-arm64 k3d-registry.localhost:5000/control-plane-dev
#docker push k3d-registry.localhost:5000/control-plane-dev
