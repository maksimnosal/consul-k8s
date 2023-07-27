pushd ../
GOOS=linux GOARCH=arm64 go build -o custom-build/arm64.bin
GOOS=linux GOARCH=amd64 go build -o custom-build/amd64.bin
popd

docker build --platform linux/arm64 -t hashiderek/consul-k8s-control-plane:0.34.1-custom-arm64 -f Dockerfile.arm64 .
docker build --platform linux/amd64 -t hashiderek/consul-k8s-control-plane:0.34.1-custom-amd64 -f Dockerfile.amd64 .

docker push hashiderek/consul-k8s-control-plane:0.34.1-custom-arm64
docker push hashiderek/consul-k8s-control-plane:0.34.1-custom-amd64

docker manifest create hashiderek/consul-k8s-control-plane:0.34.1-custom \
--amend hashiderek/consul-k8s-control-plane:0.34.1-custom-arm64 \
--amend hashiderek/consul-k8s-control-plane:0.34.1-custom-amd64

docker manifest push hashiderek/consul-k8s-control-plane:0.34.1-custom
