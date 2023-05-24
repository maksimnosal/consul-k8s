#!/usr/bin/env bats

load _helpers

@test "apiGateway/GatewayClass: enabled by default" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/gateway-gatewayclass.yaml  \
      . | tee /dev/stderr |
      yq 'length > 0' | tee /dev/stderr)
  [ "${actual}" = "true" ]
}

@test "apiGateway/GatewayClass: disabled with connectInject.enabled" {
  cd `chart_dir`
  assert_empty helm template \
      -s templates/gateway-gatewayclass.yaml  \
      --set 'connectInject.enabled=false' \
      .
}

@test "apiGateway/GatewayClass: disabled with connectInject.apiGateway.managedGatewayClass.enabled" {
  cd `chart_dir`
  assert_empty helm template \
      -s templates/gateway-gatewayclass.yaml  \
      --set 'connectInject.apiGateway.managedGatewayClass.enabled=false' \
      .
}
