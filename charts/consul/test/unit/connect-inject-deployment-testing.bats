#!/usr/bin/env bats

load _helpers

@test "connectInject/Deployment: tls-cert-dir flag is set to /etc/connect-injector/certs" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/connect-inject-deployment.yaml  \
      --set 'connectInject.enabled=true' \
      --set 'global.experiments[0]=resource-apis' \
      --set 'ui.enabled=false' \
                 . | tee /dev/stderr |
      yq '.spec.template.spec.containers[0].command | any(contains("-tls-cert-dir=/etc/connect-injector/certs"))' | tee /dev/stderr)

  [ "${actual}" = "true" ]
}