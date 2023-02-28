package connect

import (
	"testing"

	"github.com/hashicorp/consul-k8s/acceptance/framework/connhelper"
	"github.com/hashicorp/consul-k8s/acceptance/framework/consul"
	"github.com/hashicorp/consul-k8s/acceptance/framework/helpers"
	"github.com/hashicorp/consul-k8s/acceptance/framework/k8s"
	"github.com/hashicorp/consul-k8s/acceptance/framework/logger"
	"github.com/hashicorp/consul/api"
	"github.com/stretchr/testify/require"
)

func TestPermissiveMTLS_ConnectInject(t *testing.T) {
	cfg := suite.Config()
	// TODO: forcing this for the test.
	cfg.EnableTransparentProxy = true
	ctx := suite.Environment().DefaultContext(t)

	releaseName := helpers.RandomName()
	connHelper := connhelper.ConnectHelper{
		ClusterKind: consul.Helm,
		Secure:      true,
		ReleaseName: releaseName,
		Ctx:         ctx,
		Cfg:         cfg,
	}

	connHelper.Setup(t)

	connHelper.Install(t)

	// Configure proxy-defaults with TLSMode = permissive.
	// 1. Use the consul api.
	// 2. Create a ProxyDefaults CRD.
	// TODO: for now we do (1) but need to support (2) eventually.
	client := connHelper.GimmeClient(t)
	setPermissiveMode(t, client, true)

	connHelper.DeployNonMeshClient(t)
	// TODO: Automate setting the TProxy exclude inbound port setting.
	connHelper.DeployClientAndServer(t)

	logger.Log(t, "checking that incoming non-mTLS connection is successful")
	// This should hit <k8s-service>:80 and then go to <pod>:8080 ?
	k8s.CheckStaticServerConnectionSuccessful(t, connHelper.Ctx.KubectlOptions(t), "static-client", "http://static-server")

	logger.Log(t, "checking that mTLS connections and intentions")
	connHelper.TestConnectionFailureWithoutIntention(t)
	connHelper.CreateIntention(t)

	connHelper.TestConnectionSuccess(t)
	connHelper.TestConnectionFailureWhenUnhealthy(t)
}

func setPermissiveMode(t *testing.T, client *api.Client, enabled bool) {
	_, _, err := client.ConfigEntries().Set(&api.ProxyConfigEntry{
		Kind:           api.ProxyDefaults,
		Name:           api.ProxyConfigGlobal,
		PermissiveMTLS: enabled,
	}, nil)
	require.NoError(t, err)
}
