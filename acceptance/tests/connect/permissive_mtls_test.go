package connect

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/consul-k8s/acceptance/framework/connhelper"
	"github.com/hashicorp/consul-k8s/acceptance/framework/consul"
	"github.com/hashicorp/consul-k8s/acceptance/framework/envoy"
	"github.com/hashicorp/consul-k8s/acceptance/framework/helpers"
	"github.com/hashicorp/consul-k8s/acceptance/framework/k8s"
	"github.com/hashicorp/consul-k8s/acceptance/framework/logger"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/sdk/testutil/retry"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	mtlsStatName       = "tcp.public_listener.downstream_cx_total"
	permissiveStatName = "tcp.permissive_public_listener.downstream_cx_total"
)

func TestPermissiveMTLS_ConnectInject(t *testing.T) {
	cfg := suite.Config()
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

	kubectlOpts := connHelper.Ctx.KubectlOptions(t)

	connHelper.Setup(t)
	connHelper.Install(t)

	deployNonMeshClient(t, connHelper)
	connHelper.DeployClientAndServer(t)
	connHelper.CreateIntention(t)

	envoyHelper := envoy.NewEnvoyAdminHelper(connHelper, "app=static-server")

	envoyHelper.Setup(t)

	// requireEnvoyStats fetches and passes current Envoy stats to the check function.
	requireEnvoyStats := func(t *testing.T, check func(*retry.R, map[string]envoy.EnvoyStat)) {
		// Need to retry in order to wait until the Envoy stats flush internval.
		//
		// TODO: We could potentially avoid the retry by passing `stats_flush_on_admin: true`
		// so that Envoy flushes stats on each fetch, but I couldn't get this working in these tests.
		// I tried passing the Helm value `envoyExtraArgs=--config-yaml '{"stats_flush_on_admin": true}'
		// but couldn't figure out exactly how to get the shell quoting right.
		retry.Run(t, func(r *retry.R) {
			check(r, envoyHelper.GetStats(r).ToMap())
		})
	}

	logger.Logf(t, "Check that incoming mTLS connection succeeds in MutualTLSMode = strict")
	{
		envoyHelper.ResetCounters(t)
		k8s.CheckStaticServerConnectionSuccessful(t, kubectlOpts, "static-client", "http://static-server")

		requireEnvoyStats(t, func(r *retry.R, stats map[string]envoy.EnvoyStat) {
			// We check GreaterOrEqual, because:
			// - The readiness probe hits Envoy every 10 seconds, and may increments this stat.
			// - The CheckStaticServerConnectionSuccessful function retries until success.
			require.GreaterOrEqual(r, stats[mtlsStatName].Int(r), 1)

			// No filter chain for the permissive traffic, so no stats should be present.
			require.NotContains(r, stats, permissiveStatName)
		})
	}

	logger.Logf(t, "Check that incoming non-mTLS connection fails in MutualTLSMode = strict")
	{
		envoyHelper.ResetCounters(t)
		k8s.CheckStaticServerConnectionFailing(t, kubectlOpts, "non-mesh-client", "http://static-server")

		requireEnvoyStats(t, func(r *retry.R, stats map[string]envoy.EnvoyStat) {
			// We check LessOrEqual because:
			// - The readiness probe hits Envoy every 10 seconds, and may increments this stat.
			require.LessOrEqual(r, stats[mtlsStatName].Int(r), 1)

			// No filter chain for the permissive traffic, so no stats should be present.
			require.NotContains(r, stats, permissiveStatName)
		})
	}

	// TODO: Use a CRD for this.
	client := connHelper.ConsulClient(t)
	setMutualTLSMode(t, client, "static-server", api.MutualTLSModePermissive)

	// TODO: need ensure envoy config is updated before checking requests.
	time.Sleep(5)

	logger.Log(t, "Check that incoming mTLS connection is successful in MutualTLSMode = permissive")
	{
		envoyHelper.ResetCounters(t)
		k8s.CheckStaticServerConnectionSuccessful(t, kubectlOpts, "static-client", "http://static-server")

		requireEnvoyStats(t, func(r *retry.R, stats map[string]envoy.EnvoyStat) {
			// We check GreaterOrEqual, because:
			// - The readiness probe hits Envoy every 10 seconds, and may increments this stat.
			// - The CheckStaticServerConnectionSuccessful function retries until success.
			require.GreaterOrEqual(r, stats[mtlsStatName].Int(r), 1)
			// Nothing but our own requests should hit the permissive listener.
			require.Equal(r, stats[permissiveStatName].Int(r), 0)
		})
	}

	logger.Log(t, "Check that incoming non-mTLS connection is successful in MutualTLSMode = permissive")
	{
		envoyHelper.ResetCounters(t)
		k8s.CheckStaticServerConnectionSuccessful(t, kubectlOpts, "non-mesh-client", "http://static-server")

		requireEnvoyStats(t, func(r *retry.R, stats map[string]envoy.EnvoyStat) {
			// We check LessOrEqual because:
			// - The readiness probe hits Envoy every 10 seconds, and may increments this stat.
			require.LessOrEqual(r, stats[mtlsStatName].Int(r), 1)
			// We check GreaterOrEqual because:
			// - CheckStaticServerConnectionSuccessful retries until success
			require.GreaterOrEqual(r, stats[permissiveStatName].Int(r), 1)
		})
	}
}

func deployNonMeshClient(t *testing.T, ch connhelper.ConnectHelper) {
	t.Helper()
	logger.Log(t, "Creating non-mesh-client deployment.")

	opts := ch.Ctx.KubectlOptions(t)

	k8s.DeployKustomize(t, opts, ch.Cfg.NoCleanupOnFailure, ch.Cfg.DebugDirectory, "../fixtures/bases/non-mesh-client")

	podList, err := ch.Ctx.KubernetesClient(t).CoreV1().Pods(opts.Namespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: "app=non-mesh-client",
	})
	require.NoError(t, err)
	require.Len(t, podList.Items, 1)
	require.Len(t, podList.Items[0].Spec.Containers, 1)
}

func setMutualTLSMode(t *testing.T, client *api.Client, service string, mode api.MutualTLSMode) {
	t.Helper()
	logger.Log(t, "Set MutualTLSMode = %v for service %v", mode, service)

	_, _, err := client.ConfigEntries().Set(&api.ServiceConfigEntry{
		Kind:          api.ServiceDefaults,
		Name:          service,
		MutualTLSMode: mode,
	}, nil)
	require.NoError(t, err)
}
