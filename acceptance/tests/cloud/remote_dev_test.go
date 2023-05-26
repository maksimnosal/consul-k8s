// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloud

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/consul-k8s/cli/preset"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/consul-k8s/acceptance/framework/consul"
	"github.com/hashicorp/consul-k8s/acceptance/framework/environment"
	"github.com/hashicorp/consul-k8s/acceptance/framework/helpers"
	"github.com/hashicorp/consul-k8s/acceptance/framework/k8s"
	"github.com/hashicorp/consul-k8s/acceptance/framework/logger"

	hcpgnm "github.com/hashicorp/hcp-sdk-go/clients/cloud-global-network-manager-service/preview/2022-02-15/client/global_network_manager_service"
	"github.com/hashicorp/hcp-sdk-go/clients/cloud-global-network-manager-service/preview/2022-02-15/models"
	"github.com/hashicorp/hcp-sdk-go/httpclient"
	"github.com/hashicorp/hcp-sdk-go/resource"
)

type DevTokenResponse struct {
	Token string `json:"token"`
}

type hcp struct {
	HCPConfig *preset.HCPConfig
}

func TestRemoteDevCloud(t *testing.T) {
	ctx := suite.Environment().DefaultContext(t)

	kubectlOptions := ctx.KubectlOptions(t)
	ns := kubectlOptions.Namespace
	k8sClient := environment.KubernetesClientFromOptions(t, kubectlOptions)

	var (
		resourceSecretName     = "resource-sec-name"
		resourceSecretKey      = "resource-sec-key"
		resourceSecretKeyValue = os.Getenv("HCP_RESOURCE_ID")

		clientIDSecretName     = "clientid-sec-name"
		clientIDSecretKey      = "clientid-sec-key"
		clientIDSecretKeyValue = os.Getenv("HCP_CLIENT_ID")

		clientSecretName     = "client-sec-name"
		clientSecretKey      = "client-sec-key"
		clientSecretKeyValue = os.Getenv("HCP_CLIENT_SECRET")

		apiHostSecretName = "apihost-sec-name"
		apiHostSecretKey  = "apihost-sec-key"
		// helloworldsvc.test.svc.cluster.local:9111
		apiHostSecretKeyValue = "https://api.hcp.dev" //TODO this will be the name of the test service

		authUrlSecretName     = "authurl-sec-name"
		authUrlSecretKey      = "authurl-sec-key"
		authUrlSecretKeyValue = "https://auth.idp.hcp.dev" //TODO this will be the name of the test service

		scadaAddressSecretName     = "scadaaddress-sec-name"
		scadaAddressSecretKey      = "scadaaddress-sec-key"
		scadaAddressSecretKeyValue = "scada.internal.hcp.dev:7224" //TODO this will be the name of the test service

		bootstrapTokenSecretName = "bootstrap-token"
		bootstrapTokenSecretKey  = "token"
	)

	os.Setenv("HCP_AUTH_URL", authUrlSecretKeyValue)
	os.Setenv("HCP_API_HOST", apiHostSecretKeyValue)
	os.Setenv("HCP_SCADA_ADDRESS", scadaAddressSecretKeyValue)
	t.Cleanup(func() {
		os.Unsetenv("HCP_AUTH_URL")
		os.Unsetenv("HCP_API_HOST")
		os.Unsetenv("HCP_SCADA_ADDRESS")

	})

	presetCfg := preset.GetHCPPresetFromEnv(resourceSecretKeyValue)
	hcpCfg := hcp{HCPConfig: presetCfg}
	bootstrapCfg := hcpCfg.fetchAgentBootstrapConfig(t)

	cfg := suite.Config()
	consul.CreateK8sSecret(t, k8sClient, cfg, ns, resourceSecretName, resourceSecretKey, resourceSecretKeyValue)
	consul.CreateK8sSecret(t, k8sClient, cfg, ns, clientIDSecretName, clientIDSecretKey, clientIDSecretKeyValue)
	consul.CreateK8sSecret(t, k8sClient, cfg, ns, clientSecretName, clientSecretKey, clientSecretKeyValue)
	consul.CreateK8sSecret(t, k8sClient, cfg, ns, apiHostSecretName, apiHostSecretKey, apiHostSecretKeyValue)
	consul.CreateK8sSecret(t, k8sClient, cfg, ns, authUrlSecretName, authUrlSecretKey, authUrlSecretKeyValue)
	consul.CreateK8sSecret(t, k8sClient, cfg, ns, scadaAddressSecretName, scadaAddressSecretKey, scadaAddressSecretKeyValue)
	consul.CreateK8sSecret(t, k8sClient, cfg, ns, bootstrapTokenSecretName, bootstrapTokenSecretKey, bootstrapCfg.ConsulConfig.ACL.Tokens.InitialManagement)

	// k8s.DeployKustomize(t, ctx.KubectlOptions(t), cfg.NoCleanupOnFailure, cfg.DebugDirectory, "../fixtures/bases/cloud/hcp-mock")
	// podName, err := k8s.RunKubectlAndGetOutputE(t, ctx.KubectlOptions(t), "get", "pod", "-l", "app=fake-server", "-o", `jsonpath="{.items[0].metadata.name}"`)
	// podName = strings.ReplaceAll(podName, "\"", "")
	// if err != nil {
	// logger.Log(t, "error finding pod name")
	// return
	// }
	// logger.Log(t, "fake-server pod name:"+podName)
	// localPort := terratestk8s.GetAvailablePort(t)
	// tunnel := terratestk8s.NewTunnelWithLogger(
	// ctx.KubectlOptions(t),
	// terratestk8s.ResourceTypePod,
	// podName,
	// localPort,
	// 443,
	// logger.TestLogger{})

	// Retry creating the port forward since it can fail occasionally.
	// retry.RunWith(&retry.Counter{Wait: 5 * time.Second, Count: 60}, t, func(r *retry.R) {
	// 	// NOTE: It's okay to pass in `t` to ForwardPortE despite being in a retry
	// 	// because we're using ForwardPortE (not ForwardPort) so the `t` won't
	// 	// get used to fail the test, just for logging.
	// 	require.NoError(r, tunnel.ForwardPortE(t))
	// })

	// logger.Log(t, "fake-server addr:"+tunnel.Endpoint())
	// consulToken, err := requestToken(tunnel.Endpoint())
	// if err != nil {
	// 	logger.Log(t, "error finding consul token")
	// 	return
	// }
	// tunnel.Close()
	// logger.Log(t, "consul test token :"+consulToken)

	releaseName := helpers.RandomName()

	helmValues := map[string]string{
		"global.cloud.enabled":               "true",
		"global.cloud.resourceId.secretName": resourceSecretName,
		"global.cloud.resourceId.secretKey":  resourceSecretKey,

		"global.cloud.clientId.secretName": clientIDSecretName,
		"global.cloud.clientId.secretKey":  clientIDSecretKey,

		"global.cloud.clientSecret.secretName": clientSecretName,
		"global.cloud.clientSecret.secretKey":  clientSecretKey,

		"global.cloud.apiHost.secretName": apiHostSecretName,
		"global.cloud.apiHost.secretKey":  apiHostSecretKey,

		"global.cloud.authUrl.secretName": authUrlSecretName,
		"global.cloud.authUrl.secretKey":  authUrlSecretKey,

		"global.cloud.scadaAddress.secretName": scadaAddressSecretName,
		"global.cloud.scadaAddress.secretKey":  scadaAddressSecretKey,
		"connectInject.default":                "true",

		"global.acls.manageSystemACLs":          "true",
		"global.acls.bootstrapToken.secretName": bootstrapTokenSecretName,
		"global.acls.bootstrapToken.secretKey":  bootstrapTokenSecretKey,

		"global.gossipEncryption.autoGenerate": "false",
		"global.tls.enabled":                   "true",
		"global.tls.enableAutoEncrypt":         "true",
		"global.image":                         "consul:local",

		"telemetryCollector.enabled":                   "true",
		"telemetryCollector.image":                     "consul-telemetry-collector:local",
		"telemetryCollector.cloud.clientId.secretName": clientIDSecretName,
		"telemetryCollector.cloud.clientId.secretKey":  clientIDSecretKey,

		"telemetryCollector.cloud.clientSecret.secretName": clientSecretName,
		"telemetryCollector.cloud.clientSecret.secretKey":  clientSecretKey,
		// Either we set the global.trustedCAs (make sure it's idented exactly) or we
		// set TLS to insecure

		"telemetryCollector.extraEnvironmentVars.HCP_AUTH_TLS":    "insecure",
		"telemetryCollector.extraEnvironmentVars.HCP_SCADA_TLS":   "insecure",
		"telemetryCollector.extraEnvironmentVars.HCP_API_ADDRESS": apiHostSecretKeyValue,
		// "telemetryCollector.extraEnvironmentVars.OTLP_EXPORTER_TLS": "disabled",

		"server.extraEnvironmentVars.HCP_API_TLS":   "insecure",
		"server.extraEnvironmentVars.HCP_AUTH_TLS":  "insecure",
		"server.extraEnvironmentVars.HCP_SCADA_TLS": "insecure",

		// This is pregenerated CA used for testing. It can be replaced at any time and isn't
		// meant for anything other than testing
		// 		"global.trustedCAs[0]": `-----BEGIN CERTIFICATE-----
		// MIICrjCCAZYCCQD5LxMcnMY8rDANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDDA5m
		// YWtlLXNlcnZlci1jYTAeFw0yMzA1MTkxMjIwMzhaFw0zMzA1MTYxMjIwMzhaMBkx
		// FzAVBgNVBAMMDmZha2Utc2VydmVyLWNhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
		// MIIBCgKCAQEAwhbiII7sMultedFzQVhVZz5Ti+9lWrpZb8y0ZR6NaNvoxDPX151t
		// Adh5NegSeH/+351iDBGZHhmKECtBuk8FJgk88O7y8A7Yg+/lyeZd0SJTEeiYUe7d
		// sSaBTYSmixyn6s15Y5MVp9gM7t2YXrocRkFxDtdhLMWf0zwzJEwDouFMMiFZw5II
		// yDbI6UfwKyB8C8ln10+TcczbheaOMQ1jGn35YWAG/LEdutU6DO2Y/GZYQ41nyLF1
		// klqh34USQPVQSQW7R7GiDxyhh1fGaDF6RAzH4RerzQSNvvTHmBXIGurB/Hnu1n3p
		// CwWeatWMU5POy1es73S/EPM0NpWD5RabSwIDAQABMA0GCSqGSIb3DQEBCwUAA4IB
		// AQBayoTltSW55PvKVp9cmqGOBMlkIMKPd6Ny4bCb/3UF+3bzQmIblh3O3kEt7WoY
		// fA9vp+6cSRGVqgBfR2bi40RrerLNA79yywIZjfBMteNuRoul5VeD+mLyFCo4197r
		// Atl2TEx2kl2V8rjCsEBcTqKqetVOMLYEZ2tbCeUt1A/K7OzaJfHgelEYcsVt68Q9
		// /BLoo2UXfOpRrcsx7u7s5HPVbG3bx+1MvGJZ2C3i0B6agnkGDzEpoM4KZGxEefB9
		// DOHIJfie9d9BQD52nZh3SGHz0b3vfJ430XrQmaNZ26fuIEyIYrpvyAhBXckj2iTD
		// 1TXpqr/1D7EUbddktyhXTK9e
		// -----END CERTIFICATE-----`,
	}

	consulCluster := consul.NewHelmCluster(t, helmValues, suite.Environment().DefaultContext(t), suite.Config(), releaseName)
	consulCluster.Create(t)

	// TODO remove once Nick makes this part of the standard k8s run
	logger.Log(t, "creating proxy defaults that sets envoy_telemetry_collector_bind_socket_dir")
	kustomizeDir := "../fixtures/bases/cloud/proxydefaults"
	k8s.KubectlApplyK(t, ctx.KubectlOptions(t), kustomizeDir)
	helpers.Cleanup(t, cfg.NoCleanupOnFailure, func() {
		k8s.KubectlDeleteK(t, ctx.KubectlOptions(t), kustomizeDir)
	})

	logger.Log(t, "creating static-server deployment")
	k8s.DeployKustomize(t, ctx.KubectlOptions(t), cfg.NoCleanupOnFailure, cfg.DebugDirectory, "../fixtures/bases/static-server")
	time.Sleep(1 * time.Hour)

	// TODO: add in test assertions here

}

// fetchAgentBootstrapConfig use the resource-id, client-id, and client-secret
// to call to the agent bootstrap config endpoint and parse the response into a
// CloudBootstrapConfig struct.
func (c *hcp) fetchAgentBootstrapConfig(t *testing.T) *preset.CloudBootstrapConfig {
	hcpConfig := preset.GetHCPPresetFromEnv(c.HCPConfig.ResourceID)

	logger.Log(t, "Fetching Consul cluster configuration from HCP")
	httpClientCfg := httpclient.Config{}
	clientRuntime, err := httpclient.New(httpClientCfg)
	require.NoError(t, err)

	hcpgnmClient := hcpgnm.New(clientRuntime, nil)
	clusterResource, err := resource.FromString(hcpConfig.ResourceID)
	require.NoError(t, err)

	params := hcpgnm.NewAgentBootstrapConfigParams().
		WithID(clusterResource.ID).
		WithLocationOrganizationID(clusterResource.Organization).
		WithLocationProjectID(clusterResource.Project)

	resp, err := hcpgnmClient.AgentBootstrapConfig(params, nil)
	require.NoError(t, err)

	bootstrapConfig := resp.GetPayload()
	logger.Log(t, "HCP configuration successfully fetched.")

	return c.parseBootstrapConfigResponse(t, bootstrapConfig)
}

// parseBootstrapConfigResponse unmarshals the boostrap parseBootstrapConfigResponse
// and also sets the HCPConfig values to return CloudBootstrapConfig struct.
func (c *hcp) parseBootstrapConfigResponse(t *testing.T, bootstrapRepsonse *models.HashicorpCloudGlobalNetworkManager20220215AgentBootstrapResponse) *preset.CloudBootstrapConfig {
	var cbc preset.CloudBootstrapConfig
	var consulConfig preset.ConsulConfig
	err := json.Unmarshal([]byte(bootstrapRepsonse.Bootstrap.ConsulConfig), &consulConfig)
	require.NoError(t, err)

	cbc.ConsulConfig = consulConfig
	cbc.HCPConfig = *c.HCPConfig
	cbc.BootstrapResponse = bootstrapRepsonse

	return &cbc
}
