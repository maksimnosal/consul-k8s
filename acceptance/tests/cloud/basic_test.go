// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloud

import (
	"testing"
	"time"

	"github.com/hashicorp/consul-k8s/acceptance/framework/consul"
	"github.com/hashicorp/consul-k8s/acceptance/framework/environment"
	"github.com/hashicorp/consul-k8s/acceptance/framework/helpers"
	"github.com/hashicorp/consul-k8s/acceptance/framework/k8s"
)

var (
	resourceSecretName     = "resource-sec-name"
	resourceSecretKey      = "resource-sec-key"
	resourceSecretKeyValue = "organization/11eb1a35-aac0-f7c7-8fe1-0242ac110008/project/11eb1a35-ab64-d576-8fe1-0242ac110008/hashicorp.consul.global-network-manager.cluster/TEST"

	clientIDSecretName     = "clientid-sec-name"
	clientIDSecretKey      = "clientid-sec-key"
	clientIDSecretKeyValue = "clientid"

	clientSecretName     = "client-sec-name"
	clientSecretKey      = "client-sec-key"
	clientSecretKeyValue = "client-secret"

	apiHostSecretName = "apihost-sec-name"
	apiHostSecretKey  = "apihost-sec-key"
	// helloworldsvc.test.svc.cluster.local:9111
	apiHostSecretKeyValue = "fake-server:443" //TODO this will be the name of the test service

	authUrlSecretName     = "authurl-sec-name"
	authUrlSecretKey      = "authurl-sec-key"
	authUrlSecretKeyValue = "https://fake-server:443" //TODO this will be the name of the test service

	scadaAddressSecretName     = "scadaaddress-sec-name"
	scadaAddressSecretKey      = "scadaaddress-sec-key"
	scadaAddressSecretKeyValue = "fake-server:443" //TODO this will be the name of the test service

)

func TestBasicCloud(t *testing.T) {
	ctx := suite.Environment().DefaultContext(t)

	kubectlOptions := ctx.KubectlOptions(t)
	ns := kubectlOptions.Namespace
	k8sClient := environment.KubernetesClientFromOptions(t, kubectlOptions)

	cfg := suite.Config()
	consul.CreateK8sSecret(t, k8sClient, cfg, ns, resourceSecretName, resourceSecretKey, resourceSecretKeyValue)
	consul.CreateK8sSecret(t, k8sClient, cfg, ns, clientIDSecretName, clientIDSecretKey, clientIDSecretKeyValue)
	consul.CreateK8sSecret(t, k8sClient, cfg, ns, clientSecretName, clientSecretKey, clientSecretKeyValue)
	consul.CreateK8sSecret(t, k8sClient, cfg, ns, apiHostSecretName, apiHostSecretKey, apiHostSecretKeyValue)
	consul.CreateK8sSecret(t, k8sClient, cfg, ns, authUrlSecretName, authUrlSecretKey, authUrlSecretKeyValue)
	consul.CreateK8sSecret(t, k8sClient, cfg, ns, scadaAddressSecretName, scadaAddressSecretKey, scadaAddressSecretKeyValue)

	k8s.DeployKustomize(t, ctx.KubectlOptions(t), cfg.NoCleanupOnFailure, cfg.DebugDirectory, "../fixtures/bases/cloud-hcp-mock")

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
		"global.cloud.apiTLS":             "insecure",

		"global.cloud.scadaAddress.secretName": scadaAddressSecretName,
		"global.cloud.scadaAddress.secretKey":  scadaAddressSecretKey,
		"global.cloud.scadaTLS":                "insecure",

		"global.acls.manageSystemACLs":         "true",
		"global.tls.enabled":                   "true",
		"global.gossipEncryption.autoGenerate": "true",
		"global.tls.enableAutoEncrypt":         "true",
		"global.image":                         "hashicorpdev/consul:latest",
	}
	consulCluster := consul.NewHelmCluster(t, helmValues, suite.Environment().DefaultContext(t), suite.Config(), releaseName)

	consulCluster.Create(t)

	time.Sleep(1 * time.Hour)

}

// cloud:
// # If true, the Helm chart will enable the installation of an HCP Consul
// # self-managed cluster.
// enabled: false

// # The name of the Kubernetes secret that holds the HCP resource id.
// # This is required when global.cloud.enabled is true.
// resourceId:
//   # The name of the Kubernetes secret that holds the resource id.
//   # @type: string
//   secretName: null
//   # The key within the Kubernetes secret that holds the resource id.
//   # @type: string
//   secretKey: null

// # The name of the Kubernetes secret that holds the HCP cloud client id.
// # This is required when global.cloud.enabled is true.
// clientId:
//   # The name of the Kubernetes secret that holds the client id.
//   # @type: string
//   secretName: null
//   # The key within the Kubernetes secret that holds the client id.
//   # @type: string
//   secretKey: null

// # The name of the Kubernetes secret that holds the HCP cloud client secret.
// # This is required when global.cloud.enabled is true.
// clientSecret:
//   # The name of the Kubernetes secret that holds the client secret.
//   # @type: string
//   secretName: null
//   # The key within the Kubernetes secret that holds the client secret.
//   # @type: string
//   secretKey: null

// # The name of the Kubernetes secret that holds the HCP cloud client id.
// # This is optional when global.cloud.enabled is true.
// apiHost:
//   # The name of the Kubernetes secret that holds the api hostname.
//   # @type: string
//   secretName: null
//   # The key within the Kubernetes secret that holds the api hostname.
//   # @type: string
//   secretKey: null

// # The name of the Kubernetes secret that holds the HCP cloud authorization url.
// # This is optional when global.cloud.enabled is true.
// authUrl:
//   # The name of the Kubernetes secret that holds the authorization url.
//   # @type: string
//   secretName: null
//   # The key within the Kubernetes secret that holds the authorization url.
//   # @type: string
//   secretKey: null

// # The name of the Kubernetes secret that holds the HCP cloud scada address.
// # This is optional when global.cloud.enabled is true.
// scadaAddress:
//   # The name of the Kubernetes secret that holds the scada address.
//   # @type: string
//   secretName: null
//   # The key within the Kubernetes secret that holds the scada address.
//   # @type: string
//   secretKey: null
