// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package locality

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	terratestk8s "github.com/gruntwork-io/terratest/modules/k8s"
	"github.com/hashicorp/consul-k8s/acceptance/framework/config"
	"github.com/hashicorp/consul-k8s/acceptance/framework/consul"
	"github.com/hashicorp/consul-k8s/acceptance/framework/environment"
	"github.com/hashicorp/consul-k8s/acceptance/framework/helpers"
	"github.com/hashicorp/consul-k8s/acceptance/framework/k8s"
	"github.com/hashicorp/consul-k8s/acceptance/framework/logger"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/sdk/testutil/retry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	localPartition        = "ap1"
	localDatacenter       = "dc1"
	sameZoneDatacenter    = "dc2"
	sameRegionDatacenter  = "dc3"
	remoteDatacenter      = "dc4"
	staticClientNamespace = "ns1"
	staticServerNamespace = "ns2"

	keyLocal          = "server"
	keyLocalPartition = "partition"
	keySameZone       = "peer1"
	keySameRegion     = "peer2"
	keyRemote         = "peer3"

	staticServerDeployment = "deploy/static-server"
	staticClientDeployment = "deploy/static-client"

	localClusterName      = "cluster-01-a"
	partitionClusterName  = "cluster-01-b"
	sameZoneClusterName   = "cluster-02-a"
	sameRegionClusterName = "cluster-03-a"
	remoteClusterName     = "cluster-04-a"
)

func TestFailover_Connect(t *testing.T) {
	env := suite.Environment()
	cfg := suite.Config()

	if !cfg.EnableEnterprise {
		t.Skipf("skipping this test because -enable-enterprise is not set")
	}

	cases := []struct {
		name        string
		ACLsEnabled bool
	}{
		{
			"default failover",
			false,
		},
		{
			"secure failover",
			true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			/*
				Architecture Overview:						Region		Zone			Expected traffic priority

				Primary Datacenter (DC1)					us-east-1
					Default Partition
						Local Upstream 1								us-east-1a		1
						Local Upstream 2								us-east-1b		2
				    Partition AP1
						Local Upstream 3								us-east-1a		3
				Datacenter 2 (DC2)							us-east-1
					Default Partition
						Remote Upstream 1								us-east-1a		4
				Datacenter 3 (DC3)				us-east-2
					Default Partition
						Remote Upstream 2								us-east-2a		5
				Datacenter 4 (DC4)				us-west-1
					Default Partition
						Remote Upstream 3								us-west-1a		6


				Architecture Diagram + failover scenarios from perspective of DC1 Default Partition Static-Server
				is available in this directory at ./locality_test_arch_diagram.excalidraw
			*/

			members := map[string]*member{
				keyLocal:          {context: env.DefaultContext(t), hasServer: true},
				keyLocalPartition: {context: env.Context(t, 1), hasServer: false},
				keySameZone:       {context: env.Context(t, 2), hasServer: true},
				keySameRegion:     {context: env.Context(t, 3), hasServer: true},
				keyRemote:         {context: env.Context(t, 4), hasServer: true},
			}

			// Setup Namespaces.
			for _, v := range members {
				createNamespaces(t, cfg, v.context)
			}

			// Create the Default Cluster.
			commonHelmValues := map[string]string{
				"global.peering.enabled": "true",

				"global.tls.enabled":   "true",
				"global.tls.httpsOnly": strconv.FormatBool(c.ACLsEnabled),

				"global.enableConsulNamespaces": "true",

				"global.adminPartitions.enabled": "true",

				"global.logLevel": "debug",

				"global.acls.manageSystemACLs": strconv.FormatBool(c.ACLsEnabled),

				"connectInject.enabled":                       "true",
				"connectInject.consulNamespaces.mirroringK8S": "true",

				"meshGateway.enabled":  "true",
				"meshGateway.replicas": "1",

				"dns.enabled": "true",
			}

			defaultPartitionHelmValues := map[string]string{
				"global.datacenter": localDatacenter,
			}

			// On Kind, there are no load balancers but since all clusters
			// share the same node network (docker bridge), we can use
			// a NodePort service so that we can access node(s) in a different Kind cluster.
			if cfg.UseKind {
				defaultPartitionHelmValues["meshGateway.service.type"] = "NodePort"
				defaultPartitionHelmValues["meshGateway.service.nodePort"] = "30200"
				defaultPartitionHelmValues["server.exposeService.type"] = "NodePort"
				defaultPartitionHelmValues["server.exposeService.nodePort.https"] = "30000"
				defaultPartitionHelmValues["server.exposeService.nodePort.grpc"] = "30100"
			}
			helpers.MergeMaps(defaultPartitionHelmValues, commonHelmValues)

			releaseName := helpers.RandomName()
			members[keyLocal].helmCluster = consul.NewHelmCluster(t, defaultPartitionHelmValues, members[keyLocal].context, cfg, releaseName)
			members[keyLocal].helmCluster.Create(t)

			// Create Secondary Partition.
			// Get the TLS CA certificate and key secret from the server cluster and apply it to the client cluster.
			caCertSecretName := fmt.Sprintf("%s-consul-ca-cert", releaseName)

			logger.Logf(t, "retrieving ca cert secret %s from the default partition and applying to the secondary partition", caCertSecretName)
			k8s.CopySecret(t, members[keyLocal].context, members[keyLocalPartition].context, caCertSecretName)

			partitionServiceName := fmt.Sprintf("%s-consul-expose-servers", releaseName)
			partitionSvcAddress := k8s.ServiceHost(t, cfg, members[keyLocal].context, partitionServiceName)

			k8sAuthMethodHost := k8s.KubernetesAPIServerHost(t, cfg, members[keyLocalPartition].context)

			secondaryPartitionHelmValues := map[string]string{
				"global.enabled":    "false",
				"global.datacenter": localDatacenter,

				"global.adminPartitions.name": localPartition,

				"global.tls.caCert.secretName": caCertSecretName,
				"global.tls.caCert.secretKey":  "tls.crt",

				"externalServers.enabled":       "true",
				"externalServers.hosts[0]":      partitionSvcAddress,
				"externalServers.tlsServerName": fmt.Sprintf("server.%s.consul", localDatacenter),
				"global.server.enabled":         "false",
			}

			if c.ACLsEnabled {
				// Setup partition token and auth method host if ACLs enabled.
				partitionToken := fmt.Sprintf("%s-consul-partitions-acl-token", releaseName)
				logger.Logf(t, "retrieving partition token secret %s from the from the default partition and applying to the secondary partition", partitionToken)
				k8s.CopySecret(t, members[keyLocal].context, members[keyLocalPartition].context, partitionToken)

				secondaryPartitionHelmValues["global.acls.bootstrapToken.secretName"] = partitionToken
				secondaryPartitionHelmValues["global.acls.bootstrapToken.secretKey"] = "token"
				secondaryPartitionHelmValues["externalServers.k8sAuthMethodHost"] = k8sAuthMethodHost
			}

			if cfg.UseKind {
				secondaryPartitionHelmValues["externalServers.httpsPort"] = "30000"
				secondaryPartitionHelmValues["externalServers.grpcPort"] = "30100"
				secondaryPartitionHelmValues["meshGateway.service.type"] = "NodePort"
				secondaryPartitionHelmValues["meshGateway.service.nodePort"] = "30200"
			}
			helpers.MergeMaps(secondaryPartitionHelmValues, commonHelmValues)

			members[keyLocalPartition].helmCluster = consul.NewHelmCluster(t, secondaryPartitionHelmValues, members[keyLocalPartition].context, cfg, releaseName)
			members[keyLocalPartition].helmCluster.Create(t)

			// Create peer clusters.
			createPeerCluster(t, cfg, commonHelmValues, sameZoneDatacenter, releaseName, members[keySameZone])
			createPeerCluster(t, cfg, commonHelmValues, sameRegionDatacenter, releaseName, members[keySameRegion])
			createPeerCluster(t, cfg, commonHelmValues, remoteDatacenter, releaseName, members[keyRemote])

			// Create a ProxyDefaults resource to configure services to use the mesh
			// gateways and set server and client opts.
			for k, v := range members {
				logger.Logf(t, "applying resources on %s", v.context.KubectlOptions(t).ContextName)

				// Client will use the client namespace.
				members[k].clientOpts = &terratestk8s.KubectlOptions{
					ContextName: v.context.KubectlOptions(t).ContextName,
					ConfigPath:  v.context.KubectlOptions(t).ConfigPath,
					Namespace:   staticClientNamespace,
				}

				// Server will use the server namespace.
				members[k].serverOpts = &terratestk8s.KubectlOptions{
					ContextName: v.context.KubectlOptions(t).ContextName,
					ConfigPath:  v.context.KubectlOptions(t).ConfigPath,
					Namespace:   staticServerNamespace,
				}

				// Sameness Defaults need to be applied first so that the sameness group exists.
				applyResources(t, cfg, "../fixtures/bases/mesh-gateway", members[k].context.KubectlOptions(t))
				applyResources(t, cfg, "../fixtures/bases/sameness/default-ns", members[k].context.KubectlOptions(t))
				applyResources(t, cfg, "../fixtures/bases/sameness/override-ns", members[k].serverOpts)

				// Only assign a client if the cluster is running a Consul server.
				if v.hasServer {
					members[k].client, _ = members[k].helmCluster.SetupConsulClient(t, c.ACLsEnabled)
				}
			}

			// TODO: Add further setup for peering, right now the rest of this test will only cover Partitions
			// Create static server deployments.
			logger.Log(t, "creating static-server and static-client deployments")
			k8s.DeployKustomize(t, members[keyLocal].serverOpts, cfg.NoCleanupOnFailure, cfg.NoCleanup, cfg.DebugDirectory,
				"../fixtures/cases/sameness/static-server/default")
			k8s.DeployKustomize(t, members[keyLocalPartition].serverOpts, cfg.NoCleanupOnFailure, cfg.NoCleanup, cfg.DebugDirectory,
				"../fixtures/cases/sameness/static-server/partition")

			// Create static client deployments.
			k8s.DeployKustomize(t, members[keyLocal].clientOpts, cfg.NoCleanupOnFailure, cfg.NoCleanup, cfg.DebugDirectory,
				"../fixtures/cases/sameness/static-client/default")
			k8s.DeployKustomize(t, members[keyLocalPartition].clientOpts, cfg.NoCleanupOnFailure, cfg.NoCleanup, cfg.DebugDirectory,
				"../fixtures/cases/sameness/static-client/partition")

			// Verify that both static-server and static-client have been injected and now have 2 containers in server cluster.
			// Also get the server IP
			for _, labelSelector := range []string{"app=static-server", "app=static-client"} {
				podList, err := members[keyLocal].context.KubernetesClient(t).CoreV1().Pods(metav1.NamespaceAll).List(context.Background(),
					metav1.ListOptions{LabelSelector: labelSelector})
				require.NoError(t, err)
				require.Len(t, podList.Items, 1)
				require.Len(t, podList.Items[0].Spec.Containers, 2)
				if labelSelector == "app=static-server" {
					ip := &podList.Items[0].Status.PodIP
					require.NotNil(t, ip)
					logger.Logf(t, "default-static-server-ip: %s", *ip)
					members[keyLocal].staticServerIP = ip
				}

				podList, err = members[keyLocalPartition].context.KubernetesClient(t).CoreV1().Pods(metav1.NamespaceAll).List(context.Background(),
					metav1.ListOptions{LabelSelector: labelSelector})
				require.NoError(t, err)
				require.Len(t, podList.Items, 1)
				require.Len(t, podList.Items[0].Spec.Containers, 2)
				if labelSelector == "app=static-server" {
					ip := &podList.Items[0].Status.PodIP
					require.NotNil(t, ip)
					logger.Logf(t, "partition-static-server-ip: %s", *ip)
					members[keyLocalPartition].staticServerIP = ip
				}
			}

			logger.Log(t, "creating exported services")
			applyResources(t, cfg, "../fixtures/cases/sameness/exported-services/default-partition", members[keyLocal].context.KubectlOptions(t))
			applyResources(t, cfg, "../fixtures/cases/sameness/exported-services/ap1-partition", members[keyLocalPartition].context.KubectlOptions(t))

			// Setup DNS.
			dnsService, err := members[keyLocal].context.KubernetesClient(t).CoreV1().Services("default").Get(context.Background(), fmt.Sprintf("%s-%s", releaseName, "consul-dns"), metav1.GetOptions{})
			require.NoError(t, err)
			dnsIP := dnsService.Spec.ClusterIP
			logger.Logf(t, "dnsIP: %s", dnsIP)

			// Setup Prepared Query.
			definition := &api.PreparedQueryDefinition{
				Name: "my-query",
				Service: api.ServiceQuery{
					Service:       "static-server",
					SamenessGroup: "mine",
					Namespace:     staticServerNamespace,
					OnlyPassing:   false,
				},
			}
			resp, _, err := members[keyLocal].client.PreparedQuery().Create(definition, &api.WriteOptions{})
			require.NoError(t, err)
			logger.Logf(t, "PQ ID: %s", resp)

			logger.Log(t, "all infrastructure up and running")
			logger.Log(t, "verifying failover scenarios")

			const dnsLookup = "static-server.service.ns2.ns.mine.sg.consul"
			const dnsPQLookup = "my-query.query.consul"

			// Verify initial server.
			serviceFailoverCheck(t, localClusterName, members[keyLocal])

			// Verify initial dns.
			dnsFailoverCheck(t, releaseName, dnsIP, dnsLookup, members[keyLocal], members[keyLocal])

			// Verify initial dns with PQ.
			dnsFailoverCheck(t, releaseName, dnsIP, dnsPQLookup, members[keyLocal], members[keyLocal])

			// Scale down static-server on the server, will fail over to partition.
			k8s.KubectlScale(t, members[keyLocal].serverOpts, staticServerDeployment, 0)

			// Verify failover to partition.
			serviceFailoverCheck(t, partitionClusterName, members[keyLocal])

			// Verify dns failover to partition.
			dnsFailoverCheck(t, releaseName, dnsIP, dnsLookup, members[keyLocal], members[keyLocalPartition])

			// Verify prepared query failover.
			dnsFailoverCheck(t, releaseName, dnsIP, dnsPQLookup, members[keyLocal], members[keyLocalPartition])

			logger.Log(t, "tests complete")
		})
	}
}

type member struct {
	context        environment.TestContext
	helmCluster    *consul.HelmCluster
	client         *api.Client
	hasServer      bool
	serverOpts     *terratestk8s.KubectlOptions
	clientOpts     *terratestk8s.KubectlOptions
	staticServerIP *string
}

func createPeerCluster(t *testing.T, cfg *config.TestConfig, commonHelmValues map[string]string, dc string, releaseName string, member *member) {
	PeerHelmValues := map[string]string{
		"global.datacenter": dc,
	}

	if cfg.UseKind {
		PeerHelmValues["server.exposeGossipAndRPCPorts"] = "true"
		PeerHelmValues["meshGateway.service.type"] = "NodePort"
		PeerHelmValues["meshGateway.service.nodePort"] = "30100"
	}
	helpers.MergeMaps(PeerHelmValues, commonHelmValues)

	member.helmCluster = consul.NewHelmCluster(t, PeerHelmValues, member.context, cfg, releaseName)
	member.helmCluster.Create(t)
}

func createNamespaces(t *testing.T, cfg *config.TestConfig, context environment.TestContext) {
	logger.Logf(t, "creating namespaces in %s", context.KubectlOptions(t).ContextName)
	k8s.RunKubectl(t, context.KubectlOptions(t), "create", "ns", staticServerNamespace)
	k8s.RunKubectl(t, context.KubectlOptions(t), "create", "ns", staticClientNamespace)
	helpers.Cleanup(t, cfg.NoCleanupOnFailure, cfg.NoCleanup, func() {
		k8s.RunKubectl(t, context.KubectlOptions(t), "delete", "ns", staticClientNamespace, staticServerNamespace)
	})
}

func applyResources(t *testing.T, cfg *config.TestConfig, kustomizeDir string, opts *terratestk8s.KubectlOptions) {
	k8s.KubectlApplyK(t, opts, kustomizeDir)
	helpers.Cleanup(t, cfg.NoCleanupOnFailure, cfg.NoCleanup, func() {
		k8s.KubectlDeleteK(t, opts, kustomizeDir)
	})
}

// serviceFailoverCheck verifies that the server failed over as expected by checking that curling the `static-server`
// using the `static-client` responds with the expected cluster name. Each static-server responds with a uniquue
// name so that we can verify failover occured as expected.
func serviceFailoverCheck(t *testing.T, expectedClusterName string, server *member) {
	retry.Run(t, func(r *retry.R) {
		resp, err := k8s.RunKubectlAndGetOutputE(t, server.clientOpts, "exec", "-i",
			staticClientDeployment, "-c", "static-client", "--", "curl", "localhost:8080")
		require.NoError(r, err)
		assert.Contains(r, resp, expectedClusterName)
		logger.Log(t, resp)
	})
}

func dnsFailoverCheck(t *testing.T, releaseName string, dnsIP string, dnsQuery string, server, failover *member) {
	retry.Run(t, func(r *retry.R) {
		logs, err := k8s.RunKubectlAndGetOutputE(t, server.clientOpts, "exec", "-i",
			staticClientDeployment, "-c", "static-client", "--", "dig", fmt.Sprintf("@%s-consul-dns.default", releaseName), dnsQuery)
		require.NoError(r, err)

		// When the `dig` request is successful, a section of its response looks like the following:
		//
		// ;; ANSWER SECTION:
		// static-server.service.mine.sg.ns2.ns.consul.	0	IN	A	<consul-server-pod-ip>
		//
		// ;; Query time: 2 msec
		// ;; SERVER: <dns-ip>#<dns-port>(<dns-ip>)
		// ;; WHEN: Mon Aug 10 15:02:40 UTC 2020
		// ;; MSG SIZE  rcvd: 98
		//
		// We assert on the existence of the ANSWER SECTION, The consul-server IPs being present in
		// the ANSWER SECTION and the DNS IP mentioned in the SERVER: field

		assert.Contains(r, logs, fmt.Sprintf("SERVER: %s", dnsIP))
		assert.Contains(r, logs, "ANSWER SECTION:")
		assert.Contains(r, logs, *failover.staticServerIP)
	})
}
