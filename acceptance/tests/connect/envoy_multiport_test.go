// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package connect

import (
	"context"
	"fmt"
	"github.com/hashicorp/consul-k8s/acceptance/framework/connhelper"
	"github.com/hashicorp/consul-k8s/acceptance/framework/k8s"
	"github.com/hashicorp/consul-k8s/acceptance/framework/logger"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

func TestDirectCommunication_MultiportServices(t *testing.T) {
	for _, secure := range []bool{false, true} {
		name := fmt.Sprintf("secure: %t", secure)
		t.Run(name, func(t *testing.T) {
			cfg := suite.Config()
			ctx := suite.Environment().DefaultContext(t)

			logger.Log(t, "creating multiport static-server and static-client deployments")
			k8s.DeployKustomize(t, ctx.KubectlOptions(t), cfg.NoCleanupOnFailure, cfg.DebugDirectory, "../fixtures/bases/multiport-app")
			k8s.DeployKustomize(t, ctx.KubectlOptions(t), cfg.NoCleanupOnFailure, cfg.DebugDirectory, "../fixtures/cases/static-client-inject-multiport")

			// Check that static-client has been injected and now has 1 containers.
			podList, err := ctx.KubernetesClient(t).CoreV1().Pods(ctx.KubectlOptions(t).Namespace).List(context.Background(), metav1.ListOptions{
				LabelSelector: "app=static-client",
			})
			require.NoError(t, err)
			require.Len(t, podList.Items, 1)
			require.Len(t, podList.Items[0].Spec.Containers, 1)

			// Check that multiport has been injected and now has 2 containers.
			podList, err = ctx.KubernetesClient(t).CoreV1().Pods(ctx.KubectlOptions(t).Namespace).List(context.Background(), metav1.ListOptions{
				LabelSelector: "app=multiport",
			})
			require.NoError(t, err)
			require.Len(t, podList.Items, 1)
			require.Len(t, podList.Items[0].Spec.Containers, 2)

			//if secure {
			//	logger.Log(t, "checking that the connection is not successful because there's no intention")
			//	k8s.CheckStaticServerConnectionFailing(t, ctx.KubectlOptions(t), connhelper.StaticClientName, "http://localhost:1234")
			//	k8s.CheckStaticServerConnectionFailing(t, ctx.KubectlOptions(t), connhelper.StaticClientName, "http://localhost:2234")
			//
			//	logger.Log(t, fmt.Sprintf("creating intention for %s", multiport))
			//	_, _, err := consulClient.ConfigEntries().Set(&api.ServiceIntentionsConfigEntry{
			//		Kind: api.ServiceIntentions,
			//		Name: multiport,
			//		Sources: []*api.SourceIntention{
			//			{
			//				Name:   connhelper.StaticClientName,
			//				Action: api.IntentionActionAllow,
			//			},
			//		},
			//	}, nil)
			//	require.NoError(t, err)
			//	logger.Log(t, fmt.Sprintf("creating intention for %s", multiportAdmin))
			//	_, _, err = consulClient.ConfigEntries().Set(&api.ServiceIntentionsConfigEntry{
			//		Kind: api.ServiceIntentions,
			//		Name: multiportAdmin,
			//		Sources: []*api.SourceIntention{
			//			{
			//				Name:   connhelper.StaticClientName,
			//				Action: api.IntentionActionAllow,
			//			},
			//		},
			//	}, nil)
			//	require.NoError(t, err)
			//}

			// Check communication from static client to multiport and multiport-admin
			// Communication within kubernetes should be by service name and port.

			// Check connection from static-client to multiport.
			k8s.CheckStaticServerConnectionSuccessful(t, ctx.KubectlOptions(t), connhelper.StaticClientName, "http://multiport:8080")

			// Check connection from static-client to multiport-admin.
			k8s.CheckStaticServerConnectionSuccessfulWithMessage(t, ctx.KubectlOptions(t), connhelper.StaticClientName, "hello world from 9090 admin", "http://multiport:9090")

			// Now that we've checked inbound connections to a multi port pod, check outbound connection from multi port
			// pod to static-server.

			// Deploy static-server.
			k8s.DeployKustomize(t, ctx.KubectlOptions(t), cfg.NoCleanupOnFailure, cfg.DebugDirectory, "../fixtures/cases/static-server-inject")

			//// For outbound connections from the multi port pod, only intentions from the first service in the multiport
			//// pod need to be created, since all upstream connections are made through the first service's envoy proxy.
			//if secure {
			//	logger.Log(t, "checking that the connection is not successful because there's no intention")
			//
			//	k8s.CheckStaticServerConnectionFailing(t, ctx.KubectlOptions(t), multiport, "http://localhost:3234")
			//
			//	logger.Log(t, fmt.Sprintf("creating intention for %s", connhelper.StaticServerName))
			//	_, _, err := consulClient.ConfigEntries().Set(&api.ServiceIntentionsConfigEntry{
			//		Kind: api.ServiceIntentions,
			//		Name: connhelper.StaticServerName,
			//		Sources: []*api.SourceIntention{
			//			{
			//				Name:   multiport,
			//				Action: api.IntentionActionAllow,
			//			},
			//		},
			//	}, nil)
			//	require.NoError(t, err)
			//}
			//
			//// Check the connection from the multi port pod to static-server.
			//k8s.CheckStaticServerConnectionSuccessful(t, ctx.KubectlOptions(t), multiport, "http://localhost:3234")
			//
			//// Test that kubernetes readiness status is synced to Consul. This will make the multi port pods unhealthy
			//// and check inbound connections to the multi port pods' services.
			//// Create the files so that the readiness probes of the multi port pod fails.
			//logger.Log(t, "testing k8s -> consul health checks sync by making the multiport unhealthy")
			//k8s.RunKubectl(t, ctx.KubectlOptions(t), "exec", "deploy/"+multiport, "--", "touch", "/tmp/unhealthy-multiport")
			//logger.Log(t, "testing k8s -> consul health checks sync by making the multiport-admin unhealthy")
			//k8s.RunKubectl(t, ctx.KubectlOptions(t), "exec", "deploy/"+multiport, "--", "touch", "/tmp/unhealthy-multiport-admin")
			//
			//// The readiness probe should take a moment to be reflected in Consul, CheckStaticServerConnection will retry
			//// until Consul marks the service instance unavailable for mesh traffic, causing the connection to fail.
			//// We are expecting a "connection reset by peer" error because in a case of health checks,
			//// there will be no healthy proxy host to connect to. That's why we can't assert that we receive an empty reply
			//// from server, which is the case when a connection is unsuccessful due to intentions in other tests.
			//k8s.CheckStaticServerConnectionMultipleFailureMessages(t, ctx.KubectlOptions(t), connhelper.StaticClientName, false, []string{"curl: (56) Recv failure: Connection reset by peer", "curl: (52) Empty reply from server"}, "", "http://localhost:1234")
			//k8s.CheckStaticServerConnectionMultipleFailureMessages(t, ctx.KubectlOptions(t), connhelper.StaticClientName, false, []string{"curl: (56) Recv failure: Connection reset by peer", "curl: (52) Empty reply from server"}, "", "http://localhost:2234")
		})
	}
}
