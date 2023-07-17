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

// TestConnectInject tests that Connect works in a default and a secure installation using Helm CLI.
func TestDirectCommunication(t *testing.T) {

	cfg := suite.Config()
	ctx := suite.Environment().DefaultContext(t)

	logger.Log(t, "creating static-server and static-client deployments")
	k8s.DeployKustomize(t, ctx.KubectlOptions(t), cfg.NoCleanupOnFailure, cfg.DebugDirectory, "../fixtures/cases/static-server-inject")
	k8s.DeployKustomize(t, ctx.KubectlOptions(t), cfg.NoCleanupOnFailure, cfg.DebugDirectory, "../fixtures/cases/static-client-inject")

	// Check that both static-server and static-client have been injected and
	// now have 2 containers.
	for _, labelSelector := range []string{"app=static-server", "app=static-client"} {
		podList, err := ctx.KubernetesClient(t).CoreV1().Pods(ctx.KubectlOptions(t).Namespace).List(context.Background(), metav1.ListOptions{
			LabelSelector: labelSelector,
		})
		require.NoError(t, err)
		require.Len(t, podList.Items, 1)
		require.Len(t, podList.Items[0].Spec.Containers, 1)
	}

	// Check connection from static-client to server based on the k8s service name.
	k8s.CheckStaticServerConnectionSuccessful(t, ctx.KubectlOptions(t), connhelper.StaticClientName, fmt.Sprintf("http://%s:80", connhelper.StaticServerName))
}

// TestConnectInject tests that Connect works in a default and a secure installation using Helm CLI.
func TestEnvoyCommunication(t *testing.T) {

	cfg := suite.Config()
	ctx := suite.Environment().DefaultContext(t)

	logger.Log(t, "creating static-server and static-client deployments")
	k8s.DeployKustomize(t, ctx.KubectlOptions(t), cfg.NoCleanupOnFailure, cfg.DebugDirectory, "../fixtures/cases/static-server-inject-envoy")
	k8s.DeployKustomize(t, ctx.KubectlOptions(t), cfg.NoCleanupOnFailure, cfg.DebugDirectory, "../fixtures/cases/static-client-inject-envoy")

	// Check that both static-server and static-client have been injected and
	// now have 2 containers.
	for _, labelSelector := range []string{"app=static-server", "app=static-client"} {
		podList, err := ctx.KubernetesClient(t).CoreV1().Pods(ctx.KubectlOptions(t).Namespace).List(context.Background(), metav1.ListOptions{
			LabelSelector: labelSelector,
		})
		require.NoError(t, err)
		require.Len(t, podList.Items, 1)
		require.Len(t, podList.Items[0].Spec.Containers, 2)
	}

	// Check connection from static-client to server based on the k8s service name.
	k8s.CheckStaticServerConnectionSuccessful(t, ctx.KubectlOptions(t), connhelper.StaticClientName, "http://localhost:1234")
}
