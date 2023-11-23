// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/consul-k8s/acceptance/framework/consul"
	"github.com/hashicorp/consul-k8s/acceptance/framework/helpers"
	"github.com/hashicorp/consul-k8s/acceptance/framework/k8s"
	"github.com/hashicorp/consul-k8s/acceptance/framework/logger"
	"github.com/hashicorp/go-multierror"
	"github.com/stretchr/testify/require"
)

// Test that when servers are restarted, they don't lose quorum.
func TestServerRestart(t *testing.T) {
	ctx := suite.Environment().DefaultContext(t)
	replicas := 3
	releaseName := helpers.RandomName()
	helmValues := map[string]string{
		"global.enabled":        "false",
		"connectInject.enabled": "false",
		"server.enabled":        "true",
		"server.replicas":       fmt.Sprintf("%d", replicas),
	}
	consulCluster := consul.NewHelmCluster(t, helmValues, suite.Environment().DefaultContext(t), suite.Config(), releaseName)

	consulCluster.Create(t)

	// Start a separate goroutine to check if at any point quorum is lost.
	// Use number of ready replicas as proxy for whether there is quorum because
	// replicas are marked unready if they don't think there's a leader so if
	// >n/2 replicas are unready then there's no quorum.
	noQuorumCount := 0
	var unmarshallErrs error
	done := make(chan bool)
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				out, err := k8s.RunKubectlAndGetOutputE(t, ctx.KubectlOptions(t), "get", fmt.Sprintf("statefulset/%s-consul-server", releaseName),
					"-o", "jsonpath={.status}")
				if err != nil {
					// Not failing the test on this error to reduce flakiness.
					logger.Logf(t, "kubectl err: %s: %s", err, out)
					break
				}
				type statefulsetOut struct {
					ReadyReplicas *int `json:"readyReplicas,omitempty"`
				}
				var jsonOut statefulsetOut
				if err = json.Unmarshal([]byte(out), &jsonOut); err != nil {
					unmarshallErrs = multierror.Append(err)
				} else if jsonOut.ReadyReplicas == nil || *jsonOut.ReadyReplicas < replicas-1 {
					// note: for some k8s api reason when readyReplicas is 0 it's not included in the json output so
					// that's why we're checking if it's nil.
					noQuorumCount++
				}
				time.Sleep(1 * time.Second)
			}
		}
	}()

	// Restart servers
	out, err := k8s.RunKubectlAndGetOutputE(t, ctx.KubectlOptions(t), "rollout", "restart", fmt.Sprintf("statefulset/%s-consul-server", releaseName))
	require.NoError(t, err, out)

	// Wait for restart to finish.
	start := time.Now()
	out, err = k8s.RunKubectlAndGetOutputE(t, ctx.KubectlOptions(t), "rollout", "status", "--timeout", "5m", "--watch", fmt.Sprintf("statefulset/%s-consul-server", releaseName))
	require.NoError(t, err, out, "rollout status command errored, this likely means the rollout didn't complete in time")
	close(done)

	require.NoError(t, unmarshallErrs, "there were some json unmarshall errors, this is likely a bug")

	logger.Logf(t, "restart took %s, there were %d seconds without quorum", time.Now().Sub(start), noQuorumCount)
	require.Equal(t, 0, noQuorumCount, "there was %d seconds without quorum", noQuorumCount)
}
