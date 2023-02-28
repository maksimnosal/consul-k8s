package envoy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	terratestLogger "github.com/gruntwork-io/terratest/modules/logger"
	"github.com/hashicorp/consul-k8s/acceptance/framework/connhelper"
	"github.com/hashicorp/consul-k8s/acceptance/framework/environment"
	"github.com/hashicorp/consul-k8s/acceptance/framework/portforward"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type EnvoyAdminHelper struct {
	ch          connhelper.ConnectHelper
	podSelector string

	localAddr string
}

func NewEnvoyAdminHelper(ch connhelper.ConnectHelper, podSelector string) *EnvoyAdminHelper {
	return &EnvoyAdminHelper{
		ch:          ch,
		podSelector: podSelector,
	}
}

func (e *EnvoyAdminHelper) Setup(t *testing.T) {
	podName := e.getPodName(t)

	e.localAddr = portforward.CreateTunnelToResourcePort(t, podName, 19000, e.ch.Ctx.KubectlOptions(t), terratestLogger.Discard)
	t.Cleanup(func() { e.localAddr = "" })
	t.Logf("Started portforward to Envoy admin interface: localAddr=%s", e.localAddr)
}

func (e *EnvoyAdminHelper) ResetCounters(t require.TestingT) {
	resp, err := http.DefaultClient.Post(e.url(t, "/reset_counters"), "", nil)
	require.NoError(t, err)
	require.Equal(t, resp.StatusCode, http.StatusOK)
}

func (e *EnvoyAdminHelper) GetStats(t require.TestingT) EnvoyStats {
	resp, err := http.DefaultClient.Get(e.url(t, "/stats?format=json"))
	require.NoError(t, err)
	require.Equal(t, resp.StatusCode, http.StatusOK)

	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var stats map[string]EnvoyStats
	require.NoError(t, json.Unmarshal(data, &stats))
	require.Greater(t, len(stats), 0, "no envoy stats found")
	require.Contains(t, stats, "stats")
	return stats["stats"]
}

func (e *EnvoyAdminHelper) url(t require.TestingT, path string) string {
	require.NotEmpty(t, e.localAddr, "no local portforward address for envoy (need to call EnvoyHelper.Setup?)")
	return fmt.Sprintf("http://%s%s", e.localAddr, path)
}
func (e *EnvoyAdminHelper) getPodName(t *testing.T) string {
	opts := e.ch.Ctx.KubectlOptions(t)
	k8sClient := environment.KubernetesClientFromOptions(t, opts)
	podList, err := k8sClient.CoreV1().Pods(opts.Namespace).List(
		context.Background(),
		metav1.ListOptions{LabelSelector: e.podSelector})
	require.NoError(t, err)

	require.Len(t, podList.Items, 1, "Multiple pods found for selector %q. Unable to start portforward to Envoy.", e.podSelector)
	return podList.Items[0].Name
}
