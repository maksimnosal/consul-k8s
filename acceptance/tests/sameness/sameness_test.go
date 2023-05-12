package sameness

import (
	"testing"

	"github.com/hashicorp/go-version"
	"github.com/stretchr/testify/require"
)

func TestFailover_Connect(t *testing.T) {
	env := suite.Environment()
	cfg := suite.Config()

	ver, err := version.NewVersion("1.15.0")
	require.NoError(t, err)
	if cfg.ConsulVersion != nil && cfg.ConsulVersion.LessThan(ver) {
		t.Skipf("skipping this test because peering is not supported in version %v", cfg.ConsulVersion.String())
	}

	// Create the cluster

}
