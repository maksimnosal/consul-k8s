// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package peering

import (
	"fmt"
	"os"
	"testing"

	testsuite "github.com/hashicorp/consul-k8s/acceptance/framework/suite"
)

var suite testsuite.Suite

func TestMain(m *testing.M) {
	suite = testsuite.NewSuite(m)

	if len(suite.Config().KubeEnvs) >= 2 && !suite.Config().DisablePeering {
		os.Exit(suite.Run())
	} else {
		fmt.Println("Skipping peering tests because either there are not enough available Kube contexts is not set or -disable-peering is set")
		os.Exit(0)
	}
}
