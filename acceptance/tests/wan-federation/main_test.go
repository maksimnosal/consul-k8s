// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package wanfederation

import (
	"fmt"
	"os"
	"testing"

	testsuite "github.com/hashicorp/consul-k8s/acceptance/framework/suite"
)

var suite testsuite.Suite

func TestMain(m *testing.M) {
	suite = testsuite.NewSuite(m)

	if len(suite.Config().KubeEnvs) >= 2 {
		os.Exit(suite.Run())
	} else {
		fmt.Println("Skipping wan federation tests because there are not enough context available for multicluster")
		os.Exit(0)
	}
}
