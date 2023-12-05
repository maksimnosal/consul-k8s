// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package logger

import (
	"fmt"
	"github.com/hashicorp/consul/sdk/testutil/retry"
	"testing"
	"time"

	terratesting "github.com/gruntwork-io/terratest/modules/testing"
)

// TestLogger implements Terratest's TestLogger interface so that we can pass it to Terratest objects to have consistent
// logging across all tests.
type TestLogger struct{}

// Logf takes a format string and args and calls Logf function.
func (tl TestLogger) Logf(t terratesting.TestingT, format string, args ...any) {
	if tt, ok := t.(*testing.T); ok {
		tt.Helper()
	}

	Logf(t, format, args...)
}

// Logf takes a format string and args and logs formatted string with a timestamp.
func Logf(t terratesting.TestingT, format string, args ...any) {
	if tt, ok := t.(*testing.T); ok {
		tt.Helper()
	}

	log := fmt.Sprintf(format, args...)
	Log(t, log)
}

// Log calls t.Log or r.Log, adding an RFC3339 timestamp to the beginning of the log line.
func Log(t terratesting.TestingT, args ...any) {
	if tt, ok := t.(*testing.T); ok {
		tt.Helper()
		allArgs := []any{time.Now().Format(time.RFC3339)}
		allArgs = append(allArgs, args...)
		tt.Log(allArgs...)
	}

	if rt, ok := t.(*retry.R); ok {
		allArgs := []any{time.Now().Format(time.RFC3339)}
		allArgs = append(allArgs, args...)
		rt.Log(allArgs...)
	}
}
