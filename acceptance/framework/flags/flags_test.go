// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package flags

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFlags_validate(t *testing.T) {
	type fields struct {
		flagEnableEnt  bool
		flagEntLicense string
	}
	tests := []struct {
		name       string
		fields     fields
		wantErr    bool
		errMessage string
	}{
		{
			"no error by default",
			fields{},
			false,
			"",
		},
		{
			"enterprise license: error when only -enable-enterprise is true but env CONSUL_ENT_LICENSE is not provided",
			fields{
				flagEnableEnt: true,
			},
			true,
			"-enable-enterprise provided without setting env var CONSUL_ENT_LICENSE with consul license",
		},
		{
			"enterprise license: no error when both -enable-enterprise and env CONSUL_ENT_LICENSE are provided",
			fields{
				flagEnableEnt:  true,
				flagEntLicense: "license",
			},
			false,
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tf := &TestFlags{
				flagEnableEnterprise:  tt.fields.flagEnableEnt,
				flagEnterpriseLicense: tt.fields.flagEntLicense,
			}
			err := tf.Validate()
			if tt.wantErr {
				require.EqualError(t, err, tt.errMessage)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
