// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controllers

import (
	"context"
	"encoding/json"
	"fmt"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	consulv1alpha1 "github.com/hashicorp/consul-k8s/control-plane/api/v1alpha1"
)

// ServiceSplitterReconciler reconciles a ServiceSplitter object.
type ServiceSplitterController struct {
	client.Client
	Log                   logr.Logger
	Scheme                *runtime.Scheme
	ConfigEntryController *ConfigEntryController
}

// +kubebuilder:rbac:groups=consul.hashicorp.com,resources=servicesplitters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=consul.hashicorp.com,resources=servicesplitters/status,verbs=get;update;patch

func (r *ServiceSplitterController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return r.ConfigEntryController.ReconcileEntry(ctx, r, req, &consulv1alpha1.ServiceSplitter{})
}

func (r *ServiceSplitterController) Logger(name types.NamespacedName) logr.Logger {
	return r.Log.WithValues("request", name)
}

func (r *ServiceSplitterController) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	return r.Client.Patch(ctx, obj, AddFinalizerPatch(obj, "blarg"))
	// return r.Client.Update(ctx, obj, opts...)
}

func (r *ServiceSplitterController) UpdateStatus(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	return r.Status().Update(ctx, obj, opts...)
}

func (r *ServiceSplitterController) SetupWithManager(mgr ctrl.Manager) error {
	return setupWithManager(mgr, &consulv1alpha1.ServiceSplitter{}, r)
}

func (r *ServiceSplitterController) UpdateFinalizers(ctx context.Context, obj client.Object, opts ...client.PatchOption) error {
	return r.Patch(ctx, obj, client.Apply, opts...)
}

var _ client.Patch = (*FinalizerPatch)(nil)

func AddFinalizerPatch(oldObj client.Object, addFinalizers ...string) *FinalizerPatch {
	output := make([]string, 0, len(addFinalizers))
	existing := make(map[string]bool)
	for _, f := range oldObj.GetFinalizers() {
		existing[f] = true
		output = append(output, f)
	}
	for _, f := range addFinalizers {
		if !existing[f] {
			output = append(output, f)
		}
	}
	return &FinalizerPatch{
		NewFinalizers: output,
	}
}

type FinalizerPatch struct {
	NewFinalizers []string
}

// Data implements client.Patch.
func (fp *FinalizerPatch) Data(obj client.Object) ([]byte, error) {
	newData, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"finalizers": fp.NewFinalizers,
		},
	})
	if err != nil {
		return nil, err
	}

	p, err := jsonpatch.CreateMergePatch([]byte(`{}`), newData)
	fmt.Println("============================", string(p))
	return p, err
}

// Type implements client.Patch.
func (fp *FinalizerPatch) Type() types.PatchType {
	return types.MergePatchType
}
