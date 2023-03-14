package controller

import (
	"context"

	ctrl "sigs.k8s.io/controller-runtime"
)

// GatewayClassController handles reconciliations for GatewayClass objects.
type GatewayClassController struct{}

func (c *GatewayClassController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller manager with the proper subscriptions for GatewayClasses.
func (c *GatewayClassController) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(defaultControllerOptions()).
		Complete(c)
}
