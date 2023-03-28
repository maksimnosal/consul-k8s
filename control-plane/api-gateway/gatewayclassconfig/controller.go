package gatewayclassconfig

import (
	"context"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"

	v1alpha1 "github.com/hashicorp/consul-k8s/control-plane/api/v1alpha1"
	"github.com/hashicorp/go-hclog"
)

const (
	gatewayClassConfigFinalizer = "gateway-class-exists-finalizer.api-gateway.consul.hashicorp.com"
)

// GatewayClassConfigController reconciles GatewayClassConfig resources.
type GatewayClassConfigController struct {
	Log hclog.Logger
}

func NewGatewayClassController() *GatewayClassConfigController {
	return &GatewayClassConfigController{}
}

//+kubebuilder:rbac:groups=api-gateway.consul.hashicorp.com,resources=gatewayclassconfigs,verbs=get;update;list;watch
//+kubebuilder:rbac:groups=api-gateway.consul.hashicorp.com,resources=gatewayclassconfigs/finalizers,verbs=update

func (g *GatewayClassConfigController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := g.Log.With("gatewayClassConfig", req.NamespacedName)

	gcc, err := get(ctx, req.NamespacedName)
	if err != nil {
		logger.Error("error getting gateway class config", "err", err)
		return ctrl.Result{}, err
	}

	if gcc == nil {
		logger.Info("gateway class config deleted")
		return ctrl.Result{}, nil
	}

	if !gcc.ObjectMeta.DeletionTimestamp.IsZero() {
		inUse, err := inUse(ctx, gcc)
		if err != nil {
			logger.Error("error checking if gateway class config is in use", "err", err)
			return ctrl.Result{}, err
		}

		if inUse {
			logger.Trace("gateway class config is in use, not deleting")
			return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
		}

		if _, err := removeFinalizer(ctx, gcc); err != nil {
			logger.Error("error removing finalizer", "err", err)
			return ctrl.Result{}, err
		}
	}

	logger.Info("reconciling gateway class config", "gatewayClassConfig", gcc)

	return ctrl.Result{}, nil
}

func get(ctx context.Context, namespacedName any) (*v1alpha1.GatewayClassConfig, error) {
	var gcc *v1alpha1.GatewayClassConfig

	// This should actually be done by the client.

	return gcc, nil
}

func inUse(ctx context.Context, gcc *v1alpha1.GatewayClassConfig) (bool, error) {
	// This should actually be done by the client.

	return false, nil
}
