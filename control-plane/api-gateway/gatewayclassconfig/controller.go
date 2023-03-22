package gatewayclassconfig

import (
	"context"

	ctrl "sigs.k8s.io/controller-runtime"

	apigateway "github.com/hashicorp/consul-k8s/control-plane/api-gateway"
	"github.com/hashicorp/go-hclog"
)

// GatewayClassConfigController reconciles GatewayClassConfig resources.
type GatewayClassConfigController struct {
	Client apigateway.Client
	Log    hclog.Logger
}

func NewGatewayClassController() *GatewayClassConfigController {
	return &GatewayClassConfigController{}
}

//+kubebuilder:rbac:groups=api-gateway.consul.hashicorp.com,resources=gatewayclassconfigs,verbs=get;update;list;watch
//+kubebuilder:rbac:groups=api-gateway.consul.hashicorp.com,resources=gatewayclassconfigs/finalizers,verbs=update

func (g *GatewayClassConfigController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := g.Log.With("gatewayClassConfig", req.NamespacedName)

	gcc, err := g.Client.GetGatewayClassConfig(ctx, req.NamespacedName)
	if err != nil {
		logger.Error("error getting gateway class config", "err", err)
		return ctrl.Result{}, err
	}

	logger.Info("reconciling gateway class config", "gatewayClassConfig", gcc)

	return ctrl.Result{}, nil
}
