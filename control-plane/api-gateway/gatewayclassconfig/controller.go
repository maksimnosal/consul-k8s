package gatewayclassconfig

type GatewayClassController struct {
}

func NewGatewayClassController() *GatewayClassController {
	return &GatewayClassController{}
}

func (g *GatewayClassController) Reconcile() error {
	return nil
}
