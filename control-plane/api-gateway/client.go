package apigateway

import (
	"context"
)

type Client interface {
	GetGatewayClassConfig(ctx context.Context, key any) (any, error)
}

type GatewayClient struct {
}

func (g *GatewayClient) GetGatewayClassConfig(ctx context.Context, key any) (any, error) {
	return nil, nil
}
