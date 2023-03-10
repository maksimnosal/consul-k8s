package apigateway

import (
	capi "github.com/hashicorp/consul/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gwv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	"time"
)

type Translator interface {
	//TODO not sure which k8s interface exactly makes sense to use at the moment, think it would be object
	K8sObjectToConfigEntry(object client.Object) capi.ConfigEntry
	ConfigEntryToK8sObject(configEntry capi.ConfigEntry)
}

type Translator struct {
	//TODO actually can probably get away with not having these clients at all and assume whatever is calling this knows things
	//but might need these at some point when translating secrets (?)
	//gatewayClient
	//consulClient
}

// would be replaced with gatewayclient.GetGateway in actual port
// TODO where should we put k8s controller helper files probably in the sub command
func fakeGatewayK8s() *gwv1beta1.Gateway {
	return &gwv1beta1.Gateway{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Gateway",
			APIVersion: "v1beta",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            "",
			GenerateName:    "",
			Namespace:       "",
			UID:             "",
			ResourceVersion: "",
			Generation:      0,
			CreationTimestamp: metav1.Time{
				Time: time.Time{},
			},
			DeletionTimestamp: &metav1.Time{
				Time: time.Time{},
			},
			DeletionGracePeriodSeconds: nil,
			Labels:                     nil,
			Annotations:                nil,
			OwnerReferences:            nil,
			Finalizers:                 nil,
			ManagedFields:              nil,
		},
		Spec: gwv1beta1.GatewaySpec{
			GatewayClassName: "test",
			Listeners: []gwv1beta1.Listener{
				{
					"",
					nil,
					0,
					"",
					&gwv1beta1.GatewayTLSConfig{
						Mode:            nil,
						CertificateRefs: nil,
						Options:         nil,
					},
					&gwv1beta1.AllowedRoutes{
						Namespaces: &gwv1beta1.RouteNamespaces{
							From: nil,
							Selector: &metav1.LabelSelector{
								MatchLabels:      nil,
								MatchExpressions: nil,
							},
						},
						Kinds: nil,
					},
				},
			},
			Addresses: nil,
		},
		Status: gwv1beta1.GatewayStatus{
			Addresses:  nil,
			Conditions: nil,
			Listeners:  nil,
		},
	}
}
