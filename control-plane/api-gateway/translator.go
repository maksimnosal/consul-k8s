package apigateway

import (
	"fmt"
	capi "github.com/hashicorp/consul/api"
	"k8s.io/apimachinery/pkg/runtime"
	gwv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

type Translate interface {
	//TODO not sure which k8s interface exactly makes sense to use at the moment, think it would be object
	K8sObjectToConfigEntry(object runtime.Object) (capi.ConfigEntry, error)
	ConfigEntryToK8sObject(configEntry capi.ConfigEntry) (runtime.Object, error)
}

type Translator struct {
	consulClient capi.Client
}

func (t *Translator) K8sObjectToConfigEntry(object runtime.Object) (capi.ConfigEntry, error) {
	//determine type of k8s object
	switch object.(type) {
	case *gwv1beta1.Gateway:
		return t.gatewayK8sToConfig(object), nil
	}
	return nil, fmt.Errorf("invalid runtime.Object type")
}

func (t *Translator) ConfigEntryToK8sObject(configEntry capi.ConfigEntry) (runtime.Object, error) {
	//determine type of k8s object
	switch configEntry.(type) {
	case *capi.APIGatewayConfigEntry:
		return t.gatewayConfigToK8s(configEntry), nil
	}
	return nil, fmt.Errorf("invalid api.ConfigEntry type")
}

func (t *Translator) gatewayK8sToConfig(object runtime.Object) *capi.APIGatewayConfigEntry {
	gateway := object.(*gwv1beta1.Gateway)
	return &capi.APIGatewayConfigEntry{
		Kind: capi.APIGateway,
		Name: gateway.Name,
		//TODO how do we account for enterprise
		Namespace: "",
		//TODO how does this value map?
		Meta:      map[string]string{},
		Listeners: t.listenersK8sToConfig(gateway.Spec.Listeners),
	}
}

func (t *Translator) listenersK8sToConfig(listeners []gwv1beta1.Listener) []capi.APIGatewayListener {
	output := make([]capi.APIGatewayListener, len(listeners))
	for i, l := range listeners {
		output[i] = capi.APIGatewayListener{
			Name:     string(l.Name),
			Hostname: string(*l.Hostname),
			Port:     int(l.Port),
			Protocol: string(l.Protocol),
			TLS:      t.tlsK8sToConfig(l.TLS),
		}
	}
	return output
}

func (t *Translator) tlsK8sToConfig(tls *gwv1beta1.GatewayTLSConfig) capi.APIGatewayTLSConfiguration {
	return capi.APIGatewayTLSConfiguration{
		Certificates: t.k8sCertificatesToConfig(tls.CertificateRefs),
	}
}

// TODO this one will need a bit more work
func (t *Translator) k8sCertificatesToConfig(certs []gwv1beta1.SecretObjectReference) []capi.ResourceReference {
	return []capi.ResourceReference{}
}

func (t *Translator) gatewayConfigToK8s(configEntry capi.ConfigEntry) *gwv1beta1.Gateway {
	return &gwv1beta1.Gateway{}
}
