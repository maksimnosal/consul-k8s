package controller

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/hashicorp/consul-k8s/control-plane/cache"
	"github.com/hashicorp/consul-k8s/control-plane/consul"
	"github.com/hashicorp/consul/api"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
	gwapiv1a2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gwapiv1b1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

const (
	gatewaySecretCertificatesIndex = "__gateway-secret-certificates-index"
	gatewayClassNameIndex          = "__gateway-class-name-index"
	referenceGrantTargetIndex      = "__referencegrant-target-index"
	httpRouteGatewayIndex          = "__httproute-gateway-index"
	httpRouteServiceIndex          = "__httproute-service-index"
	tcpRouteGatewayIndex           = "__tcproute-gateway-index"
	tcpRouteServiceIndex           = "__tcproute-service-index"

	kindSecret  = "Secret"
	kindService = "Service"
	kindGateway = "Gateway"

	gatewayControllerManagerName = "gateway-controller"
	gatewayControllerClassName   = "consul.hashicorp.com/gateway-controller"
)

var (
	betaGroup    = gwapiv1b1.GroupVersion.Group
	betaVersion  = gwapiv1b1.GroupVersion.Version
	alphaGroup   = gwapiv1a2.GroupVersion.Group
	alphaVersion = gwapiv1a2.GroupVersion.Version
)

func serviceRefsForHTTPRoute(route *gwapiv1b1.HTTPRoute) []types.NamespacedName {
	var refs []types.NamespacedName
	for _, rule := range route.Spec.Rules {
		for _, backend := range rule.BackendRefs {
			if nilOrEqual(backend.Group, "") && nilOrEqual(backend.Kind, kindService) {
				// If an explicit Service namespace is not provided, use the route namespace to lookup the provided Service Name.
				refs = append(refs, indexedNamespacedNameWithDefault(backend.Name, backend.Namespace, route.Namespace))
			}
		}
	}
	return refs
}

func serviceRefsForTCPRoute(route *gwapiv1a2.TCPRoute) []types.NamespacedName {
	var refs []types.NamespacedName
	for _, rule := range route.Spec.Rules {
		for _, backend := range rule.BackendRefs {
			if nilOrEqual(backend.Group, "") && nilOrEqual(backend.Kind, kindService) {
				// If an explicit Service namespace is not provided, use the route namespace to lookup the provided Service Name.
				refs = append(refs, indexedNamespacedNameWithDefault(backend.Name, backend.Namespace, route.Namespace))
			}
		}
	}
	return refs
}

var gatewayIndices = []Indexer{
	// Gateway indexers

	// extract class names from gateways
	{
		Name: gatewayClassNameIndex,
		Kind: &gwapiv1b1.Gateway{},
		Extractor: func(o client.Object) []string {
			return []string{string(o.(*gwapiv1b1.Gateway).Spec.GatewayClassName)}
		},
	},
	// extract secret-based certificates from gateways
	{
		Name: gatewaySecretCertificatesIndex,
		Kind: &gwapiv1b1.Gateway{},
		Extractor: func(o client.Object) []string {
			gateway := o.(*gwapiv1b1.Gateway)
			var secretReferences []string
			for _, listener := range gateway.Spec.Listeners {
				if listener.TLS == nil || *listener.TLS.Mode != gwapiv1b1.TLSModeTerminate {
					continue
				}
				for _, cert := range listener.TLS.CertificateRefs {
					if nilOrEqual(cert.Group, "") && nilOrEqual(cert.Kind, kindSecret) {
						// If an explicit Secret namespace is not provided, use the Gateway namespace to lookup the provided Secret Name.
						secretReferences = append(secretReferences, indexedNamespacedNameWithDefault(cert.Name, cert.Namespace, gateway.Namespace).String())
					}
				}
			}
			return secretReferences
		},
	},

	// ReferenceGrant indexers
	{
		Name: referenceGrantTargetIndex,
		Kind: &gwapiv1b1.ReferenceGrant{},
		Extractor: func(o client.Object) []string {
			grant := o.(*gwapiv1a2.ReferenceGrant)
			var kinds []string
			for _, target := range grant.Spec.To {
				kinds = append(kinds, string(target.Kind))
			}
			return kinds
		},
	},

	// HTTPRoute indexers

	// extract gateway parents from http route
	{
		Name: httpRouteGatewayIndex,
		Kind: &gwapiv1b1.HTTPRoute{},
		Extractor: func(o client.Object) []string {
			route := o.(*gwapiv1b1.HTTPRoute)
			// If an explicit Gateway namespace is not provided, use the route namespace to lookup the provided Gateway Name.
			return parentRefsToIndexed(betaGroup, kindGateway, route.Namespace, route.Spec.ParentRefs)
		},
	},
	// extract service upstreams from http route
	{
		Name: httpRouteGatewayIndex,
		Kind: &gwapiv1b1.HTTPRoute{},
		Extractor: func(o client.Object) []string {
			route := o.(*gwapiv1b1.HTTPRoute)
			return stringArray(serviceRefsForHTTPRoute(route))
		},
	},

	// TCPRoute indexers

	// extract gateway parents from tcp route
	{
		Name: tcpRouteGatewayIndex,
		Kind: &gwapiv1a2.TCPRoute{},
		Extractor: func(o client.Object) []string {
			route := o.(*gwapiv1a2.TCPRoute)
			// If an explicit Gateway namespace is not provided, use the route namespace to lookup the provided Gateway Name.
			return parentRefsToIndexed(betaGroup, kindGateway, route.Namespace, route.Spec.ParentRefs)
		},
	},
	// extract service upstreams from tcp route
	{
		Name: tcpRouteServiceIndex,
		Kind: &gwapiv1a2.TCPRoute{},
		Extractor: func(o client.Object) []string {
			route := o.(*gwapiv1a2.TCPRoute)
			return stringArray(serviceRefsForTCPRoute(route))
		},
	},
}

type GatewayControllerConfig struct {
	ConsulClientConfig  *consul.Config
	ConsulServerConnMgr consul.ServerConnectionManager
	NamespacesEnabled   bool
	Partition           string
	Logger              logr.Logger
}

// GatewayController handles reconciliations for Gateway objects.
type GatewayController struct {
	cache               *cache.Cache
	client              client.Client
	controllerClassName gwapiv1b1.GatewayController
	log                 logr.Logger
}

func (c *GatewayController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return ctrl.Result{}, nil
}

func (c *GatewayController) isOwnedGateway(ctx context.Context) func(o client.Object) bool {
	return func(o client.Object) bool {
		gateway, ok := o.(*gwapiv1b1.Gateway)
		if !ok {
			return false
		}

		gatewayclass := &gwapiv1b1.GatewayClass{}
		key := types.NamespacedName{Name: string(gateway.Spec.GatewayClassName)}
		if err := c.client.Get(ctx, key, gatewayclass); err != nil {
			return false
		}

		return gatewayclass.Spec.ControllerName == c.controllerClassName
	}
}

func (c *GatewayController) transformGatewayClass(ctx context.Context) func(o client.Object) []reconcile.Request {
	return func(o client.Object) []reconcile.Request {
		gatewayclass := o.(*gwapiv1b1.GatewayClass)
		gatewayList := &gwapiv1b1.GatewayList{}
		if err := c.client.List(ctx, gatewayList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(gatewayClassNameIndex, gatewayclass.Name),
		}); err != nil {
			return nil
		}
		return objectsToRequests(pointersOf(gatewayList.Items))
	}
}

func (c *GatewayController) transformHTTPRoute(ctx context.Context) func(o client.Object) []reconcile.Request {
	return func(o client.Object) []reconcile.Request {
		route := o.(*gwapiv1b1.HTTPRoute)
		return refsToRequests(parentRefs(betaGroup, kindGateway, route.Namespace, route.Spec.ParentRefs))
	}
}

func (c *GatewayController) transformTCPRoute(ctx context.Context) func(o client.Object) []reconcile.Request {
	return func(o client.Object) []reconcile.Request {
		route := o.(*gwapiv1a2.TCPRoute)
		return refsToRequests(parentRefs(betaGroup, kindGateway, route.Namespace, route.Spec.ParentRefs))
	}
}

func (c *GatewayController) transformReferenceGrant(ctx context.Context) func(o client.Object) []reconcile.Request {
	return func(o client.Object) []reconcile.Request {
		// just reconcile all gateways within the namespace
		grant := o.(*gwapiv1b1.ReferenceGrant)
		gatewayList := &gwapiv1b1.GatewayList{}
		if err := c.client.List(ctx, gatewayList, &client.ListOptions{
			Namespace: grant.Namespace,
		}); err != nil {
			return nil
		}
		return objectsToRequests(pointersOf(gatewayList.Items))
	}
}

func (c *GatewayController) transformSecret(ctx context.Context) func(o client.Object) []reconcile.Request {
	return func(o client.Object) []reconcile.Request {
		secret := o.(*corev1.Secret)
		gatewayList := &gwapiv1b1.GatewayList{}
		if err := c.client.List(ctx, gatewayList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(gatewaySecretCertificatesIndex, secret.Name),
		}); err != nil {
			return nil
		}
		return objectsToRequests(pointersOf(gatewayList.Items))
	}
}

func (c *GatewayController) transformConsulGateway(ctx context.Context) func(config api.ConfigEntry) []types.NamespacedName {
	return func(config api.ConfigEntry) []types.NamespacedName {
		meta, ok := metaToK8sMeta(config)
		if !ok {
			return nil
		}
		return []types.NamespacedName{meta}
	}
}

func (c *GatewayController) transformConsulHTTPRoute(ctx context.Context) func(config api.ConfigEntry) []types.NamespacedName {
	return func(config api.ConfigEntry) []types.NamespacedName {
		route, ok := config.(*api.HTTPRouteConfigEntry)
		if !ok {
			return nil
		}

		return consulRefsToMeta(c.cache, route.Parents)
	}
}

func (c *GatewayController) transformConsulTCPRoute(ctx context.Context) func(config api.ConfigEntry) []types.NamespacedName {
	return func(config api.ConfigEntry) []types.NamespacedName {
		route, ok := config.(*api.TCPRouteConfigEntry)
		if !ok {
			return nil
		}

		return consulRefsToMeta(c.cache, route.Parents)
	}
}

func (c *GatewayController) transformConsulInlineCertificate(ctx context.Context) func(config api.ConfigEntry) []types.NamespacedName {
	return func(config api.ConfigEntry) []types.NamespacedName {
		meta, ok := metaToK8sMeta(config)
		if !ok {
			return nil
		}
		return requestsToRefs(c.transformSecret(ctx)(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      meta.Name,
				Namespace: meta.Namespace,
			},
		}))
	}
}

// SetupGatewayControllerWithManager sets up the controller manager with the proper subscriptions for Gateways.
func SetupGatewayControllerWithManager(ctx context.Context, mgr ctrl.Manager, config GatewayControllerConfig) (*cache.Cache, error) {
	if err := addIndexers(ctx, mgr, gatewayIndices...); err != nil {
		return nil, err
	}

	cache := cache.New(cache.Config{
		ConsulClientConfig:  config.ConsulClientConfig,
		ConsulServerConnMgr: config.ConsulServerConnMgr,
		Logger:              config.Logger,
		NamespacesEnabled:   config.NamespacesEnabled,
		Partition:           config.Partition,
		Kinds: []string{
			api.APIGateway,
			api.HTTPRoute,
			api.TCPRoute,
			api.InlineCertificate,
		},
	})
	c := &GatewayController{
		client:              mgr.GetClient(),
		cache:               cache,
		controllerClassName: gwapiv1b1.GatewayController(gatewayControllerClassName),
		log:                 config.Logger,
	}

	return cache, ctrl.NewControllerManagedBy(mgr).For(
		&gwapiv1b1.Gateway{},
		builder.WithPredicates(predicate.NewPredicateFuncs(c.isOwnedGateway(ctx))),
	).Owns(
		// Watch owned deployments we create and process owner Gateways.
		&appsv1.Deployment{},
	).Owns(
		// Watch owned services we create and process owner Gateways.
		&corev1.Service{},
	).Owns(
		// Watch owned pods we create and process owner Gateways.
		&corev1.Pod{},
	).Watches(
		// Watch GatewayClass CRUDs and process affected Gateways.
		source.NewKindWithCache(&gwapiv1b1.GatewayClass{}, mgr.GetCache()),
		handler.EnqueueRequestsFromMapFunc(c.transformGatewayClass(ctx)),
	).Watches(
		// Watch HTTPRoute CRUDs and process affected Gateways.
		source.NewKindWithCache(&gwapiv1b1.HTTPRoute{}, mgr.GetCache()),
		handler.EnqueueRequestsFromMapFunc(c.transformHTTPRoute(ctx)),
	).Watches(
		// Watch TCPRoute CRUDs and process affected Gateways.
		source.NewKindWithCache(&gwapiv1a2.TCPRoute{}, mgr.GetCache()),
		handler.EnqueueRequestsFromMapFunc(c.transformTCPRoute(ctx)),
	).Watches(
		// Watch Secret CRUDs and process affected Gateways.
		source.NewKindWithCache(&corev1.Secret{}, mgr.GetCache()),
		handler.EnqueueRequestsFromMapFunc(c.transformSecret(ctx)),
	).Watches(
		// Watch ReferenceGrant CRUDs and process affected Gateways.
		source.NewKindWithCache(&gwapiv1a2.ReferenceGrant{}, mgr.GetCache()),
		handler.EnqueueRequestsFromMapFunc(c.transformReferenceGrant(ctx)),
	).Watches(
		// Subscribe to changes from Consul for APIGateways
		&source.Channel{Source: cache.Subscribe(ctx, api.APIGateway, c.transformConsulGateway(ctx)).Events()},
		&handler.EnqueueRequestForObject{},
	).Watches(
		// Subscribe to changes from Consul for HTTPRoutes
		&source.Channel{Source: cache.Subscribe(ctx, api.APIGateway, c.transformConsulHTTPRoute(ctx)).Events()},
		&handler.EnqueueRequestForObject{},
	).Watches(
		// Subscribe to changes from Consul for TCPRoutes
		&source.Channel{Source: cache.Subscribe(ctx, api.APIGateway, c.transformConsulTCPRoute(ctx)).Events()},
		&handler.EnqueueRequestForObject{},
	).Watches(
		// Subscribe to changes from Consul for InlineCertificates
		&source.Channel{Source: cache.Subscribe(ctx, api.InlineCertificate, c.transformConsulInlineCertificate(ctx)).Events()},
		&handler.EnqueueRequestForObject{},
	).Complete(c)
}
