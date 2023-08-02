package connectinject

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/go-logr/logr"
	"github.com/hashicorp/consul-k8s/control-plane/consul"
	"github.com/hashicorp/consul-k8s/control-plane/namespaces"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-multierror"
	"github.com/mitchellh/hashstructure/v2"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	MetaKeyPodName             = "pod-name"
	MetaKeyKubeServiceName     = "k8s-service-name"
	MetaKeyKubeNS              = "k8s-namespace"
	MetaKeyManagedBy           = "managed-by"
	TokenMetaPodNameKey        = "pod"
	kubernetesSuccessReasonMsg = "Kubernetes health checks passing"
	envoyPrometheusBindAddr    = "envoy_prometheus_bind_addr"
	envoySidecarContainer      = "envoy-sidecar"

	// clusterIPTaggedAddressName is the key for the tagged address to store the service's cluster IP and service port
	// in Consul. Note: This value should not be changed without a corresponding change in Consul.
	clusterIPTaggedAddressName = "virtual"

	// exposedPathsLivenessPortsRangeStart is the start of the port range that we will use as
	// the ListenerPort for the Expose configuration of the proxy registration for a liveness probe.
	exposedPathsLivenessPortsRangeStart = 20300

	// exposedPathsReadinessPortsRangeStart is the start of the port range that we will use as
	// the ListenerPort for the Expose configuration of the proxy registration for a readiness probe.
	exposedPathsReadinessPortsRangeStart = 20400

	// exposedPathsStartupPortsRangeStart is the start of the port range that we will use as
	// the ListenerPort for the Expose configuration of the proxy registration for a startup probe.
	exposedPathsStartupPortsRangeStart = 20500
)

type EndpointsController struct {
	client.Client
	// ConsulClient points at the agent local to the connect-inject deployment pod.
	ConsulClient *api.Client
	// ConsulClientCfg is the client config used by the ConsulClient when calling NewClient().
	ConsulClientCfg *api.Config
	// ConsulScheme is the scheme to use when making API calls to Consul,
	// i.e. "http" or "https".
	ConsulScheme string
	// ConsulPort is the port to make HTTP API calls to Consul agents on.
	ConsulPort string
	// Only endpoints in the AllowK8sNamespacesSet are reconciled.
	AllowK8sNamespacesSet mapset.Set
	// Endpoints in the DenyK8sNamespacesSet are ignored.
	DenyK8sNamespacesSet mapset.Set
	// EnableConsulPartitions indicates that a user is running Consul Enterprise
	// with version 1.11+ which supports Admin Partitions.
	EnableConsulPartitions bool
	// EnableConsulNamespaces indicates that a user is running Consul Enterprise
	// with version 1.7+ which supports namespaces.
	EnableConsulNamespaces bool
	// ConsulDestinationNamespace is the name of the Consul namespace to create
	// all config entries in. If EnableNSMirroring is true this is ignored.
	ConsulDestinationNamespace string
	// EnableNSMirroring causes Consul namespaces to be created to match the
	// k8s namespace of any config entry custom resource. Config entries will
	// be created in the matching Consul namespace.
	EnableNSMirroring bool
	// NSMirroringPrefix is an optional prefix that can be added to the Consul
	// namespaces created while mirroring. For example, if it is set to "k8s-",
	// then the k8s `default` namespace will be mirrored in Consul's
	// `k8s-default` namespace.
	NSMirroringPrefix string
	// CrossNSACLPolicy is the name of the ACL policy to attach to
	// any created Consul namespaces to allow cross namespace service discovery.
	// Only necessary if ACLs are enabled.
	CrossNSACLPolicy string
	// ReleaseName is the Consul Helm installation release.
	ReleaseName string
	// ReleaseNamespace is the namespace where Consul is installed.
	ReleaseNamespace string
	// EnableTransparentProxy controls whether transparent proxy should be enabled
	// for all proxy service registrations.
	EnableTransparentProxy bool
	// TProxyOverwriteProbes controls whether the endpoints controller should expose pod's HTTP probes
	// via Envoy proxy.
	TProxyOverwriteProbes bool
	// AuthMethod is the name of the Kubernetes Auth Method that
	// was used to login with Consul. The Endpoints controller
	// will delete any tokens associated with this auth method
	// whenever service instances are deregistered.
	AuthMethod string

	MetricsConfig MetricsConfig
	Log           logr.Logger

	Scheme *runtime.Scheme
	context.Context

	stateMutex sync.Mutex
	podCache   map[serviceName]map[podID]podStatus
	agentCache map[hostIP]agentStatus
}

type hostIP string

type serviceName struct {
	name string
	ns   string
}

type podID struct {
	name string
	ns   string
}

type podStatus struct {
	serviceName         serviceName
	podID               podID
	hostIP              hostIP
	health              string
	agentCreationTime   time.Time
	registrationSuccess bool
	registrationHash    uint64
}

type agentStatus struct {
	cachePopulated bool
	creationTime   time.Time
	client         *api.Client
}

type addressHealth struct {
	address corev1.EndpointAddress
	health  string
}

type svcRegistration struct {
	id      string
	proxy   *api.AgentServiceConnectProxyConfig
	connect *api.AgentServiceConnect
}

func (r *EndpointsController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if shouldIgnore(req.Namespace, r.DenyK8sNamespacesSet, r.AllowK8sNamespacesSet) {
		return ctrl.Result{}, nil
	}
	k8sService := serviceName{ns: req.Namespace, name: req.Name}

	// Fetch the latest listing of agents.
	currentAgents, err := r.fetchAgents(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Detect new and bounced agents.
	newAgents := map[hostIP]corev1.Pod{}
	for _, agent := range currentAgents.Items {
		creationTime := getAgentCreationTime(agent)
		hostIP := hostIP(agent.Status.HostIP)
		oldAgentStatus := r.agentCache[hostIP]
		if hostIP != "" {
			// Mark our agent as new if it restarted (bounced) or if the cache was never populated for it.
			if !oldAgentStatus.cachePopulated || creationTime.After(oldAgentStatus.creationTime) {
				newAgents[hostIP] = agent
			}
		}
	}

	// Remove any entries that were related to a now-dead agent / node.
	r.removeStaleAgentCacheEntries(k8sService, currentAgents)
	// Attempt to get new state from any agents that aren't in the cache already.
	cacheError := r.populateCache(ctx, req, newAgents)
	if cacheError != nil {
		r.Log.Error(cacheError, "An error occurred while populating the cache", err)
	}

	// Get the service endpoints
	var serviceEndpoints corev1.Endpoints
	err = r.Client.Get(ctx, req.NamespacedName, &serviceEndpoints)
	// If the endpoints object has been deleted (and we get an IsNotFound error),
	// we need to deregister all instances in Consul for that service.
	if k8serrors.IsNotFound(err) {
		// Deregister all instances in Consul for this service. The function deregisterServiceOnAgents handles
		// the case where the Consul service name is different from the Kubernetes service name.
		if err = r.deregisterServiceOnAgents(ctx, k8sService, r.podCache[k8sService]); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	} else if err != nil {
		// Make no changes if we failed to fetch the endpoints.
		r.Log.Error(err, "failed to get Endpoints", "name", req.Name, "ns", req.Namespace)
		return ctrl.Result{}, err
	}

	// Handle service registrations and capture any pods that are now "missing" so that they can be deregistered.
	var registerErrors error
	missingPods := make(map[podID]bool)
	seenPods := make(map[podID]bool)
	for _, subset := range serviceEndpoints.Subsets {
		allAddresses := make([]addressHealth, 0, 100)
		for _, address := range subset.Addresses {
			if address.TargetRef != nil && address.TargetRef.Kind == "Pod" {
				allAddresses = append(allAddresses, addressHealth{address: address, health: api.HealthPassing})
				seenPods[podID{name: address.TargetRef.Name, ns: address.TargetRef.Namespace}] = true
			}
		}
		for _, address := range subset.NotReadyAddresses {
			if address.TargetRef != nil && address.TargetRef.Kind == "Pod" {
				allAddresses = append(allAddresses, addressHealth{address: address, health: api.HealthCritical})
				seenPods[podID{name: address.TargetRef.Name, ns: address.TargetRef.Namespace}] = true
			}
		}
		missingPods, err = r.updateHealthAndRegistrations(ctx, serviceEndpoints, allAddresses)
		if err != nil {
			// Do not perform service deregistrations if there was an error performing registrations.
			// This will prevent accidental k8s API query failures from triggering bad behavior.
			registerErrors = multierror.Append(registerErrors, err)
		}
	}

	// Only deregister services if no errors were encountered, since otherwise we could be stuck in an unknown state and may incorrectly
	// remove services. This is possible if fetching a pod via the k8s API fails, since we wouldn't know enough metadata to make a decision.
	if err != nil || registerErrors != nil {
		return ctrl.Result{}, err
	}

	toDeregister := make(map[podID]podStatus)
	for podID, pod := range r.podCache[k8sService] {
		_, seen := seenPods[podID]
		_, missing := missingPods[podID]
		// If we didn't encounter the pod in the current service endpoint listing
		// or if we explicitly got a 404 when fetching the pod from k8s, then it should be deregistered.
		if !seen || missing {
			toDeregister[podID] = pod
		}
	}

	// Compare service instances in Consul with addresses in Endpoints. If an address is not in Endpoints, deregister
	// from Consul. This uses endpointAddressMap which is populated with the addresses in the Endpoints object during
	// the registration codepath.
	if err = r.deregisterServiceOnAgents(ctx, k8sService, toDeregister); err != nil {
		r.Log.Error(err, "failed to deregister endpoints on all agents", "name", serviceEndpoints.Name, "ns", serviceEndpoints.Namespace)
		return ctrl.Result{}, err
	}

	// Save the new agent statuses if we were able to successfully reconcile differences.
	r.agentCache = make(map[hostIP]agentStatus)
	for _, agent := range currentAgents.Items {
		hostIP := hostIP(agent.Status.HostIP)
		if hostIP != "" {
			r.agentCache[hostIP] = agentStatus{
				client:         r.agentCache[hostIP].client,
				cachePopulated: r.agentCache[hostIP].cachePopulated,
				creationTime:   getAgentCreationTime(agent),
			}
		}
	}

	// Return the cache error at the very end. This ensures that if there was some issue fetching info from agents,
	// then we will come back and attempt to deregister services.
	return ctrl.Result{}, cacheError
}

func (r *EndpointsController) updateHealthAndRegistrations(ctx context.Context, serviceEndpoints corev1.Endpoints, allAddresses []addressHealth) (map[podID]bool, error) {
	var errs error
	concurrentCalls := getConcurrentCalls()
	if concurrentCalls > len(allAddresses) {
		concurrentCalls = len(allAddresses)
	}

	// Wait for all items to complete before returning to preserve the original flow of data.
	r.Log.Info("Queuing up updateHealthAndRegistrations",
		"tasks", len(allAddresses), "goroutines", concurrentCalls, "svc", serviceEndpoints.Name, "ns", serviceEndpoints.Namespace)
	var waiter sync.WaitGroup
	waiter.Add(concurrentCalls)

	// Queue the agent calls.
	var hadError atomic.Bool
	allMissingPods := make(map[podID]bool)
	addressHealthChan := make(chan addressHealth)
	for i := 0; i < concurrentCalls; i++ {
		go func() {
			defer waiter.Done()
			for addrHealth := range addressHealthChan {
				podID := podID{name: addrHealth.address.TargetRef.Name, ns: addrHealth.address.TargetRef.Namespace}
				if missingPod, err := r.updateHealthAndRegistration(ctx, podID, addrHealth.health, serviceEndpoints); err != nil {
					r.Log.Error(err, "error while reconciling address", "address", addrHealth.address, "pod", podID)
					hadError.Store(true)
				} else if missingPod {
					r.stateMutex.Lock()
					allMissingPods[podID] = true
					r.stateMutex.Unlock()
				}
			}
		}()
	}

	for _, health := range allAddresses {
		addressHealthChan <- health
	}
	close(addressHealthChan)

	waiter.Wait()
	r.Log.Info("Done with all tasks for updateHealthAndRegistrations", "tasks", len(allAddresses))
	if hadError.Load() {
		errs = fmt.Errorf("some updateHealthAndRegistrations tasks were not successful")
	}
	return allMissingPods, errs
}

func (r *EndpointsController) updateHealthAndRegistration(
	ctx context.Context,
	podID podID,
	newHealth string,
	serviceEndpoints corev1.Endpoints,
) (missing bool, err error) {
	// Get pod associated with this address.
	var pod corev1.Pod
	objectKey := types.NamespacedName{Name: podID.name, Namespace: podID.ns}
	if err := r.Client.Get(ctx, objectKey, &pod); err != nil {
		if k8serrors.IsNotFound(err) {
			// If the pod doesn't exist, then we won't put an entry in the endpointAddressMap
			// and it will be deregistered. The rest of this flow is not necessary.
			return true, nil
		}
		r.Log.Error(err, "failed to get pod", "pod", podID)
		return false, err
	}
	// Do nothing if we don't manage the pod with connect-inject.
	if !hasBeenInjected(pod) {
		return false, nil
	}
	var managedByEndpointsController bool
	if raw, ok := pod.Labels[keyManagedBy]; ok && raw == managedByValue {
		managedByEndpointsController = true
	}

	// Get information from the pod to create service instance registrations.
	serviceRegistration, proxyServiceRegistration, err := r.createServiceRegistrations(pod, serviceEndpoints)
	if err != nil {
		r.Log.Error(err, "failed to create service registrations for endpoints",
			"name", serviceEndpoints.Name, "ns", serviceEndpoints.Namespace, "pod", podID)
		return false, err
	}
	registration := svcRegistration{
		id:      serviceRegistration.ID,
		proxy:   serviceRegistration.Proxy,
		connect: serviceRegistration.Connect,
	}
	svcRegHash, err := hashstructure.Hash(registration, hashstructure.FormatV2, nil)
	if err != nil {
		r.Log.Error(err, "failed to hash service registration", "name", serviceRegistration.Name)
		return false, err
	}

	// For pods managed by this controller, create and register the service instance.
	serviceName := serviceName{name: serviceEndpoints.Name, ns: serviceEndpoints.Namespace}
	serviceID := getServiceID(pod, serviceEndpoints)
	healthCheckID := getConsulHealthCheckID(pod, serviceID)
	podHostIP := hostIP(pod.Status.HostIP)
	if podHostIP == "" {
		return false, fmt.Errorf("pod had an unexpected missing host IP: %v", podID)
	}

	r.stateMutex.Lock()
	agentStatus := r.agentCache[hostIP(pod.Status.HostIP)]
	oldStatus, found := r.podCache[serviceName][podID]
	r.stateMutex.Unlock()

	shouldUpdateRegistration := (
	// The instance was not found
	!found ||
		// Or a previous registration was not successful
		!oldStatus.registrationSuccess ||
		// Or the service registration changed
		oldStatus.registrationHash != svcRegHash ||
		// Or the agent was restarted
		!oldStatus.agentCreationTime.Equal(agentStatus.creationTime))
	shouldUpdateHealth := (shouldUpdateRegistration ||
		// The health status changed
		oldStatus.health != newHealth)

	// Create client for Consul agent local to the pod.
	client, err := r.getAgentClient(hostIP(pod.Status.HostIP), r.consulNamespace(pod.Namespace))
	if err != nil {
		r.Log.Error(err, "failed to get a Consul client", "address", podHostIP)
		return false, err
	}

	newStatus := podStatus{
		serviceName:         serviceName,
		podID:               podID,
		hostIP:              podHostIP,
		agentCreationTime:   agentStatus.creationTime,
		registrationHash:    svcRegHash,
		registrationSuccess: true, // the registration should be considered successful unless managed by an endpoints controller.
		health:              "",   // set this to empty until we save the health check successfully.
	}
	if shouldUpdateRegistration && managedByEndpointsController {
		// Add an entry into our cache since we've done a partial service registration.
		r.stateMutex.Lock()
		newStatus.registrationSuccess = false
		r.trackPod(newStatus)
		r.stateMutex.Unlock()

		// Register the service instance with the local agent.
		// Note: the order of how we register services is important,
		// and the connect-proxy service should come after the "main" service
		// because its alias health check depends on the main service existing.
		r.Log.Info("registering service with Consul", "name", serviceRegistration.Name,
			"id", serviceRegistration.ID, "agentIP", podHostIP)
		err = client.Agent().ServiceRegister(serviceRegistration)
		if err != nil {
			r.Log.Error(err, "failed to register service", "name", serviceRegistration.Name)
			return false, err
		}

		// Register the proxy service instance with the local agent.
		r.Log.Info("registering proxy service with Consul", "name", proxyServiceRegistration.Name)
		err = client.Agent().ServiceRegister(proxyServiceRegistration)
		if err != nil {
			r.Log.Error(err, "failed to register proxy service", "name", proxyServiceRegistration.Name)
			return false, err
		}

		// Save the successful registration
		r.stateMutex.Lock()
		newStatus.registrationSuccess = true
		r.trackPod(newStatus)
		r.stateMutex.Unlock()
	}

	// Update the service TTL health check for both legacy services and services managed by endpoints
	// controller. The proxy health checks are registered separately by endpoints controller and
	// lifecycle sidecar for legacy services. Here, we always update the health check for legacy and
	// newer services idempotently since the service health check is not added as part of the service
	// registration.
	if shouldUpdateHealth || os.Getenv("INJECT_FORCE_HEALTH_UPDATES") == "TRUE" {
		err = r.upsertHealthCheck(pod, client, serviceID, healthCheckID, newHealth)
		if err != nil {
			r.Log.Error(err, "failed to update health check status for service", "serviceID", serviceID)
			return false, err
		}
		r.stateMutex.Lock()
		newStatus.health = newHealth
		r.trackPod(newStatus)
		r.stateMutex.Unlock()
	}

	return false, nil
}

func (r *EndpointsController) Logger(name types.NamespacedName) logr.Logger {
	return r.Log.WithValues("request", name)
}

func (r *EndpointsController) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Endpoints{}).
		Watches(
			&source.Kind{Type: &corev1.Pod{}},
			handler.EnqueueRequestsFromMapFunc(r.requestsForRunningAgentPods),
			builder.WithPredicates(predicate.NewPredicateFuncs(r.filterAgentPods)),
		).Complete(r)
}

// getServiceCheck will return the health check for this pod and service if it exists.
func getServiceCheck(client *api.Client, healthCheckID string) (*api.AgentCheck, error) {
	filter := fmt.Sprintf("CheckID == `%s`", healthCheckID)
	checks, err := client.Agent().ChecksWithFilter(filter)
	if err != nil {
		return nil, err
	}
	// This will be nil (does not exist) or an actual check.
	return checks[healthCheckID], nil
}

// registerConsulHealthCheck registers a TTL health check for the service on this Agent local to the Pod. This will add
// the Pod's readiness status, which will mark the service instance healthy/unhealthy for Consul service mesh
// traffic.
func registerConsulHealthCheck(client *api.Client, consulHealthCheckID, serviceID, status string) error {
	// Create a TTL health check in Consul associated with this service and pod.
	// The TTL time is 100000h which should ensure that the check never fails due to timeout
	// of the TTL check.
	err := client.Agent().CheckRegister(&api.AgentCheckRegistration{
		ID:        consulHealthCheckID,
		Name:      "Kubernetes Health Check",
		ServiceID: serviceID,
		AgentServiceCheck: api.AgentServiceCheck{
			TTL:                    "100000h",
			Status:                 status,
			SuccessBeforePassing:   1,
			FailuresBeforeCritical: 1,
		},
	})
	if err != nil {
		// Full error looks like:
		// Unexpected response code: 500 (ServiceID "consulnamespace/svc-id" does not exist)
		if strings.Contains(err.Error(), fmt.Sprintf("%s\" does not exist", serviceID)) {
			return fmt.Errorf("service %q not found in Consul: unable to register health check", serviceID)
		}
		return fmt.Errorf("registering health check for service %q: %w", serviceID, err)
	}

	return nil
}

// updateConsulHealthCheckStatus updates the consul health check status.
func (r *EndpointsController) updateConsulHealthCheckStatus(client *api.Client, consulHealthCheckID, status, reason string) error {
	r.Log.Info("updating health check", "id", consulHealthCheckID)
	err := client.Agent().UpdateTTL(consulHealthCheckID, reason, status)
	if err != nil {
		return fmt.Errorf("error updating health check: %w", err)
	}
	return nil
}

// upsertHealthCheck checks if the healthcheck exists for the service, and creates it if it doesn't exist, or updates it
// if it does.
func (r *EndpointsController) upsertHealthCheck(pod corev1.Pod, client *api.Client, serviceID, healthCheckID, status string) error {
	reason := getHealthCheckStatusReason(status, pod.Name, pod.Namespace)
	// Retrieve the health check that would exist if the service had one registered for this pod.
	serviceCheck, err := getServiceCheck(client, healthCheckID)
	if err != nil {
		return fmt.Errorf("unable to get agent health checks: serviceID=%s, checkID=%s, %s", serviceID, healthCheckID, err)
	}
	if serviceCheck == nil {
		r.Log.Info("inserting health check status for service", "serviceID", serviceID, "reason", reason, "status", status)
		// Create a new health check.
		err = registerConsulHealthCheck(client, healthCheckID, serviceID, status)
		if err != nil {
			return err
		}

		// Also update it, the reason this is separate is there is no way to set the Output field of the health check
		// at creation time, and this is what is displayed on the UI as opposed to the Notes field.
		err = r.updateConsulHealthCheckStatus(client, healthCheckID, status, reason)
		if err != nil {
			return err
		}
	} else if serviceCheck.Status != status {
		r.Log.Info("updating health check status for service", "serviceID", serviceID, "reason", reason, "status", status)
		err = r.updateConsulHealthCheckStatus(client, healthCheckID, status, reason)
		if err != nil {
			return err
		}
	}
	return nil
}

// TODO this looks odd. Is it correct?
func getServiceName(pod corev1.Pod, serviceEndpoints corev1.Endpoints) string {
	serviceName := serviceEndpoints.Name
	if serviceNameFromAnnotation, ok := pod.Annotations[annotationService]; ok && serviceNameFromAnnotation != "" {
		serviceName = serviceNameFromAnnotation
	}
	return serviceName
}

func getServiceID(pod corev1.Pod, serviceEndpoints corev1.Endpoints) string {
	return fmt.Sprintf("%s-%s", pod.Name, getServiceName(pod, serviceEndpoints))
}

func getProxyServiceName(pod corev1.Pod, serviceEndpoints corev1.Endpoints) string {
	serviceName := getServiceName(pod, serviceEndpoints)
	return fmt.Sprintf("%s-sidecar-proxy", serviceName)
}

func getProxyServiceID(pod corev1.Pod, serviceEndpoints corev1.Endpoints) string {
	proxyServiceName := getProxyServiceName(pod, serviceEndpoints)
	return fmt.Sprintf("%s-%s", pod.Name, proxyServiceName)
}

// createServiceRegistrations creates the service and proxy service instance registrations with the information from the
// Pod.
func (r *EndpointsController) createServiceRegistrations(pod corev1.Pod, serviceEndpoints corev1.Endpoints) (*api.AgentServiceRegistration, *api.AgentServiceRegistration, error) {
	// If a port is specified, then we determine the value of that port
	// and register that port for the host service.
	// The handler will always set the port annotation if one is not provided on the pod.
	var consulServicePort int
	if raw, ok := pod.Annotations[annotationPort]; ok && raw != "" {
		if port, err := portValue(pod, raw); port > 0 {
			if err != nil {
				return nil, nil, err
			}
			consulServicePort = int(port)
		}
	}

	// We only want that annotation to be present when explicitly overriding the consul svc name
	// Otherwise, the Consul service name should equal the Kubernetes Service name.
	// The service name in Consul defaults to the Endpoints object name, and is overridden by the pod
	// annotation consul.hashicorp.com/connect-service..
	serviceName := getServiceName(pod, serviceEndpoints)

	serviceID := getServiceID(pod, serviceEndpoints)

	meta := map[string]string{
		MetaKeyPodName:         pod.Name,
		MetaKeyKubeServiceName: serviceEndpoints.Name,
		MetaKeyKubeNS:          serviceEndpoints.Namespace,
		MetaKeyManagedBy:       managedByValue,
	}
	for k, v := range pod.Annotations {
		if strings.HasPrefix(k, annotationMeta) && strings.TrimPrefix(k, annotationMeta) != "" {
			meta[strings.TrimPrefix(k, annotationMeta)] = v
		}
	}

	var tags []string
	if raw, ok := pod.Annotations[annotationTags]; ok && raw != "" {
		tags = strings.Split(raw, ",")
	}
	// Get the tags from the deprecated tags annotation and combine.
	if raw, ok := pod.Annotations[annotationConnectTags]; ok && raw != "" {
		tags = append(tags, strings.Split(raw, ",")...)
	}

	service := &api.AgentServiceRegistration{
		ID:        serviceID,
		Name:      serviceName,
		Port:      consulServicePort,
		Address:   pod.Status.PodIP,
		Meta:      meta,
		Namespace: r.consulNamespace(pod.Namespace),
	}
	if len(tags) > 0 {
		service.Tags = tags
	}

	proxyServiceName := getProxyServiceName(pod, serviceEndpoints)
	proxyServiceID := getProxyServiceID(pod, serviceEndpoints)
	proxyConfig := &api.AgentServiceConnectProxyConfig{
		DestinationServiceName: serviceName,
		DestinationServiceID:   serviceID,
		Config:                 make(map[string]interface{}),
	}

	// If metrics are enabled, the proxyConfig should set envoy_prometheus_bind_addr to a listener on 0.0.0.0 on
	// the prometheusScrapePort that points to a metrics backend. The backend for this listener will be determined by
	// the envoy bootstrapping command (consul connect envoy) configuration in the init container. If there is a merged
	// metrics server, the backend would be that server. If we are not running the merged metrics server, the backend
	// should just be the Envoy metrics endpoint.
	enableMetrics, err := r.MetricsConfig.enableMetrics(pod)
	if err != nil {
		return nil, nil, err
	}
	if enableMetrics {
		prometheusScrapePort, err := r.MetricsConfig.prometheusScrapePort(pod)
		if err != nil {
			return nil, nil, err
		}
		prometheusScrapeListener := fmt.Sprintf("0.0.0.0:%s", prometheusScrapePort)
		proxyConfig.Config[envoyPrometheusBindAddr] = prometheusScrapeListener
	}

	if consulServicePort > 0 {
		proxyConfig.LocalServiceAddress = "127.0.0.1"
		proxyConfig.LocalServicePort = consulServicePort
	}

	upstreams, err := r.processUpstreams(pod)
	if err != nil {
		return nil, nil, err
	}
	proxyConfig.Upstreams = upstreams

	proxyService := &api.AgentServiceRegistration{
		Kind:      api.ServiceKindConnectProxy,
		ID:        proxyServiceID,
		Name:      proxyServiceName,
		Port:      20000,
		Address:   pod.Status.PodIP,
		Meta:      meta,
		Namespace: r.consulNamespace(pod.Namespace),
		Proxy:     proxyConfig,
		Checks: api.AgentServiceChecks{
			{
				Name:                           "Proxy Public Listener",
				TCP:                            fmt.Sprintf("%s:20000", pod.Status.PodIP),
				Interval:                       "10s",
				DeregisterCriticalServiceAfter: "10m",
			},
			{
				Name:         "Destination Alias",
				AliasService: serviceID,
			},
		},
	}
	if len(tags) > 0 {
		proxyService.Tags = tags
	}

	// A user can enable/disable tproxy for an entire namespace.
	var ns corev1.Namespace
	err = r.Client.Get(r.Context, types.NamespacedName{Name: pod.Namespace, Namespace: ""}, &ns)
	if err != nil {
		return nil, nil, err
	}

	tproxyEnabled, err := transparentProxyEnabled(ns, pod, r.EnableTransparentProxy)
	if err != nil {
		return nil, nil, err
	}

	if tproxyEnabled {
		var k8sService corev1.Service

		err := r.Client.Get(r.Context, types.NamespacedName{Name: serviceEndpoints.Name, Namespace: serviceEndpoints.Namespace}, &k8sService)
		if err != nil {
			return nil, nil, err
		}

		// Check if the service has a valid IP.
		parsedIP := net.ParseIP(k8sService.Spec.ClusterIP)
		if parsedIP != nil {
			taggedAddresses := make(map[string]api.ServiceAddress)

			// When a service has multiple ports, we need to choose the port that is registered with Consul
			// and only set that port as the tagged address because Consul currently does not support multiple ports
			// on a single service.
			var k8sServicePort int32
			for _, sp := range k8sService.Spec.Ports {
				targetPortValue, err := portValueFromIntOrString(pod, sp.TargetPort)
				if err != nil {
					return nil, nil, err
				}

				// If the targetPortValue is not zero and is the consulServicePort, then this is the service port we'll use as the tagged address.
				if targetPortValue != 0 && targetPortValue == consulServicePort {
					k8sServicePort = sp.Port
					break
				} else {
					// If targetPort is not specified, then the service port is used as the target port,
					// and we can compare the service port with the Consul service port.
					if sp.Port == int32(consulServicePort) {
						k8sServicePort = sp.Port
						break
					}
				}
			}

			taggedAddresses[clusterIPTaggedAddressName] = api.ServiceAddress{
				Address: k8sService.Spec.ClusterIP,
				Port:    int(k8sServicePort),
			}

			service.TaggedAddresses = taggedAddresses
			proxyService.TaggedAddresses = taggedAddresses

			proxyService.Proxy.Mode = api.ProxyModeTransparent
		} else {
			r.Log.Info("skipping syncing service cluster IP to Consul", "name", k8sService.Name, "ns", k8sService.Namespace, "ip", k8sService.Spec.ClusterIP)
		}

		// Expose k8s probes as Envoy listeners if needed.
		overwriteProbes, err := shouldOverwriteProbes(pod, r.TProxyOverwriteProbes)
		if err != nil {
			return nil, nil, err
		}
		if overwriteProbes {
			var originalPod corev1.Pod
			err := json.Unmarshal([]byte(pod.Annotations[annotationOriginalPod]), &originalPod)
			if err != nil {
				return nil, nil, err
			}

			for _, mutatedContainer := range pod.Spec.Containers {
				for _, originalContainer := range originalPod.Spec.Containers {
					if originalContainer.Name == mutatedContainer.Name {
						if mutatedContainer.LivenessProbe != nil && mutatedContainer.LivenessProbe.HTTPGet != nil {
							originalLivenessPort, err := portValueFromIntOrString(originalPod, originalContainer.LivenessProbe.HTTPGet.Port)
							if err != nil {
								return nil, nil, err
							}
							proxyConfig.Expose.Paths = append(proxyConfig.Expose.Paths, api.ExposePath{
								ListenerPort:  mutatedContainer.LivenessProbe.HTTPGet.Port.IntValue(),
								LocalPathPort: originalLivenessPort,
								Path:          mutatedContainer.LivenessProbe.HTTPGet.Path,
							})
						}
						if mutatedContainer.ReadinessProbe != nil && mutatedContainer.ReadinessProbe.HTTPGet != nil {
							originalReadinessPort, err := portValueFromIntOrString(originalPod, originalContainer.ReadinessProbe.HTTPGet.Port)
							if err != nil {
								return nil, nil, err
							}
							proxyConfig.Expose.Paths = append(proxyConfig.Expose.Paths, api.ExposePath{
								ListenerPort:  mutatedContainer.ReadinessProbe.HTTPGet.Port.IntValue(),
								LocalPathPort: originalReadinessPort,
								Path:          mutatedContainer.ReadinessProbe.HTTPGet.Path,
							})
						}
						if mutatedContainer.StartupProbe != nil && mutatedContainer.StartupProbe.HTTPGet != nil {
							originalStartupPort, err := portValueFromIntOrString(originalPod, originalContainer.StartupProbe.HTTPGet.Port)
							if err != nil {
								return nil, nil, err
							}
							proxyConfig.Expose.Paths = append(proxyConfig.Expose.Paths, api.ExposePath{
								ListenerPort:  mutatedContainer.StartupProbe.HTTPGet.Port.IntValue(),
								LocalPathPort: originalStartupPort,
								Path:          mutatedContainer.StartupProbe.HTTPGet.Path,
							})
						}
					}
				}
			}
		}
	}

	return service, proxyService, nil
}

// portValueFromIntOrString returns the integer port value from the port that can be
// a named port, an integer string (e.g. "80"), or an integer. If the port is a named port,
// this function will attempt to find the value from the containers of the pod.
func portValueFromIntOrString(pod corev1.Pod, port intstr.IntOrString) (int, error) {
	if port.Type == intstr.Int {
		return port.IntValue(), nil
	}

	// Otherwise, find named port or try to parse the string as an int.
	portVal, err := portValue(pod, port.StrVal)
	if err != nil {
		return 0, err
	}
	return int(portVal), nil
}

// getConsulHealthCheckID deterministically generates a health check ID that will be unique to the Agent
// where the health check is registered and deregistered.
func getConsulHealthCheckID(pod corev1.Pod, serviceID string) string {
	return fmt.Sprintf("%s/%s/kubernetes-health-check", pod.Namespace, serviceID)
}

// getHealthCheckStatusReason takes an Consul's health check status (either passing or critical)
// as well as pod name and namespace and returns the reason message.
func getHealthCheckStatusReason(healthCheckStatus, podName, podNamespace string) string {
	if healthCheckStatus == api.HealthPassing {
		return kubernetesSuccessReasonMsg
	}

	return fmt.Sprintf("Pod \"%s/%s\" is not ready", podNamespace, podName)
}

// deregisterServiceOnAgents queries all agents for service instances that have the metadata
// "k8s-service-name"=k8sSvcName and "k8s-namespace"=k8sSvcNamespace. The k8s service name may or may not match the
// consul service name, but the k8s service name will always match the metadata on the Consul service
// "k8s-service-name". So, we query Consul services by "k8s-service-name" metadata, which is only exposed on the agent
// API. Therefore, we need to query all agents who have services matching that metadata, and deregister each service
// instance. When querying by the k8s service name and namespace, the request will return service instances and
// associated proxy service instances.
// The argument endpointsAddressesMap decides whether to deregister *all* service instances or selectively deregister
// them only if they are not in endpointsAddressesMap. If the map is nil, it will deregister all instances. If the map
// has addresses, it will only deregister instances not in the map.
func (r *EndpointsController) deregisterServiceOnAgents(ctx context.Context, k8sSvc serviceName, toDeregister map[podID]podStatus) error {
	if len(toDeregister) == 0 {
		return nil
	}

	// Group pods by hostIP so that we make fewer calls to agents.
	groupedDeletes := make(map[hostIP]map[podID]podStatus)
	for id, pod := range toDeregister {
		group := groupedDeletes[pod.hostIP]
		if group == nil {
			group = make(map[podID]podStatus)
		}
		group[id] = pod
		groupedDeletes[pod.hostIP] = group
	}

	consulNS := r.consulNamespace(k8sSvc.ns)

	// Control the number of concurrent calls that can be made to agents
	concurrentCalls := getConcurrentCalls()
	if concurrentCalls > len(groupedDeletes) {
		concurrentCalls = len(groupedDeletes)
	}

	// Get the tokens so that we can delete them after deregistrations.
	var err error
	var tokens []*api.ACLTokenListEntry
	if r.AuthMethod != "" {
		tokens, _, err = r.ConsulClient.ACL().TokenList(nil)
		if err != nil {
			return fmt.Errorf("failed to get a list of tokens from Consul: %s", err)
		}
	}

	// Wait for all items to complete
	r.Log.Info("Queuing up deregisterServiceOnAgents", "tasks", len(groupedDeletes), "goroutines", concurrentCalls)
	var waiter sync.WaitGroup
	waiter.Add(concurrentCalls)

	// Queue the agent calls
	var hadError atomic.Bool
	podChan := make(chan map[podID]podStatus)
	for i := 0; i < concurrentCalls; i++ {
		go func() {
			defer waiter.Done()
			for pods := range podChan {
				if err := deleteServiceInstances(r, pods, k8sSvc, consulNS, tokens); err != nil {
					r.Log.Error(err, "error while contacting agent for deregistration")
					hadError.Store(true)
				}
			}
		}()
	}
	for _, pods := range groupedDeletes {
		if len(pods) > 0 {
			podChan <- pods
		}
	}
	close(podChan)

	// Wait for all responses
	waiter.Wait()
	r.Log.Info("Done with all tasks for deregisterServiceOnAgents", "tasks", len(groupedDeletes))
	if hadError.Load() {
		return fmt.Errorf("some deregisterServiceOnAgents tasks were not successful")
	}
	return nil
}

// deleteServiceInstances deletes all service instances for a single hostIP. It is expected that the pods are correctly
// grouped prior to this function call.
func deleteServiceInstances(r *EndpointsController, deletePods map[podID]podStatus, k8sSvc serviceName, consulNS string, tokens []*api.ACLTokenListEntry) error {
	if len(deletePods) == 0 {
		return nil
	}
	// All pods will share the same hostIP, so just grab the first one.
	var hostIP hostIP
	for _, pod := range deletePods {
		hostIP = pod.hostIP
	}
	client, err := r.getAgentClient(hostIP, consulNS)
	if err != nil {
		r.Log.Error(err, "failed to get a Consul client", "address", hostIP)
		return err
	}

	// Fetch all services on the agent.
	svcs, err := serviceInstancesForK8SServiceNameAndNamespace(k8sSvc.name, k8sSvc.ns, client)
	if err != nil {
		r.Log.Error(err, "failed to get service instances", "name", k8sSvc.name, "ns", k8sSvc.ns, "hostIP", hostIP)
		return err
	}
	for svcID, svc := range svcs {
		pod, ok := deletePods[podID{name: svc.Meta[MetaKeyPodName], ns: k8sSvc.ns}]
		// Only delete services that we explicitly put in our delete listing.
		if !ok {
			continue
		}

		r.Log.Info("deregistering service from consul", "svc", svcID)
		if err = client.Agent().ServiceDeregister(svcID); err != nil {
			r.Log.Error(err, "failed to deregister service instance", "id", svcID)
			return err
		}
		r.stateMutex.Lock()
		r.untrackPod(pod)
		r.stateMutex.Unlock()

		// TODO: This is leaky. It was this way in the old controller for some reason.
		if r.AuthMethod != "" {
			r.Log.Info("reconciling ACL tokens for service", "svc", svc.Service)
			err = r.deleteACLTokensForServiceInstance(svc.Service, pod.serviceName.ns, svc.Meta[MetaKeyPodName], tokens)
			if err != nil {
				r.Log.Error(err, "failed to reconcile ACL tokens for service", "svc", svc.Service)
				return err
			}
		}
	}
	return nil
}

func (r *EndpointsController) populateCache(ctx context.Context, req ctrl.Request, newAgents map[hostIP]corev1.Pod) error {
	if r.agentCache == nil {
		r.agentCache = map[hostIP]agentStatus{}
	}
	if r.podCache == nil {
		r.podCache = map[serviceName]map[podID]podStatus{}
	}
	// Stop if there's no new data to fetch.
	if len(newAgents) == 0 {
		return nil
	}

	concurrentCalls := getConcurrentCalls()
	if concurrentCalls > len(newAgents) {
		concurrentCalls = len(newAgents)
	}

	r.Log.Info("Queuing up populateCache", "tasks", len(newAgents), "goroutines", concurrentCalls)
	// Wait for all goroutines to complete before returning.
	var waiter sync.WaitGroup
	waiter.Add(concurrentCalls)

	// Queue the agent calls.
	var hadError atomic.Bool
	agentChan := make(chan corev1.Pod)
	for i := 0; i < concurrentCalls; i++ {
		go func() {
			defer waiter.Done()
			for agent := range agentChan {
				consulNS := r.consulNamespace(req.Namespace)
				consulClient, err := r.getAgentClient(hostIP(agent.Status.HostIP), consulNS)
				if err != nil {
					r.Log.Error(err, "error while getting Consul client for cache population", "agentIP", agent.Status.HostIP)
					continue
				}
				pods, err := r.getAgentDataForCache(consulClient, agent, consulNS)
				r.stateMutex.Lock()
				{
					r.agentCache[hostIP(agent.Status.HostIP)] = agentStatus{
						cachePopulated: err == nil,
						creationTime:   getAgentCreationTime(agent),
						client:         consulClient,
					}
					if err != nil {
						r.Log.Error(err, "error while contacting agent for cache population", "agentIP", agent.Status.HostIP)
						hadError.Store(true)
					} else {
						for _, i := range pods {
							r.trackPod(i)
						}
					}
				}
				r.stateMutex.Unlock()
			}
		}()
	}

	for _, agent := range newAgents {
		agentChan <- agent
	}
	close(agentChan)

	// Wait for all responses
	waiter.Wait()
	r.Log.Info("Done with all tasks for populateCache", "tasks", len(newAgents))
	if hadError.Load() {
		return fmt.Errorf("some populateCache tasks were not successful")
	}
	return nil
}

// deleteACLTokensForServiceInstance finds the ACL tokens that belongs to the service instance and deletes it from Consul.
// It will only check for ACL tokens that have been created with the auth method this controller
// has been configured with and will only delete tokens for the provided podName.
func (r *EndpointsController) deleteACLTokensForServiceInstance(serviceName, k8sNS, podName string, tokens []*api.ACLTokenListEntry) error {
	// Skip if podName is empty.
	if podName == "" {
		return nil
	}
	for _, token := range tokens {
		// Only delete tokens that:
		// * have been created with the auth method configured for this endpoints controller
		// * have a single service identity whose service name is the same as 'serviceName'
		if token != nil &&
			token.AuthMethod == r.AuthMethod &&
			len(token.ServiceIdentities) == 1 &&
			token.ServiceIdentities[0].ServiceName == serviceName {
			tokenMeta, err := getTokenMetaFromDescription(token.Description)
			if err != nil {
				return fmt.Errorf("failed to parse token metadata: %s", err)
			}

			tokenPodName := strings.TrimPrefix(tokenMeta[TokenMetaPodNameKey], k8sNS+"/")

			// If we can't find token's pod, delete it.
			if tokenPodName == podName {
				r.Log.Info("deleting ACL token for pod", "name", podName)
				_, err = r.ConsulClient.ACL().TokenDelete(token.AccessorID, nil)
				if err != nil {
					return fmt.Errorf("failed to delete token from Consul: %s", err)
				}
			} else if err != nil {
				return err
			}
		}
	}

	return nil
}

var tokenRE = regexp.MustCompile(`.*({.+})`)

// getTokenMetaFromDescription parses JSON metadata from token's description.
func getTokenMetaFromDescription(description string) (map[string]string, error) {
	matches := tokenRE.FindStringSubmatch(description)
	if len(matches) != 2 {
		return nil, fmt.Errorf("failed to extract token metadata from description: %s", description)
	}
	tokenMetaJSON := matches[1]

	var tokenMeta map[string]string
	err := json.Unmarshal([]byte(tokenMetaJSON), &tokenMeta)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal token metadata '%s': %s", tokenMetaJSON, err)
	}

	return tokenMeta, nil
}

// serviceInstancesForK8SServiceNameAndNamespace calls Consul's ServicesWithFilter to get the list
// of services instances that have the provided k8sServiceName and k8sServiceNamespace in their metadata.
func serviceInstancesForK8SServiceNameAndNamespace(k8sServiceName, k8sServiceNamespace string, client *api.Client) (map[string]*api.AgentService, error) {
	return client.Agent().ServicesWithFilter(
		fmt.Sprintf(`Meta[%q] == %q and Meta[%q] == %q and Meta[%q] == %q`,
			MetaKeyKubeServiceName, k8sServiceName,
			MetaKeyKubeNS, k8sServiceNamespace,
			MetaKeyManagedBy, managedByValue,
		))
}

// processUpstreams reads the list of upstreams from the Pod annotation and converts them into a list of api.Upstream
// objects.
func (r *EndpointsController) processUpstreams(pod corev1.Pod) ([]api.Upstream, error) {
	var upstreams []api.Upstream
	if raw, ok := pod.Annotations[annotationUpstreams]; ok && raw != "" {
		for _, raw := range strings.Split(raw, ",") {
			parts := strings.SplitN(raw, ":", 3)

			var datacenter, serviceName, preparedQuery, namespace, partition string
			var port int32
			if strings.TrimSpace(parts[0]) == "prepared_query" {
				port, _ = portValue(pod, strings.TrimSpace(parts[2]))
				preparedQuery = strings.TrimSpace(parts[1])
			} else {
				port, _ = portValue(pod, strings.TrimSpace(parts[1]))

				// If Consul Namespaces or Admin Partitions are enabled, attempt to parse the
				// upstream for a namespace.
				if r.EnableConsulNamespaces || r.EnableConsulPartitions {
					pieces := strings.SplitN(parts[0], ".", 3)
					switch len(pieces) {
					case 3:
						partition = strings.TrimSpace(pieces[2])
						fallthrough
					case 2:
						namespace = strings.TrimSpace(pieces[1])
						fallthrough
					default:
						serviceName = strings.TrimSpace(pieces[0])
					}
				} else {
					serviceName = strings.TrimSpace(parts[0])
				}

				// parse the optional datacenter
				if len(parts) > 2 {
					datacenter = strings.TrimSpace(parts[2])

					// Check if there's a proxy defaults config with mesh gateway
					// mode set to local or remote. This helps users from
					// accidentally forgetting to set a mesh gateway mode
					// and then being confused as to why their traffic isn't
					// routing.
					// entry, _, err := r.ConsulClient.ConfigEntries().Get(api.ProxyDefaults, api.ProxyConfigGlobal, nil)
					// if err != nil && strings.Contains(err.Error(), "Unexpected response code: 404") {
					// 	return []api.Upstream{}, fmt.Errorf("upstream %q is invalid: there is no ProxyDefaults config to set mesh gateway mode", raw)
					// } else if err == nil {
					// 	mode := entry.(*api.ProxyConfigEntry).MeshGateway.Mode
					// 	if mode != api.MeshGatewayModeLocal && mode != api.MeshGatewayModeRemote {
					// 		return []api.Upstream{}, fmt.Errorf("upstream %q is invalid: ProxyDefaults mesh gateway mode is neither %q nor %q", raw, api.MeshGatewayModeLocal, api.MeshGatewayModeRemote)
					// 	}
					// }
					// NOTE: If we can't reach Consul we don't error out because
					// that would fail the pod scheduling and this is a nice-to-have
					// check, not something that should block during a Consul hiccup.
				}
			}

			if port > 0 {
				upstream := api.Upstream{
					DestinationType:      api.UpstreamDestTypeService,
					DestinationPartition: partition,
					DestinationNamespace: namespace,
					DestinationName:      serviceName,
					Datacenter:           datacenter,
					LocalBindPort:        int(port),
				}

				if preparedQuery != "" {
					upstream.DestinationType = api.UpstreamDestTypePreparedQuery
					upstream.DestinationName = preparedQuery
				}

				upstreams = append(upstreams, upstream)
			}
		}
	}

	return upstreams, nil
}

// remoteConsulClient returns an *api.Client that points at the consul agent local to the pod for a provided namespace.
func (r *EndpointsController) remoteConsulClient(ip string, namespace string) (*api.Client, error) {
	newAddr := fmt.Sprintf("%s://%s:%s", r.ConsulScheme, ip, r.ConsulPort)
	localConfig := *r.ConsulClientCfg
	localConfig.Address = newAddr
	localConfig.Namespace = namespace
	return consul.NewClient(&localConfig)
}

// shouldIgnore ignores namespaces where we don't connect-inject.
func shouldIgnore(namespace string, denySet, allowSet mapset.Set) bool {
	// Ignores system namespaces.
	if namespace == metav1.NamespaceSystem || namespace == metav1.NamespacePublic || namespace == "local-path-storage" {
		return true
	}

	// Ignores deny list.
	if denySet.Contains(namespace) {
		return true
	}

	// Ignores if not in allow list or allow list is not *.
	if !allowSet.Contains("*") && !allowSet.Contains(namespace) {
		return true
	}

	return false
}

// filterAgentPods receives meta and object information for Kubernetes resources that are being watched,
// which in this case are Pods. It only returns true if the Pod is a Consul Client Agent Pod. It reads the labels
// from the meta of the resource and uses the values of the "app" and "component" label to validate that
// the Pod is a Consul Client Agent.
func (r *EndpointsController) filterAgentPods(object client.Object) bool {
	podLabels := object.GetLabels()
	app, ok := podLabels["app"]
	if !ok {
		return false
	}
	component, ok := podLabels["component"]
	if !ok {
		return false
	}

	release, ok := podLabels["release"]
	if !ok {
		return false
	}

	if app == "consul" && component == "client" && release == r.ReleaseName {
		return true
	}
	return false
}

// requestsForRunningAgentPods creates a slice of requests for the endpoints controller.
// It enqueues a request for each endpoint that needs to be reconciled. It iterates through
// the list of endpoints and creates a request for those endpoints that have an address that
// are on the same node as the new Consul Agent pod. It receives a Pod Object which is a
// Consul Agent that has been filtered by filterAgentPods and only enqueues endpoints
// for client agent pods where the Ready condition is true.
func (r *EndpointsController) requestsForRunningAgentPods(object client.Object) []ctrl.Request {
	var consulClientPod corev1.Pod
	r.Log.Info("received update for Consul client pod", "name", object.GetName())
	err := r.Client.Get(r.Context, types.NamespacedName{Name: object.GetName(), Namespace: object.GetNamespace()}, &consulClientPod)
	if k8serrors.IsNotFound(err) {
		// Ignore if consulClientPod is not found.
		return []ctrl.Request{}
	}
	if err != nil {
		r.Log.Error(err, "failed to get Consul client pod", "name", consulClientPod.Name)
		return []ctrl.Request{}
	}
	// We can ignore the agent pod if it's not running, since
	// we can't reconcile and register/deregister services against that agent.
	if consulClientPod.Status.Phase != corev1.PodRunning {
		r.Log.Info("ignoring Consul client pod because it's not running", "name", consulClientPod.Name)
		return []ctrl.Request{}
	}
	// We can ignore the agent pod if it's not yet ready, since
	// we can't reconcile and register/deregister services against that agent.
	for _, cond := range consulClientPod.Status.Conditions {
		if cond.Type == corev1.PodReady && cond.Status != corev1.ConditionTrue {
			// Ignore if consulClientPod is not ready.
			r.Log.Info("ignoring Consul client pod because it's not ready", "name", consulClientPod.Name)
			return []ctrl.Request{}
		}
	}

	// Get the list of all endpoints.
	var endpointsList corev1.EndpointsList
	err = r.Client.List(r.Context, &endpointsList)
	if err != nil {
		r.Log.Error(err, "failed to list endpoints")
		return []ctrl.Request{}
	}

	// Enqueue requests for endpoints that are on the same node
	// as the client agent.
	var requests []reconcile.Request
	for _, ep := range endpointsList.Items {
		for _, subset := range ep.Subsets {
			allAddresses := subset.Addresses
			allAddresses = append(allAddresses, subset.NotReadyAddresses...)
			for _, address := range allAddresses {
				// Only add requests for the address that is on the same node as the consul client pod.
				if address.NodeName != nil && *address.NodeName == consulClientPod.Spec.NodeName {
					requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: ep.Name, Namespace: ep.Namespace}})
				}
			}
		}
	}
	return requests
}

// consulNamespace returns the Consul destination namespace for a provided Kubernetes namespace
// depending on Consul Namespaces being enabled and the value of namespace mirroring.
func (r *EndpointsController) consulNamespace(namespace string) string {
	return namespaces.ConsulNamespace(namespace, r.EnableConsulNamespaces, r.ConsulDestinationNamespace, r.EnableNSMirroring, r.NSMirroringPrefix)
}

func (r *EndpointsController) getAgentDataForCache(consulClient *api.Client, agent corev1.Pod, consulNS string) ([]podStatus, error) {
	svcs, err := consulClient.Agent().Services()
	if err != nil {
		return nil, err
	}

	instances := make([]podStatus, 0, len(svcs))
	for _, svc := range svcs {
		registration := svcRegistration{
			id:      svc.ID,
			proxy:   svc.Proxy,
			connect: svc.Connect,
		}
		svcRegHash, err := hashstructure.Hash(registration, hashstructure.FormatV2, nil)
		if err != nil {
			r.Log.Error(err, "failed to hash service registration", "name", svc.Service)
			return nil, err
		}
		instances = append(instances, podStatus{
			serviceName:         serviceName{ns: svc.Meta[MetaKeyKubeNS], name: svc.Meta[MetaKeyKubeServiceName]},
			podID:               podID{ns: svc.Meta[MetaKeyKubeNS], name: svc.Meta[MetaKeyPodName]},
			hostIP:              hostIP(agent.Status.HostIP),
			agentCreationTime:   getAgentCreationTime(agent),
			registrationSuccess: true,
			registrationHash:    svcRegHash,
			health:              "", // Leave this empty for now so that an update is forced.
		})
	}
	return instances, err
}

func (r *EndpointsController) trackPod(instance podStatus) {
	if r.podCache[instance.serviceName] == nil {
		r.podCache[instance.serviceName] = make(map[podID]podStatus)
	}
	r.podCache[instance.serviceName][instance.podID] = instance
}

func (r *EndpointsController) untrackPod(instance podStatus) {
	delete(r.podCache[instance.serviceName], instance.podID)
}

// Clean out records for old agents / nodes. If they disappeared, then there's nothing we can do, since
// each agent still syncs its own registrations / deregistrations to the consul servers.
// On leave, each agent should ideally be deregistering its own services anyway.
func (r *EndpointsController) removeStaleAgentCacheEntries(svcName serviceName, currentAgents corev1.PodList) {
	currentIPs := make(map[hostIP]bool)
	for _, agent := range currentAgents.Items {
		currentIPs[hostIP(agent.Status.HostIP)] = true
	}
	for oldIP := range r.agentCache {
		if currentIPs[oldIP] {
			continue
		}
		// Delete the old agent and corresponding pods from the cache.
		r.Log.Info("removing dead agent from cache", "hostIP", oldIP)
		delete(r.agentCache, oldIP)
		for podID, status := range r.podCache[svcName] {
			if status.hostIP == oldIP {
				r.Log.Info("removing stale pod from cache", "hostIP", oldIP, "pod", podID)
				delete(r.podCache[svcName], podID)
			}
		}
	}
}

func (r *EndpointsController) fetchAgents(ctx context.Context) (corev1.PodList, error) {
	agents := corev1.PodList{}
	listOptions := client.ListOptions{
		Namespace: r.ReleaseNamespace,
		LabelSelector: labels.SelectorFromSet(map[string]string{
			"component": "client",
			"app":       "consul",
			"release":   r.ReleaseName,
		}),
	}
	if err := r.Client.List(ctx, &agents, &listOptions); err != nil {
		r.Log.Error(err, "failed to get Consul client agent pods")
		return corev1.PodList{}, err
	}
	return agents, nil
}

func (r *EndpointsController) getAgentClient(agentHostIP hostIP, consulNS string) (*api.Client, error) {
	r.stateMutex.Lock()
	defer r.stateMutex.Unlock()

	if agentHostIP == "" {
		return nil, fmt.Errorf("empty host ip given when creating a client")
	}
	// Return the cached client if we already have one.
	agent, ok := r.agentCache[agentHostIP]
	if ok && agent.client != nil {
		return agent.client, nil
	}
	// Otherwise, create one and cache it.
	r.Log.Info("creating new client for agent", "hostIP", agentHostIP)
	consulClient, err := r.remoteConsulClient(string(agentHostIP), consulNS)
	if err != nil {
		return nil, err
	}
	agent.client = consulClient
	r.agentCache[agentHostIP] = agent
	return consulClient, nil
}

// hasBeenInjected checks the value of the status annotation and returns true if the Pod has been injected.
func hasBeenInjected(pod corev1.Pod) bool {
	if anno, ok := pod.Annotations[keyInjectStatus]; ok {
		if anno == injected {
			return true
		}
	}
	return false
}

func getAgentCreationTime(agent corev1.Pod) time.Time {
	var creationTime time.Time
	for _, container := range agent.Status.ContainerStatuses {
		if container.Name == "consul" && container.State.Running != nil {
			creationTime = container.State.Running.StartedAt.Time
		}
	}
	return creationTime
}

func getConcurrentCalls() int {
	var concurrentCalls = 30
	if callsConf := os.Getenv("CONSUL_CLIENT_CONCURRENT_CALLS"); callsConf != "" {
		if i, err := strconv.Atoi(callsConf); err == nil && i > 0 {
			concurrentCalls = i
		}
	}
	return concurrentCalls
}
