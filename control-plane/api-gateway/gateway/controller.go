package gateway

import (
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The following RBAC rules are for leader election
//+kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;update;list;watch;create;patch;delete
//+kubebuilder:rbac:groups=core,resources=configmaps/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=core,resources=events,verbs=create;patch
//+kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=create;get;list;update
//+kubebuilder:rbac:groups=api-gateway.consul.hashicorp.com,resources=meshservices,verbs=get;list;watch

// StateController is responsible for watching the resources that make up the API Gateway spec.
// When any of them change, it will compute the entire state of the API Gateway and compare it
// to a snapshot of the current state. If there are any differences, it will update the API Gateway
// and relevant resources in Consul to match the desired state.
type StateController struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

func NewStateController() *StateController {
	return &StateController{}
}

func (s *StateController) Reconcile() error {
	/*
		Compute the entire state of things into a snapshot
		Compare the snapshot to the current state
	*/
	return nil
}
