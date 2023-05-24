// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package binding

import (
	"github.com/hashicorp/consul-k8s/control-plane/api/v1alpha1"
	"github.com/hashicorp/consul/api"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// KubernetesSnapshot contains all the operations
// required in Kubernetes to complete reconciliation.
type KubernetesSnapshot struct {
	// Updates is the list of objects that need to have
	// aspects of their metadata or spec updated in Kubernetes
	// (i.e. for finalizers or annotations)
	Updates []client.Object
	// StatusUpdates is the list of objects that need
	// to have their statuses updated in Kubernetes
	StatusUpdates []client.Object
}

// ConsulSnapshot contains all the operations required
// in Consul to complete reconciliation.
type ConsulSnapshot struct {
	// Updates is the list of ConfigEntry objects that should
	// either be updated or created in Consul
	Updates []api.ConfigEntry
	// Deletions is a list of references that ought to be
	// deleted in Consul
	Deletions []api.ResourceReference
	// Registrations is a list of Consul services to make sure
	// are registered in Consul
	Registrations []api.CatalogRegistration
	// Deregistrations is a list of Consul services to make sure
	// are no longer registered in Consul
	Deregistrations []api.CatalogDeregistration
}

// Snapshot contains all Kubernetes and Consul operations
// needed to complete reconciliation.
type Snapshot struct {
	// Kubernetes holds the snapshot of required Kubernetes operations
	Kubernetes KubernetesSnapshot
	// Consul holds the snapshot of required Consul operations
	Consul ConsulSnapshot
	// GatewayClassConfig is the configuration to use for determining
	// a Gateway deployment, if it is not set, a deployment should be
	// deleted instead of updated
	GatewayClassConfig *v1alpha1.GatewayClassConfig
	// TODO: melisa describe this
	UpsertGatewayDeployment bool
}