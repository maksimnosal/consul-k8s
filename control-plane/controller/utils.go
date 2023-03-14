package controller

import (
	"fmt"

	"github.com/hashicorp/consul-k8s/control-plane/cache"
	"github.com/hashicorp/consul/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwapiv1b1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

const (
	metaKeyKubeNS   = "k8s-namespace"
	metaKeyKubeName = "k8s-name"
)

func nilOrEqual[T ~string](v *T, check string) bool {
	return v == nil || string(*v) == check
}

func derefOr[T any](v *T, val T) T {
	if v == nil {
		return val
	}
	return *v
}

func pointerTo[T any](v T) *T {
	return &v
}

func derefStringOr[T ~string, U ~string](v *T, val U) string {
	if v == nil {
		return string(val)
	}
	return string(*v)
}

func indexedNamespacedNameWithDefault[T ~string, U ~string, V ~string](t T, u *U, v V) types.NamespacedName {
	return types.NamespacedName{
		Namespace: derefStringOr(u, v),
		Name:      string(t),
	}
}

func stringArray[T fmt.Stringer](t []T) []string {
	strings := make([]string, 0, len(t))
	for i, v := range t {
		strings[i] = v.String()
	}
	return strings
}

func parentRefsToIndexed(group, kind, namespace string, refs []gwapiv1b1.ParentReference) []string {
	return stringArray(parentRefs(group, kind, namespace, refs))
}

func parentRefs(group, kind, namespace string, refs []gwapiv1b1.ParentReference) []types.NamespacedName {
	indexed := []types.NamespacedName{}
	for _, parent := range refs {
		if nilOrEqual(parent.Group, group) && nilOrEqual(parent.Kind, kind) {
			indexed = append(indexed, indexedNamespacedNameWithDefault(parent.Name, parent.Namespace, namespace))
		}
	}
	return indexed
}

func objectsToRequests[T metav1.Object](objects []T) []reconcile.Request {
	var requests []reconcile.Request
	for _, object := range objects {
		requests = append(requests, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: object.GetNamespace(),
				Name:      object.GetName(),
			},
		})
	}
	return requests
}

func objectsToMeta[T metav1.Object](objects []T) []types.NamespacedName {
	var meta []types.NamespacedName
	for _, object := range objects {
		meta = append(meta, types.NamespacedName{
			Namespace: object.GetNamespace(),
			Name:      object.GetName(),
		})
	}
	return meta
}

func metaToK8sMeta(config api.ConfigEntry) (types.NamespacedName, bool) {
	meta := config.GetMeta()
	namespace, ok := meta[metaKeyKubeNS]
	if !ok {
		return types.NamespacedName{}, false
	}
	name, ok := meta[metaKeyKubeName]
	if !ok {
		return types.NamespacedName{}, false
	}
	return types.NamespacedName{
		Namespace: namespace,
		Name:      name,
	}, true
}

func k8sToMeta(o client.Object) map[string]string {
	return map[string]string{
		metaKeyKubeNS:   o.GetNamespace(),
		metaKeyKubeName: o.GetName(),
	}
}

func consulRefsToMeta(cache *cache.Cache, refs []api.ResourceReference) []types.NamespacedName {
	metaSet := map[types.NamespacedName]struct{}{}
	for _, ref := range refs {
		if parent := cache.Get(ref); parent != nil {
			if k8sMeta, ok := metaToK8sMeta(parent); ok {
				metaSet[k8sMeta] = struct{}{}
			}
		}
	}

	meta := []types.NamespacedName{}
	for namespacedName := range metaSet {
		meta = append(meta, namespacedName)
	}
	return meta
}

func refsToRequests(objects []types.NamespacedName) []reconcile.Request {
	var requests []reconcile.Request
	for _, object := range objects {
		requests = append(requests, reconcile.Request{
			NamespacedName: object,
		})
	}
	return requests
}

func requestsToRefs(objects []reconcile.Request) []types.NamespacedName {
	var refs []types.NamespacedName
	for _, object := range objects {
		refs = append(refs, object.NamespacedName)
	}
	return refs
}

func pointersOf[T any](objects []T) []*T {
	pointers := make([]*T, 0, len(objects))
	for i, object := range objects {
		pointers[i] = pointerTo(object)
	}
	return pointers
}
