// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package binding

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gwv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

var (
	// Each of the below are specified in the Gateway spec under RouteConditionReason
	// the general usage is that each error is specified as errRoute* where * corresponds
	// to the RouteConditionReason given in the spec. If a reason is overloaded and can
	// be used with two different types of things (i.e. something is not found or it's not supported)
	// then we distinguish those two usages with errRoute*_Usage.
	errRouteNotAllowedByListeners_Namespace = errors.New("listener does not allow binding routes from the given namespace")
	errRouteNotAllowedByListeners_Protocol  = errors.New("listener does not support route protocol")
	errRouteNoMatchingListenerHostname      = errors.New("listener cannot bind route with a non-aligned hostname")
	errRouteInvalidKind                     = errors.New("invalid backend kind")
	errRouteBackendNotFound                 = errors.New("backend not found")
	errRouteRefNotPermitted                 = errors.New("reference not permitted due to lack of ReferenceGrant")
)

// routeValidationResult holds the result of validating a route globally, in other
// words, for a particular backend reference without consideration to its particular
// gateway. Unfortunately, due to the fact that the spec requires a route status be
// associated with a parent reference, what it means is that anything that is global
// in nature, like this status will need to be duplicated for every parent reference
// on a given route status.
type routeValidationResult struct {
	namespace string
	backend   gwv1beta1.BackendRef
	err       error
}

// Type is used for error printing a backend reference type that we don't support on
// a validation error.
func (v routeValidationResult) Type() string {
	return (&metav1.GroupKind{
		Group: valueOr(v.backend.Group, ""),
		Kind:  valueOr(v.backend.Kind, "Service"),
	}).String()
}

// String is the namespace/name of the reference that has an error.
func (v routeValidationResult) String() string {
	return (types.NamespacedName{Namespace: v.namespace, Name: string(v.backend.Name)}).String()
}

// routeValidationResults contains a list of validation results for the backend references
// on a route.
type routeValidationResults []routeValidationResult

// Condition returns the ResolvedRefs condition that gets duplicated across every relevant
// parent on a route's status.
func (e routeValidationResults) Condition() metav1.Condition {
	// we only use the first error due to the way the spec is structured
	// where you can only have a single condition
	for _, v := range e {
		err := v.err
		if err != nil {
			switch err {
			case errRouteInvalidKind:
				return metav1.Condition{
					Type:    "ResolvedRefs",
					Status:  metav1.ConditionFalse,
					Reason:  "InvalidKind",
					Message: fmt.Sprintf("%s [%s]: %s", v.String(), v.Type(), err.Error()),
				}
			case errRouteBackendNotFound:
				return metav1.Condition{
					Type:    "ResolvedRefs",
					Status:  metav1.ConditionFalse,
					Reason:  "BackendNotFound",
					Message: fmt.Sprintf("%s: %s", v.String(), err.Error()),
				}
			case errRouteRefNotPermitted:
				return metav1.Condition{
					Type:    "ResolvedRefs",
					Status:  metav1.ConditionFalse,
					Reason:  "RefNotPermitted",
					Message: fmt.Sprintf("%s: %s", v.String(), err.Error()),
				}
			default:
				// this should never happen
				return metav1.Condition{
					Type:    "ResolvedRefs",
					Status:  metav1.ConditionFalse,
					Reason:  "UnhandledValidationError",
					Message: err.Error(),
				}
			}
		}
	}
	return metav1.Condition{
		Type:    "ResolvedRefs",
		Status:  metav1.ConditionTrue,
		Reason:  "ResolvedRefs",
		Message: "resolved backend references",
	}
}

// bindResult holds the result of attempting to bind a route to a particular gateway listener
// an error value here means that the route did not bind successfully, no error means that
// the route should be considered bound.
type bindResult struct {
	section gwv1beta1.SectionName
	err     error
}

// bindResults holds the results of attempting to bind a route to a gateway, having a separate
// bindResult for each listener on the gateway.
type bindResults []bindResult

// Error constructs a human readable error for bindResults, containing any errors that a route
// had in binding to a gateway, note that this is only used if a route failed to bind to every
// listener it attempted to bind to.
func (b bindResults) Error() string {
	messages := []string{}
	for _, result := range b {
		if result.err != nil {
			messages = append(messages, fmt.Sprintf("%s: %s", result.section, result.err.Error()))
		}
	}

	sort.Strings(messages)
	return strings.Join(messages, "; ")
}

// DidBind returns whether a route successfully bound to any listener on a gateway.
func (b bindResults) DidBind() bool {
	for _, result := range b {
		if result.err == nil {
			return true
		}
	}
	return false
}

// Condition constructs an Accepted condition for a route that will be scoped
// to the particular parent reference it's using to attempt binding.
func (b bindResults) Condition() metav1.Condition {
	// if we bound to any listeners, say we're accepted
	if b.DidBind() {
		return metav1.Condition{
			Type:    "Accepted",
			Status:  metav1.ConditionTrue,
			Reason:  "Accepted",
			Message: "route accepted",
		}
	}

	// default to the most generic reason in the spec "NotAllowedByListeners"
	reason := "NotAllowedByListeners"

	// if we only have a single binding error, we can get more specific
	if len(b) == 1 {
		for _, result := range b {
			// if we have a hostname mismatch error, then use the more specific reason
			if result.err == errRouteNoMatchingListenerHostname {
				reason = "NoMatchingListenerHostname"
			}
		}
	}

	return metav1.Condition{
		Type:    "Accepted",
		Status:  metav1.ConditionFalse,
		Reason:  reason,
		Message: b.Error(),
	}
}

// parentBindResult associates a binding result with the given parent reference.
type parentBindResult struct {
	parent  gwv1beta1.ParentReference
	results bindResults
}

// parentBindResults contains the list of all results that occurred when this route
// attempted to bind to a gateway using its parent references.
type parentBindResults []parentBindResult

var (
	// Each of the below are specified in the Gateway spec under ListenerConditionReason
	// the general usage is that each error is specified as errListener* where * corresponds
	// to the ListenerConditionReason given in the spec. If a reason is overloaded and can
	// be used with two different types of things (i.e. something is not found or it's not supported)
	// then we distinguish those two usages with errListener*_Usage.
	errListenerUnsupportedProtocol                = errors.New("listener protocol is unsupported")
	errListenerPortUnavailable                    = errors.New("listener port is unavailable")
	errListenerHostnameConflict                   = errors.New("listener hostname conflicts with another listener")
	errListenerProtocolConflict                   = errors.New("listener protocol conflicts with another listener")
	errListenerInvalidCertificateRef_NotFound     = errors.New("certificate not found")
	errListenerInvalidCertificateRef_NotSupported = errors.New("certificate type is not supported")

	// Below is where any custom generic listener validation errors should go.
	// We map anything under here to a custom ListenerConditionReason of Invalid on
	// an Accepted status type.
	errListenerNoTLSPassthrough = errors.New("TLS passthrough is not supported")
)

// listenerValidationResult contains the result of internally validating a single listener
// as well as the result of validating it in relation to all its peers (via conflictedErr).
// an error set on any of its members corresponds to an error condition on the corresponding
// status type.
type listenerValidationResult struct {
	// status type: Accepted
	acceptedErr error
	// status type: Conflicted
	conflictedErr error
	// status type: ResolvedRefs
	refErr error
	// TODO: programmed
}

// acceptedCondition constructs the condition for the Accepted status type.
func (l listenerValidationResult) acceptedCondition(generation int64) metav1.Condition {
	now := metav1.Now()
	switch l.acceptedErr {
	case errListenerPortUnavailable:
		return metav1.Condition{
			Type:               "Accepted",
			Status:             metav1.ConditionFalse,
			Reason:             "PortUnavailable",
			ObservedGeneration: generation,
			Message:            l.acceptedErr.Error(),
			LastTransitionTime: now,
		}
	case errListenerUnsupportedProtocol:
		return metav1.Condition{
			Type:               "Accepted",
			Status:             metav1.ConditionFalse,
			Reason:             "UnsupportedProtocol",
			ObservedGeneration: generation,
			Message:            l.acceptedErr.Error(),
			LastTransitionTime: now,
		}
	case nil:
		return metav1.Condition{
			Type:               "Accepted",
			Status:             metav1.ConditionTrue,
			Reason:             "Accepted",
			ObservedGeneration: generation,
			Message:            "listener accepted",
			LastTransitionTime: now,
		}
	default:
		// falback to invalid
		return metav1.Condition{
			Type:               "Accepted",
			Status:             metav1.ConditionFalse,
			Reason:             "Invalid",
			ObservedGeneration: generation,
			Message:            l.acceptedErr.Error(),
			LastTransitionTime: now,
		}
	}
}

// conflictedCondition constructs the condition for the Conflicted status type.
func (l listenerValidationResult) conflictedCondition(generation int64) metav1.Condition {
	now := metav1.Now()

	switch l.conflictedErr {
	case errListenerProtocolConflict:
		return metav1.Condition{
			Type:               "Conflicted",
			Status:             metav1.ConditionTrue,
			Reason:             "ProtocolConflict",
			ObservedGeneration: generation,
			Message:            l.conflictedErr.Error(),
			LastTransitionTime: now,
		}
	case errListenerHostnameConflict:
		return metav1.Condition{
			Type:               "Conflicted",
			Status:             metav1.ConditionTrue,
			Reason:             "HostnameConflict",
			ObservedGeneration: generation,
			Message:            l.conflictedErr.Error(),
			LastTransitionTime: now,
		}
	default:
		return metav1.Condition{
			Type:               "Conflicted",
			Status:             metav1.ConditionFalse,
			Reason:             "NoConflicts",
			ObservedGeneration: generation,
			Message:            "listener has no conflicts",
			LastTransitionTime: now,
		}
	}
}

// acceptedCondition constructs the condition for the ResolvedRefs status type.
func (l listenerValidationResult) resolvedRefsCondition(generation int64) metav1.Condition {
	now := metav1.Now()

	switch l.refErr {
	case errListenerInvalidCertificateRef_NotFound:
		return metav1.Condition{
			Type:               "ResolvedRefs",
			Status:             metav1.ConditionFalse,
			Reason:             "InvalidCertificateRef",
			ObservedGeneration: generation,
			Message:            l.refErr.Error(),
			LastTransitionTime: now,
		}
	case errListenerInvalidCertificateRef_NotSupported:
		return metav1.Condition{
			Type:               "ResolvedRefs",
			Status:             metav1.ConditionFalse,
			Reason:             "InvalidCertificateRef",
			ObservedGeneration: generation,
			Message:            l.refErr.Error(),
			LastTransitionTime: now,
		}
	default:
		return metav1.Condition{
			Type:               "ResolvedRefs",
			Status:             metav1.ConditionTrue,
			Reason:             "ResolvedRefs",
			ObservedGeneration: generation,
			Message:            "resolved certificate references",
			LastTransitionTime: now,
		}
	}
}

// Conditions constructs the entire set of conditions for a given gateway listener.
func (l listenerValidationResult) Conditions(generation int64) []metav1.Condition {
	return []metav1.Condition{
		l.acceptedCondition(generation),
		l.conflictedCondition(generation),
		l.resolvedRefsCondition(generation),
	}
}

// listenerValidationResults holds all of the results for a gateway's listeners
// the index of each result needs to correspond exactly to the index of the listener
// on the gateway spec for which it is describing.
type listenerValidationResults []listenerValidationResult

// Invalid returns whether or not there is any listener that is not "Accepted"
// this is used in constructing a gateway's status where the Accepted status
// at the top-level can have a GatewayConditionReason of ListenersNotValid.
func (l listenerValidationResults) Invalid() bool {
	for _, r := range l {
		if r.acceptedErr != nil {
			return true
		}
	}
	return false
}

// Conditions returns the listener conditions at a given index.
func (l listenerValidationResults) Conditions(generation int64, index int) []metav1.Condition {
	result := l[index]
	return result.Conditions(generation)
}

var (
	// Each of the below are specified in the Gateway spec under GatewayConditionReason
	// the general usage is that each error is specified as errGateway* where * corresponds
	// to the GatewayConditionReason given in the spec.
	errGatewayUnsupportedAddress = errors.New("gateway does not support specifying addresses")
	errGatewayListenersNotValid  = errors.New("one or more listeners are invalid")
)

// gatewayValidationResult contains the result of internally validating a gateway.
// An error set on any of its members corresponds to an error condition on the corresponding
// status type.
type gatewayValidationResult struct {
	acceptedErr error
	// TODO: programmed
}

// acceptedCondition returns a condition for the Accepted status type. It takes a boolean argument
// for whether or not any of the gateway's listeners are invalid, if they are, it overrides whatever
// Reason is set as an error on the result and instead uses the ListenersNotValid reason.
func (l gatewayValidationResult) acceptedCondition(generation int64, listenersInvalid bool) metav1.Condition {
	now := metav1.Now()

	if l.acceptedErr == nil {
		if listenersInvalid {
			return metav1.Condition{
				Type: "Accepted",
				// should one invalid listener cause the entire gateway to become invalid?
				Status:             metav1.ConditionFalse,
				Reason:             "ListenersNotValid",
				ObservedGeneration: generation,
				Message:            errGatewayListenersNotValid.Error(),
				LastTransitionTime: now,
			}
		}

		return metav1.Condition{
			Type:               "Accepted",
			Status:             metav1.ConditionTrue,
			Reason:             "Accepted",
			ObservedGeneration: generation,
			Message:            "gateway accepted",
			LastTransitionTime: now,
		}
	}

	if l.acceptedErr == errGatewayUnsupportedAddress {
		return metav1.Condition{
			Type:               "Accepted",
			Status:             metav1.ConditionFalse,
			Reason:             "UnsupportedAddress",
			ObservedGeneration: generation,
			Message:            l.acceptedErr.Error(),
			LastTransitionTime: now,
		}
	}

	// fallback to Invalid reason
	return metav1.Condition{
		Type:               "Accepted",
		Status:             metav1.ConditionFalse,
		Reason:             "Invalid",
		ObservedGeneration: generation,
		Message:            l.acceptedErr.Error(),
		LastTransitionTime: now,
	}
}

// Conditions constructs the gateway conditions given whether its listeners are valid.
func (l gatewayValidationResult) Conditions(generation int64, listenersInvalid bool) []metav1.Condition {
	return []metav1.Condition{
		l.acceptedCondition(generation, listenersInvalid),
	}
}
