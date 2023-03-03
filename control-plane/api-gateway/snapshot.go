package apigateway

type Snapshot struct {
	Gateway    string
	HTTPRoutes []string
	TCPRoutes  []string
	Secrets    []string
}

func NewSnapshot() *Snapshot {
	return &Snapshot{}
}

func (s *Snapshot) WithGateway(gateway string) *Snapshot {
	s.Gateway = gateway
	return s
}

func (s *Snapshot) WithHTTPRoutes(routes []string) *Snapshot {
	s.HTTPRoutes = routes
	return s
}

func (s *Snapshot) WithTCPRoutes(routes []string) *Snapshot {
	s.TCPRoutes = routes
	return s
}

func (s *Snapshot) WithSecrets(secrets []string) *Snapshot {
	s.Secrets = secrets
	return s
}

func (s *Snapshot) IsEqual(other *Snapshot) bool {
	if s.Gateway != other.Gateway {
		return false
	}

	if !haveEqualElements(s.HTTPRoutes, other.HTTPRoutes) {
		return false
	}

	if !haveEqualElements(s.TCPRoutes, other.TCPRoutes) {
		return false
	}

	if !haveEqualElements(s.Secrets, other.Secrets) {
		return false
	}

	return true
}

// haveEqualElements returns true if the elements contained in the two slices
// are equal regardless of the order of the elements.
func haveEqualElements(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for _, x := range a {
		found := false
		for _, y := range b {
			if x == y {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}
