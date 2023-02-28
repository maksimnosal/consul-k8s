package envoy

import (
	"math"

	"github.com/stretchr/testify/require"
)

type EnvoyStats []EnvoyStat

func (e EnvoyStats) ToMap() map[string]EnvoyStat {
	result := map[string]EnvoyStat{}
	for _, stat := range e {
		if stat.Name != "" {
			result[stat.Name] = stat
		}
	}
	return result
}

type EnvoyStat struct {
	Name  string
	Value interface{}
}

func (e EnvoyStat) Int(t require.TestingT) int {
	switch e.Value.(type) {
	case int:
		return e.Value.(int)
	case float64:
		// JSON parsing gives us float64.
		return int(math.Round(e.Value.(float64)))
	}
	t.Errorf("not a number: %v = %v (%T)", e.Name, e.Value, e.Value)
	return 0
}
