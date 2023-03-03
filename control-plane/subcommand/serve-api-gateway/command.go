package serveapigateway

import (
	"flag"
	"sync"
	"time"

	apigateway "github.com/hashicorp/consul-k8s/control-plane/api-gateway"
	"github.com/mitchellh/cli"
)

const synopsis = "Runs the API Gateway controller for Consul on Kubernetes."

const (
	defaultGRPCPort      = 8502
	defaultSDSServerHost = "consul-api-gateway-controller.default.svc.cluster.local"
	defaultSDSServerPort = 9090
	// The amount of time to wait for the first cert write
	defaultCertWaitTime = 1 * time.Minute
)

type Command struct {
	UI cli.Ui

	flagCAFile            string // CA File for CA for Consul server
	flagCASecret          string // CA Secret for Consul server
	flagCASecretNamespace string // CA Secret namespace for Consul server

	flagConsulAddress string // Consul server address

	flagPrimaryDatacenter string // Primary datacenter, may or may not be the datacenter this controller is running in

	flagSDSServerHost string // SDS server host
	flagSDSServerPort int    // SDS server port
	flagMetricsPort   int    // Port for prometheus metrics
	flagPprofPort     int    // Port for pprof profiling
	flagK8sContext    string // context to use
	flagK8sNamespace  string // namespace we're run in

	// Consul namespaces
	flagConsulDestinationNamespace string
	flagMirrorK8SNamespaces        bool
	flagMirrorK8SNamespacePrefix   string

	// Logging
	flagLogLevel string
	flagLogJSON  bool

	help string

	flagSet *flag.FlagSet
	once    sync.Once
}

func (c *Command) init() {
	c.flagSet = flag.NewFlagSet("", flag.ContinueOnError)
	c.flagSet.StringVar(&c.flagCAFile, "ca-file", "", "Path to CA for Consul server.")
	c.flagSet.StringVar(&c.flagCASecret, "ca-secret", "", "CA Secret for Consul server.")
	c.flagSet.StringVar(&c.flagCASecretNamespace, "ca-secret-namespace", "default", "CA Secret namespace for Consul server.")
	c.flagSet.StringVar(&c.flagConsulAddress, "consul-address", "", "Consul Address.")
	c.flagSet.StringVar(&c.flagPrimaryDatacenter, "primary-datacenter", "", "Name of the primary Consul datacenter")
	c.flagSet.StringVar(&c.flagSDSServerHost, "sds-server-host", defaultSDSServerHost, "SDS Server Host.")
	c.flagSet.StringVar(&c.flagK8sContext, "k8s-context", "", "Kubernetes context to use.")
	c.flagSet.StringVar(&c.flagK8sNamespace, "k8s-namespace", "", "Kubernetes namespace to use.")
	c.flagSet.IntVar(&c.flagSDSServerPort, "sds-server-port", defaultSDSServerPort, "SDS Server Port.")
	c.flagSet.IntVar(&c.flagMetricsPort, "metrics-port", 0, "Metrics port, if not set, metrics are not enabled.")
	c.flagSet.IntVar(&c.flagPprofPort, "pprof-port", 0, "Go pprof port, if not set, profiling is not enabled.")

	{
		// Consul namespaces
		c.flagSet.StringVar(&c.flagConsulDestinationNamespace, "consul-destination-namespace", "", "Consul namespace to register gateway services.")
		c.flagSet.BoolVar(&c.flagMirrorK8SNamespaces, "mirroring-k8s", false, "Register Consul gateway services based on Kubernetes namespace.")
		c.flagSet.StringVar(&c.flagMirrorK8SNamespacePrefix, "mirroring-k8s-prefix", "", "Namespace prefix for Consul services when mirroring Kubernetes namespaces.")
	}

	{
		// Logging
		c.flagSet.StringVar(&c.flagLogLevel, "log-level", "info",
			"Log verbosity level. Supported values (in order of detail) are \"trace\", "+
				"\"debug\", \"info\", \"warn\", and \"error\".")
		c.flagSet.BoolVar(&c.flagLogJSON, "log-json", false,
			"Enable or disable JSON output format for logging.")
	}
}

func (c *Command) Run(args []string) int {
	c.UI.Info("Serve API Gateway subcommand called!")

	c.once.Do(c.init)

	if err := c.flagSet.Parse(args); err != nil {
		return 1
	}

	return 0
}

func (c *Command) Synopsis() string {
	return synopsis
}

func (c *Command) Help() string {
	c.once.Do(c.init)
	return c.help
}
