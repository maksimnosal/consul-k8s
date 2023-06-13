package consul

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/hashicorp/consul-k8s/control-plane/version"
	capi "github.com/hashicorp/consul/api"
)

// NewClient returns a Consul API client. It adds a required User-Agent
// header that describes the version of consul-k8s making the call.
func NewClient(config *capi.Config) (*capi.Client, error) {
	// Temporary fix adapted from:
	// https://github.com/hashicorp/consul-k8s/pull/1178/files#diff-e26f3f069a83cd05579a03865c772ef61f179d3da5cf9636e6029c430d44f25bR14
	timeoutSeconds := 2
	strTimeout := os.Getenv("CONSUL_CLIENT_API_TIMEOUT")
	if strTimeout != "" {
		parsed, err := strconv.Atoi(strTimeout)
		if err == nil && parsed > 0 {
			timeoutSeconds = parsed
		}
	}
	if config.HttpClient == nil {
		config.HttpClient = &http.Client{}
	}
	config.HttpClient.Timeout = time.Duration(timeoutSeconds) * time.Second

	if config.Transport == nil {
		tlsClientConfig, err := capi.SetupTLSConfig(&config.TLSConfig)

		if err != nil {
			return nil, err
		}

		config.Transport = &http.Transport{TLSClientConfig: tlsClientConfig}
	} else if config.Transport.TLSClientConfig == nil {
		tlsClientConfig, err := capi.SetupTLSConfig(&config.TLSConfig)

		if err != nil {
			return nil, err
		}

		config.Transport.TLSClientConfig = tlsClientConfig
	}

	config.HttpClient.Transport = config.Transport
	client, err := capi.NewClient(config)
	if err != nil {
		return nil, err
	}
	client.AddHeader("User-Agent", fmt.Sprintf("consul-k8s/%s", version.GetHumanVersion()))
	return client, nil
}
