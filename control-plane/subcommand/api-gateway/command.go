package apigateway

import (
	"sync"

	"github.com/mitchellh/cli"
)

const synopsis = "Runs the API Gateway controller for Consul on Kubernetes."

type Command struct {
	UI cli.Ui

	help string
	once sync.Once
}

func (c *Command) init() {
	// TODO this is where all the flags that exist on the current impl should be deined.
}

func (c *Command) Run(args []string) int {
	c.once.Do(c.init)

	c.UI.Info("API Gateway subcommand called!")

	// TODO this is where the actual command should be implemented.
	return 0
}

func (c *Command) Synopsis() string {
	return synopsis
}

func (c *Command) Help() string {
	c.once.Do(c.init)
	return c.help
}
