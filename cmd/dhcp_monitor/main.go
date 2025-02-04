package main

import (
	"os"

	"github.com/alecthomas/kong"
	kongyaml "github.com/alecthomas/kong-yaml"
)

var Cli struct {
	Config kong.ConfigFlag `help:"Load configuration from a file"`

	Version VersionCmd `cmd:"" help:"Print the version of dhcp-monitor"`
	Serve   ServeCmd   `cmd:"" help:"Run the dhcp monitor daemon"`
}

func main() {
	ctx := kong.Parse(&Cli, kong.Configuration(kongyaml.Loader, "/etc/dhcp-monitor/config.yaml"))
	err := ctx.Run()
	if err != nil {
		os.Exit(1)
	}
}
