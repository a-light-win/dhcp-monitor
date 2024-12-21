package main

import (
	"os"

	"github.com/a-light-win/dhcp-monitor/logger"
	"github.com/alecthomas/kong"
	kongyaml "github.com/alecthomas/kong-yaml"
)

var Cli struct {
	Config kong.ConfigFlag `help:"Load configuration from a file"`

	LogLevel logger.LogLevel `enum:"debug,info,warn,error,fatal" help:"Set the log level" default:"info"`

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
