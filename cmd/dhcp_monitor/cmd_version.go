package main

import (
	"fmt"
)

var (
	Version   = "0.0.1"
	GoVersion = "1.23"
)

type VersionCmd struct {
	BuildInfo bool `help:"Print build information" default:"false"`
}

func (v *VersionCmd) Run() error {
	fmt.Println("dhcp-monitor", Version)
	if v.BuildInfo {
		fmt.Println("Built by: go", GoVersion)
	}
	return nil
}
