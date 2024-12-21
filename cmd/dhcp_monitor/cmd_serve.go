package main

import (
	"github.com/a-light-win/dhcp-monitor/dhcp"
	"github.com/rs/zerolog/log"
	"github.com/sacloud/packages-go/validate"
)

type ServeCmd struct {
	dhcp.DhcpMonitorConfig
}

func (s *ServeCmd) Run() error {
	validator := validate.New()
	if err := validator.Struct(&s.DhcpMonitorConfig); err != nil {
		log.Error().Err(err).Msg("config validation failed")
		return err
	}

	log.Log().Msgf("dhcp-monitor %s is start up", Version)

	monitor := dhcp.New(&s.DhcpMonitorConfig)
	err := monitor.Init()
	if err != nil {
		log.Error().Err(err).Msg("failed to initialize dhcp monitor")
		return err
	}
	defer monitor.Close()

	monitor.Run()
	return nil
}
