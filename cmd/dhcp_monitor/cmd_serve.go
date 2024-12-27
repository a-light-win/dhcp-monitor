package main

import (
	"github.com/a-light-win/dhcp-monitor/dhcp"
	"github.com/a-light-win/dhcp-monitor/logger"
	"github.com/rs/zerolog/log"
	"github.com/sacloud/packages-go/validate"
)

type ServeCmd struct {
	dhcp.DhcpMonitorConfig

	LogLevel logger.LogLevel `enum:"debug,info,warn,error,fatal" help:"Set the log level" default:"info"`
}

func (s *ServeCmd) Run() error {
	validator := validate.New()
	if err := validator.Struct(&s.DhcpMonitorConfig); err != nil {
		log.Error().Err(err).Msg("config validation failed")
		return err
	}

	log.Log().Msgf("dhcp-monitor %s is start up", Version)

	if err := logger.InitLogger(s.LogLevel); err != nil {
		log.Error().Err(err).Msg("failed to initialize logger")
		return err
	}
	monitorConfig := s.DhcpMonitorConfig
	log.Info().
		Str("WebhookURL", monitorConfig.WebhookURL).
		Strs("IfaceNames", monitorConfig.IfaceNames).
		Msg("Core config")

	monitor := dhcp.New(&monitorConfig)
	if err := monitor.Init(); err != nil {
		log.Error().Err(err).Msg("failed to initialize dhcp monitor")
		return err
	}
	defer monitor.Close()

	monitor.Run()
	return nil
}
