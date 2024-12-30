package dhcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	config "github.com/a-light-win/dhcp-monitor/configs/dhcp"
	"github.com/rs/zerolog/log"
)

type Handler interface {
	Handle(*DhcpEvent)
	Close()
}

type DhcpHandler struct {
	Config *config.DhcpMonitorConfig

	cachedEvents []DhcpEvent
}

func (d *DhcpHandler) Handle(event *DhcpEvent) {
	log.Debug().Str("MsgType", event.MsgType.String()).
		Str("IpAddr", event.IpAddr).
		Str("MacAddr", event.MacAddr).
		Str("Hostname", event.Hostname).
		Msg("Receive dhcp event")

	switch event.MsgType {
	case DHCPRequest:
		d.removeExpiredCacheEvents()
		d.cachedEvents = append(d.cachedEvents, *event)
	case DHCPAck:
		d.updateHostname(event)
		d.sendToWebhook(event)
	case DHCPRelease:
		d.sendToWebhook(event)
	default:
	}
}

func (d *DhcpHandler) Close() {
}

func (d *DhcpHandler) updateHostname(event *DhcpEvent) {
	for i, cachedEvent := range d.cachedEvents {
		if cachedEvent.Xid == event.Xid && cachedEvent.MacAddr == event.MacAddr {
			d.cachedEvents = append(d.cachedEvents[:i], d.cachedEvents[i+1:]...)
			event.Hostname = cachedEvent.Hostname
			return
		}
	}
}

func (d *DhcpHandler) removeExpiredCacheEvents() {
	for i, event := range d.cachedEvents {
		if time.Since(event.Timestamp) > time.Minute {
			d.cachedEvents = append(d.cachedEvents[:i], d.cachedEvents[i+1:]...)
		} else {
			// Fast break on first non expired event
			break
		}
	}
}

func (d *DhcpHandler) sendToWebhook(event *DhcpEvent) {
	log.Info().Str("MsgType", event.MsgType.String()).
		Str("IpAddr", event.IpAddr).
		Str("MacAddr", event.MacAddr).
		Str("Hostname", event.Hostname).
		Msg("Send dhcp event to webhook")

	data, err := json.Marshal(event)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal event before sending to webhook")
		return
	}

	resp, err := http.Post(d.Config.WebhookURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		log.Error().Err(err).Msg("Failed to send event to webhook")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("received non-200 response: %d", resp.StatusCode)
		log.Error().Err(err).Msg("Failed to send event to webhook")
	}
}
