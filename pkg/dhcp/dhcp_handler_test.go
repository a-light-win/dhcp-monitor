package dhcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	config "github.com/a-light-win/dhcp-monitor/configs/dhcp"
	"github.com/stretchr/testify/assert"
)

func TestDhcpHandler_Handle(t *testing.T) {
	config := &config.DhcpMonitorConfig{
		WebhookURL: "http://example.com/webhook",
	}
	handler := &DhcpHandler{
		Config: config,
	}

	event := &DhcpEvent{
		MsgType:   DHCPDiscover,
		IpAddr:    "192.168.1.1",
		MacAddr:   "00:11:22:33:44:55",
		Hostname:  "test-host",
		Timestamp: time.Now(),
	}

	handler.Handle(event)
	assert.Len(t, handler.cachedEvents, 1)
	assert.Equal(t, event, &handler.cachedEvents[0])
}

func TestDhcpHandler_updateHostname(t *testing.T) {
	handler := &DhcpHandler{
		cachedEvents: []DhcpEvent{
			{
				Xid:      12345,
				MacAddr:  "00:11:22:33:44:55",
				Hostname: "cached-host",
			},
		},
	}

	event := &DhcpEvent{
		Xid:     12345,
		MacAddr: "00:11:22:33:44:55",
	}

	handler.updateHostname(event)
	assert.Equal(t, "cached-host", event.Hostname)
	assert.Empty(t, handler.cachedEvents)
}

func TestDhcpHandler_removeExpiredCacheEvents(t *testing.T) {
	handler := &DhcpHandler{
		cachedEvents: []DhcpEvent{
			{
				Timestamp: time.Now().Add(-2 * time.Minute),
			},
			{
				Timestamp: time.Now(),
			},
		},
	}

	handler.removeExpiredCacheEvents()
	assert.Len(t, handler.cachedEvents, 1)
}

func TestDhcpHandler_sendToWebhook(t *testing.T) {
	config := &config.DhcpMonitorConfig{
		WebhookURL: "http://example.com/webhook",
	}
	handler := &DhcpHandler{
		Config: config,
	}

	event := &DhcpEvent{
		MsgType:   DHCPAck,
		IpAddr:    "192.168.1.1",
		MacAddr:   "00:11:22:33:44:55",
		Hostname:  "test-host",
		Timestamp: time.Now(),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var receivedEvent DhcpEvent
		err := json.NewDecoder(r.Body).Decode(&receivedEvent)
		assert.NoError(t, err)
		assert.True(t, event.Timestamp.Equal(receivedEvent.Timestamp), "Timestamps are not equal")
		event.Timestamp = receivedEvent.Timestamp // Set the same timestamp for further comparison
		assert.Equal(t, event, &receivedEvent)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	handler.Config.WebhookURL = server.URL
	handler.sendToWebhook(event)
}
