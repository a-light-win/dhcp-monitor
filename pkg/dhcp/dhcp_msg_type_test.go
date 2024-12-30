package dhcp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDhcpMsgType_String(t *testing.T) {
	tests := []struct {
		msgType  DhcpMsgType
		expected string
	}{
		{DHCPDiscover, "DHCP Discover"},
		{DHCPOffer, "DHCP Offer"},
		{DHCPRequest, "DHCP Request"},
		{DHCPDecline, "DHCP Decline"},
		{DHCPAck, "DHCP Ack"},
		{DHCPNak, "DHCP Nak"},
		{DHCPRelease, "DHCP Release"},
		{DHCPInform, "DHCP Inform"},
		{DhcpMsgType(0), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.msgType.String())
		})
	}
}

func TestDhcpMsgType_MarshalJSON(t *testing.T) {
	tests := []struct {
		msgType  DhcpMsgType
		expected string
	}{
		{DHCPDiscover, `"DHCP Discover"`},
		{DHCPOffer, `"DHCP Offer"`},
		{DHCPRequest, `"DHCP Request"`},
		{DHCPDecline, `"DHCP Decline"`},
		{DHCPAck, `"DHCP Ack"`},
		{DHCPNak, `"DHCP Nak"`},
		{DHCPRelease, `"DHCP Release"`},
		{DHCPInform, `"DHCP Inform"`},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			data, err := json.Marshal(tt.msgType)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, string(data))
		})
	}
}

func TestDhcpMsgType_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		input    string
		expected DhcpMsgType
	}{
		{`"DHCP Discover"`, DHCPDiscover},
		{`"DHCP Offer"`, DHCPOffer},
		{`"DHCP Request"`, DHCPRequest},
		{`"DHCP Decline"`, DHCPDecline},
		{`"DHCP Ack"`, DHCPAck},
		{`"DHCP Nak"`, DHCPNak},
		{`"DHCP Release"`, DHCPRelease},
		{`"DHCP Inform"`, DHCPInform},
		{`"Unknown"`, DhcpMsgType(0)},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			var msgType DhcpMsgType
			err := json.Unmarshal([]byte(tt.input), &msgType)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, msgType)
		})
	}
}
