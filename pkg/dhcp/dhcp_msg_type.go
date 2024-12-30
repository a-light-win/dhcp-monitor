package dhcp

import (
	"encoding/json"
)

type DhcpMsgType int

const (
	DHCPDiscover DhcpMsgType = 1
	DHCPOffer    DhcpMsgType = 2
	DHCPRequest  DhcpMsgType = 3
	DHCPDecline  DhcpMsgType = 4
	DHCPAck      DhcpMsgType = 5
	DHCPNak      DhcpMsgType = 6
	DHCPRelease  DhcpMsgType = 7
	DHCPInform   DhcpMsgType = 8
)

func (d DhcpMsgType) String() string {
	switch d {
	case DHCPDiscover:
		return "DHCP Discover"
	case DHCPOffer:
		return "DHCP Offer"
	case DHCPRequest:
		return "DHCP Request"
	case DHCPDecline:
		return "DHCP Decline"
	case DHCPAck:
		return "DHCP Ack"
	case DHCPNak:
		return "DHCP Nak"
	case DHCPRelease:
		return "DHCP Release"
	case DHCPInform:
		return "DHCP Inform"
	default:
		return "Unknown"
	}
}

func (d DhcpMsgType) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *DhcpMsgType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	switch s {
	case "DHCP Discover":
		*d = DHCPDiscover
	case "DHCP Offer":
		*d = DHCPOffer
	case "DHCP Request":
		*d = DHCPRequest
	case "DHCP Decline":
		*d = DHCPDecline
	case "DHCP Ack":
		*d = DHCPAck
	case "DHCP Nak":
		*d = DHCPNak
	case "DHCP Release":
		*d = DHCPRelease
	case "DHCP Inform":
		*d = DHCPInform
	default:
		*d = 0
	}

	return nil
}
