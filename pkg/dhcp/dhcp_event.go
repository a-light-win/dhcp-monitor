package dhcp

import "time"

type DhcpEvent struct {
	Xid uint32 `json:"-"`

	Timestamp   time.Time   `json:"timestamp"`
	IpAddr      string      `json:"ip_addr"`
	MacAddr     string      `json:"mac_addr"`
	Hostname    string      `json:"hostname"`
	ElapsedSecs uint16      `json:"elapsed_secs"`
	LeaseTime   uint32      `json:"lease_time"`
	MsgType     DhcpMsgType `json:"msg_type"`
}
