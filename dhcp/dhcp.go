//go:build linux

package dhcp

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -type dhcp_event bpf dhcp_packet.c

type DhcpMonitorConfig struct {
	IfaceNmes  []string
	WebhookURL string
}

type DhcpMonitor struct {
	bpfObjs bpfObjects
	links   []link.Link

	Config DhcpMonitorConfig
}

type DhcpEvent struct {
	IpAddr      string `json:"ip_addr"`
	MacAddr     string `json:"mac_addr"`
	Hostname    string `json:"hostname"`
	ElapsedSecs uint32 `json:"elapsed_secs"`
	LeaseTime   uint32 `json:"lease_time"`
	MsgType     string `json:"msg_type"`
}

const (
	DHCPDiscover = 1
	DHCPOffer    = 2
	DHCPRequest  = 3
	DHCPDecline  = 4
	DHCPAck      = 5
	DHCPNak      = 6
	DHCPRelease  = 7
	DHCPInform   = 8
)

func dhcpMsgTypeToString(msgType uint8) string {
	switch msgType {
	case DHCPDiscover:
		return "discover"
	case DHCPOffer:
		return "offer"
	case DHCPRequest:
		return "request"
	case DHCPDecline:
		return "decline"
	case DHCPAck:
		return "ack"
	case DHCPNak:
		return "nak"
	case DHCPRelease:
		return "release"
	case DHCPInform:
		return "inform"
	default:
		return "unknown"
	}
}

func convertBpfDhcpEvent(event bpfDhcpEvent) DhcpEvent {
	ip := net.IP(event.IpAddr[:]).String()
	mac := net.HardwareAddr(event.MacAddr[:]).String()
	hostname := string(event.Hostname[:])
	return DhcpEvent{
		IpAddr:      ip,
		MacAddr:     mac,
		Hostname:    hostname,
		ElapsedSecs: event.ElapsedSecs,
		LeaseTime:   event.LeaseTime,
		MsgType:     dhcpMsgTypeToString(event.MsgType),
	}
}

func New(dhcpConfig *DhcpMonitorConfig) *DhcpMonitor {
	return &DhcpMonitor{
		Config: *dhcpConfig,
	}
}

func (d *DhcpMonitor) Init() error {
	if err := d.initBpfObjects(); err != nil {
		return err
	}
	if err := d.initInterfaces(); err != nil {
		return err
	}
	return d.attachInterfaces()
}

func (d *DhcpMonitor) initInterfaces() error {
	if len(d.Config.IfaceNmes) == 0 {
		interfaces, err := net.Interfaces()
		if err != nil {
			return err
		}
		for _, iface := range interfaces {
			if iface.Name != "lo" {
				d.Config.IfaceNmes = append(d.Config.IfaceNmes, iface.Name)
			}
		}
	}
	return nil
}

func (d *DhcpMonitor) initBpfObjects() error {
	return loadBpfObjects(&d.bpfObjs, nil)
}

func (d *DhcpMonitor) attachInterfaces() error {
	for _, ifaceName := range d.Config.IfaceNmes {
		if err := d.attachInterface(ifaceName); err != nil {
			return err
		}
	}
	return nil
}

func (d *DhcpMonitor) attachInterface(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)

	linkIngress, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   d.bpfObjs.DhcpIngressProc,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return err
	}
	log.Printf("Attached TCx program to INGRESS iface %q (index %d)", iface.Name, iface.Index)
	d.links = append(d.links, linkIngress)

	// Attach the program to Egress TC.
	linkEgress, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   d.bpfObjs.DhcpEgressProc,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return err
	}
	log.Printf("Attached TCx program to INGRESS iface %q (index %d)", iface.Name, iface.Index)
	d.links = append(d.links, linkEgress)
	return nil
}

func (d *DhcpMonitor) Run() {
	rd, err := ringbuf.NewReader(d.bpfObjs.DhcpEvents)
	if err != nil {
		log.Fatalf("creating ringbuf reader: %s", err)
	}
	defer rd.Close()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("ringbuf reader closed, exiting")
				return
			}
			log.Printf("reading from ringbuf: %s", err)
			continue
		}

		var event bpfDhcpEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), hostByteOrder, &event); err != nil {
			log.Printf("decoding event: %s", err)
			continue
		}

		dhcpEvent := convertBpfDhcpEvent(event)
		if err := d.sendToWebhook(dhcpEvent); err != nil {
			log.Printf("sending to webhook: %s", err)
		}
	}
}

func (d *DhcpMonitor) sendToWebhook(event DhcpEvent) error {
	if d.Config.WebhookURL == "" {
		return nil
	}

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	resp, err := http.Post(d.Config.WebhookURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-200 response: %d", resp.StatusCode)
	}

	return nil
}

func (d *DhcpMonitor) Close() {
	d.bpfObjs.Close()
	for _, link := range d.links {
		link.Close()
	}
}
