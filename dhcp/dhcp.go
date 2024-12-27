//go:build linux

package dhcp

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -type dhcp_event bpf dhcp_packet.c

type DhcpMonitorConfig struct {
	WebhookURL string   `validate:"required" help:"URL to send DHCP events to"`
	IfaceNames []string `help:"Network interfaces to monitor DHCP traffic on"`
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
	if len(d.Config.IfaceNames) == 0 {
		interfaces, err := net.Interfaces()
		if err != nil {
			return err
		}
		for _, iface := range interfaces {
			if iface.Name != "lo" {
				d.Config.IfaceNames = append(d.Config.IfaceNames, iface.Name)
			}
		}
	}
	// Set the dhcp_prog_array with the program file descriptors
	if err := d.setDhcpProgArray(); err != nil {
		return fmt.Errorf("failed to set dhcp_prog_array: %w", err)
	}

	return nil
}

func (d *DhcpMonitor) setDhcpProgArray() error {
	progArray := d.bpfObjs.DhcpProgArray

	// Update the dhcp_prog_array with the program file descriptors
	if err := progArray.Put(uint32(0), uint32(d.bpfObjs.HandleDhcp.FD())); err != nil {
		return fmt.Errorf("failed to set handle program in dhcp_prog_array: %w", err)
	}

	return nil
}

func (d *DhcpMonitor) initBpfObjects() error {
	if err := loadBpfObjects(&d.bpfObjs, nil); err != nil {
		return fmt.Errorf("failed to load BPF objects: %w", err)
	}
	if d.bpfObjs.DhcpIngressProc == nil {
		return fmt.Errorf("BPF object DhcpIngressProc is nil")
	}
	if d.bpfObjs.DhcpEgressProc == nil {
		return fmt.Errorf("BPF object DhcpEgressProc is nil")
	}
	if d.bpfObjs.DhcpEvents == nil {
		return fmt.Errorf("BPF object DhcpEvents is nil")
	}

	return nil
}

func (d *DhcpMonitor) attachInterfaces() error {
	for _, ifaceName := range d.Config.IfaceNames {
		if err := d.attachInterface(ifaceName); err != nil {
			return err
		}
	}
	return nil
}

var logger = zerolog.New(os.Stderr).With().Timestamp().Logger()

func (d *DhcpMonitor) attachInterface(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Warn().Err(err).Str("Interface", ifaceName).Msg("Failed to get interface by name")
		return err
	}

	linkIngress, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   d.bpfObjs.DhcpIngressProc,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return err
	}
	logger.Info().Str("Interface", iface.Name).Int("Infex", iface.Index).Msg("Attached TCX program to ingress")
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
	logger.Info().Str("Interface", iface.Name).Int("Infex", iface.Index).Msg("Attached TCX program to egress")
	d.links = append(d.links, linkEgress)
	return nil
}

func (d *DhcpMonitor) Run() {
	if d.bpfObjs.DhcpEvents == nil {
		logger.Fatal().Msg("BPF object DhcpEvents is nil")
	}
	rd, err := ringbuf.NewReader(d.bpfObjs.DhcpEvents)
	if err != nil {
		logger.Fatal().Msgf("creating ringbuf reader: %s", err)
	}
	defer rd.Close()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				logger.Info().Msg("ringbuf reader closed, exiting")
				return
			}
			logger.Info().Msgf("reading from ringbuf: %s", err)
			continue
		}

		var event bpfDhcpEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), hostByteOrder, &event); err != nil {
			logger.Info().Msgf("decoding event: %s", err)
			continue
		}

		dhcpEvent := convertBpfDhcpEvent(event)
		log.Debug().Msgf("Receive event: %v", event)

		if err := d.sendToWebhook(dhcpEvent); err != nil {
			logger.Info().Msgf("sending to webhook: %s", err)
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
