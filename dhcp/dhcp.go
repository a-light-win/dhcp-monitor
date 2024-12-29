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
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf dhcp_packet.c

type DhcpMonitorConfig struct {
	WebhookURL string   `validate:"required" help:"URL to send DHCP events to"`
	IfaceNames []string `help:"Network interfaces to monitor DHCP traffic on"`
}

type DhcpMonitor struct {
	bpfObjs bpfObjects
	links   []link.Link

	Config DhcpMonitorConfig

	cachedEvents []DhcpEvent
}

type bpfDhcpEvent struct {
	Xid        [4]uint8
	Ciaddr     [4]uint8
	Yiaddr     [4]uint8
	Chaddr     [6]uint8
	Secs       [2]uint8
	OptionsLen uint16
	Options    [312]uint8
}

type DhcpEvent struct {
	Xid       uint32    `json:"-"`
	Timestamp time.Time `json:"-"`

	IpAddr      string `json:"ip_addr"`
	MacAddr     string `json:"mac_addr"`
	Hostname    string `json:"hostname"`
	ElapsedSecs uint16 `json:"elapsed_secs"`
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

	DHCPOptPad         = 0   // 0x00
	DHCPOptHostName    = 12  // 0x0c
	DHCPOptRequestedIP = 50  // 0x32
	DHCPOptLeaseTime   = 51  // 0x33
	DHCPOptType        = 53  // 0x35
	DHCPOptClientID    = 61  // 0x3d
	DHCPOptEnd         = 255 // 0xff
)

func convertBpfDhcpEvent(bpfEvent *bpfDhcpEvent) (*DhcpEvent, error) {
	event := DhcpEvent{
		Timestamp: time.Now(),
	}
	if err := parseDhcpOptions(bpfEvent, &event); err != nil {
		return nil, err
	}

	// Set IpAddr based on MsgType
	switch event.MsgType {
	case "DHCP Release":
		event.IpAddr = net.IP(bpfEvent.Ciaddr[:]).String()
	case "DHCP Ack":
		event.IpAddr = net.IP(bpfEvent.Yiaddr[:]).String()
	default:
		event.IpAddr = net.IP(bpfEvent.Ciaddr[:]).String()
	}

	// Set MacAddr and ElapsedSecs
	event.Xid = hostByteOrder.Uint32(bpfEvent.Xid[:])
	event.ElapsedSecs = hostByteOrder.Uint16(bpfEvent.Secs[:])
	event.MacAddr = net.HardwareAddr(bpfEvent.Chaddr[:6]).String()

	return &event, nil
}

func parseDhcpOptions(bpfEvent *bpfDhcpEvent, event *DhcpEvent) error {
	if bpfEvent.OptionsLen == 0 {
		return errors.New("DHCP options length is zero")
	}
	if bpfEvent.OptionsLen > uint16(len(bpfEvent.Options)) {
		return errors.New("DHCP options length is too large")
	}

	// Parse DHCP options
	options := bpfEvent.Options[:bpfEvent.OptionsLen]
	for i := 0; i < len(options); {
		opt := options[i]
		i++
		if opt == DHCPOptEnd {
			break
		}
		if opt == DHCPOptPad {
			continue
		}

		if i >= len(options) {
			return errors.New("malformed DHCP options, no length")
		}
		length := int(options[i])
		i++

		if i+length > len(options) {
			optionsHex := fmt.Sprintf("%x", options)
			log.Error().Msgf("Malformed DHCP option (%d), length %d exceeds max length %d. Options: %s", opt, length, len(options), optionsHex)
			return fmt.Errorf("malformed DHCP option (%d), length %d exceeds max length %d", opt, length, len(options))
		}
		value := options[i : i+length]
		switch opt {
		case DHCPOptHostName:
			event.Hostname = string(value)
		case DHCPOptLeaseTime:
			if len(value) != 4 {
				return errors.New("invalid lease time length")
			}
			event.LeaseTime = hostByteOrder.Uint32(value)
		case DHCPOptType:
			if len(value) != 1 {
				return errors.New("invalid message type length")
			}
			event.MsgType = dhcpMsgTypeToString(value[0])
		}
		i += length
	}

	return nil
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

		dhcpEvent, err := convertBpfDhcpEvent(&event)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to convert BPF event")
			continue
		}

		d.handleDhcpEvent(dhcpEvent)
	}
}

func (d *DhcpMonitor) handleDhcpEvent(event *DhcpEvent) {
	log.Debug().Str("MsgType", event.MsgType).
		Str("IpAddr", event.IpAddr).
		Str("MacAddr", event.MacAddr).
		Str("Hostname", event.Hostname).
		Msg("Receive dhcp event")

	switch event.MsgType {
	case "DHCP Request":
		d.removeExpiredCacheEvents()
		d.cachedEvents = append(d.cachedEvents, *event)
	case "DHCP Ack":
		d.updateHostname(event)
		d.sendToWebhook(event)
	case "DHCP Release":
		d.sendToWebhook(event)
	default:
	}
}

func (d *DhcpMonitor) updateHostname(event *DhcpEvent) {
	for i, cachedEvent := range d.cachedEvents {
		if cachedEvent.Xid == event.Xid && cachedEvent.MacAddr == event.MacAddr {
			d.cachedEvents = append(d.cachedEvents[:i], d.cachedEvents[i+1:]...)
			event.Hostname = cachedEvent.Hostname
			return
		}
	}
}

func (d *DhcpMonitor) removeExpiredCacheEvents() {
	for i, event := range d.cachedEvents {
		if time.Since(event.Timestamp) > time.Minute {
			d.cachedEvents = append(d.cachedEvents[:i], d.cachedEvents[i+1:]...)
		} else {
			// Fast break on first non expired event
			break
		}
	}
}

func (d *DhcpMonitor) sendToWebhook(event *DhcpEvent) {
	log.Info().Str("MsgType", event.MsgType).
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

func dhcpMsgTypeToString(msgType uint8) string {
	switch msgType {
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

func (d *DhcpMonitor) Close() {
	d.bpfObjs.Close()
	for _, link := range d.links {
		link.Close()
	}
}
