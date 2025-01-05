//go:build linux

package dhcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	config "github.com/a-light-win/dhcp-monitor/configs/dhcp"
	"github.com/a-light-win/dhcp-monitor/pkg/dhcp"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "$CGO_CFLAGS" -tags linux bpf dhcp_packet.c

type DhcpMonitor struct {
	bpfObjs bpfObjects
	links   []link.Link

	Config      *config.DhcpMonitorConfig
	DhcpHandler dhcp.Handler
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

const (
	DHCPOptPad         = 0   // 0x00
	DHCPOptHostName    = 12  // 0x0c
	DHCPOptRequestedIP = 50  // 0x32
	DHCPOptLeaseTime   = 51  // 0x33
	DHCPOptType        = 53  // 0x35
	DHCPOptClientID    = 61  // 0x3d
	DHCPOptEnd         = 255 // 0xff
)

func convertBpfDhcpEvent(bpfEvent *bpfDhcpEvent) (*dhcp.DhcpEvent, error) {
	event := dhcp.DhcpEvent{
		Timestamp: time.Now(),
	}
	if err := parseDhcpOptions(bpfEvent, &event); err != nil {
		return nil, err
	}

	// Set IpAddr based on MsgType
	switch event.MsgType {
	case dhcp.DHCPRelease:
		event.IpAddr = net.IP(bpfEvent.Ciaddr[:]).String()
	case dhcp.DHCPAck:
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

func parseDhcpOptions(bpfEvent *bpfDhcpEvent, event *dhcp.DhcpEvent) error {
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
			event.MsgType = dhcp.DhcpMsgType(value[0])
		}
		i += length
	}

	return nil
}

func New(dhcpConfig *config.DhcpMonitorConfig) *DhcpMonitor {
	return &DhcpMonitor{
		Config:      dhcpConfig,
		DhcpHandler: &dhcp.DhcpHandler{Config: dhcpConfig},
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
	log.Info().Str("Interface", iface.Name).Int("Infex", iface.Index).Msg("Attached TCX program to ingress")
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
	log.Info().Str("Interface", iface.Name).Int("Infex", iface.Index).Msg("Attached TCX program to egress")
	d.links = append(d.links, linkEgress)
	return nil
}

func (d *DhcpMonitor) Run() {
	if d.bpfObjs.DhcpEvents == nil {
		log.Fatal().Msg("BPF object DhcpEvents is nil")
	}
	rd, err := ringbuf.NewReader(d.bpfObjs.DhcpEvents)
	if err != nil {
		log.Fatal().Msgf("creating ringbuf reader: %s", err)
	}
	defer rd.Close()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Info().Msg("ringbuf reader closed, exiting")
				return
			}
			log.Info().Msgf("reading from ringbuf: %s", err)
			continue
		}

		var event bpfDhcpEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), hostByteOrder, &event); err != nil {
			log.Info().Msgf("decoding event: %s", err)
			continue
		}

		dhcpEvent, err := convertBpfDhcpEvent(&event)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to convert BPF event")
			continue
		}

		d.DhcpHandler.Handle(dhcpEvent)
	}
}

func (d *DhcpMonitor) Close() {
	d.bpfObjs.Close()
	for _, link := range d.links {
		link.Close()
	}
}
