//go:build linux

package dhcp

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -type dhcp_event bpf dhcp_packet.c
