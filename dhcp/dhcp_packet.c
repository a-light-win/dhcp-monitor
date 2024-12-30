// clang-format off
//go:build ignore
// clang-format on

#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>

#define DHCP_OPTIONS_LEN 312
#define DHCP_MAGIC_COOKIE 0x63825363

const static __u32 DHCP_CLIENT_PORT = 68;
const static __u32 DHCP_SERVER_PORT = 67;

struct dhcp_packet {
  __u8 op;    // Message op code / message type. 1 = BOOTREQUEST, 2 = BOOTREPLY
  __u8 htype; // Hardware address type, see ARP section in "Assigned Numbers"
              // RFC; e.g., '1' = 10mb ethernet.
  __u8 hlen;  // Hardware address length (e.g.  '6' for 10mb ethernet).
  __u8 hops;  // Client sets to zero, optionally used by relay agents when
              // booting via a relay agent.
  __u32 xid;  // Transaction ID, a random number chosen by the client, used by
              // the client and server to associate messages and responses
              // between a client and a server.
  __u16 secs; // Filled in by client, seconds elapsed since client began address
              // acquisition or renewal process.
  __u16 flags;
  __u32 ciaddr;    // Client IP address; only filled in if client is in BOUND,
                   // RENEW or REBINDING state and can respond to ARP requests.
  __u32 yiaddr;    // 'your' (client) IP address.
  __u32 siaddr;    // IP address of next server to use in bootstrap; returned in
                   // DHCPOFFER, DHCPACK by server.
  __u32 giaddr;    // Relay agent IP address, used in booting via a relay agent.
  __u8 chaddr[16]; // Client hardware address.
  __u8 sname[64];  // Optional server host name, null terminated string.
  __u8 file[128];  // Boot file name, null terminated string; "generic" name or
                   // null in DHCPDISCOVER, fully qualified directory-path name
                   // in DHCPOFFER.
  __u32 magic;     // 0x63825363
};

// Note that any fields changed in here should
// sync to bpfDhcpEvent in dhcp.go
struct dhcp_event {
  __u32 xid;    // Transaction ID, a random number chosen by the client, used by
                // the client and server to associate messages and responses
                // between a client and a server.
  __u32 ciaddr; // Client IP address; only filled in if client is in BOUND,
                // RENEW or REBINDING state and can respond to ARP requests.
  __u32 yiaddr; // 'your' (client) IP address.
  __u8 chaddr[6]; // Client hardware address.

  __u16 secs; // Filled in by client, seconds elapsed since client began address
              // acquisition or renewal process.
  __u16 options_len;              // Length of the raw DHCP packet data
  __u8 options[DHCP_OPTIONS_LEN]; // Buffer to store raw DHCP packet data
} __attribute__((packed));

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 8192);
} dhcp_events SEC(".maps");

static inline struct udphdr *parse_udp_header(struct __sk_buff *skb) {
  if (skb->protocol != bpf_htons(ETH_P_IP)) {
    return NULL;
  }

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  // Ether header
  struct ethhdr *ether_header = data;
  if ((void *)(ether_header + 1) > data_end) {
    return NULL;
  }

  // IP header
  struct iphdr *ip_header = (void *)(ether_header + 1);
  if ((void *)(ip_header + 1) > data_end) {
    return NULL;
  }

  if (ip_header->protocol != IPPROTO_UDP) {
    return NULL;
  }
  int ip_ext_len = ip_header->ihl * 4 - sizeof(*ip_header);

  // UDP header
  struct udphdr *udp_header = (void *)(ip_header + 1) + ip_ext_len;
  if ((void *)(udp_header + 1) > data_end) {
    return NULL;
  }

  return udp_header;
}

static inline int from_dhcp_client(struct udphdr *udp_header) {
  return udp_header->source == bpf_htons(DHCP_CLIENT_PORT) &&
         udp_header->dest == bpf_htons(DHCP_SERVER_PORT);
}

static inline int from_dhcp_server(struct udphdr *udp_header) {
  return udp_header->source == bpf_htons(DHCP_SERVER_PORT) &&
         udp_header->dest == bpf_htons(DHCP_CLIENT_PORT);
}

int handle_dhcp(struct __sk_buff *skb) {
  struct udphdr *udp_header = parse_udp_header(skb);
  if (udp_header == NULL) {
    return TC_ACT_OK;
  }

  if (!from_dhcp_client(udp_header) && !from_dhcp_server(udp_header)) {
    return TC_ACT_OK;
  }

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct dhcp_packet *packet = (void *)(udp_header + 1);
  if ((void *)(packet + 1) > data_end) {
    return TC_ACT_OK;
  }

  if (packet->magic != bpf_htonl(DHCP_MAGIC_COOKIE)) {
    return TC_ACT_OK;
  }

  void *options = (void *)packet + sizeof(struct dhcp_packet);
  if ((void *)options + 1 > data_end) {
    return TC_ACT_OK;
  }
  long options_len = (long)data_end - (long)options;
  if (options_len <= 0) {
    return TC_ACT_OK;
  }
  if (options_len > DHCP_OPTIONS_LEN) {
    options_len = DHCP_OPTIONS_LEN;
  }

  struct dhcp_event *event =
      bpf_ringbuf_reserve(&dhcp_events, sizeof(struct dhcp_event), 0);
  if (event == NULL) {
    return TC_ACT_OK;
  }

  event->xid = packet->xid;
  event->secs = packet->secs;
  event->ciaddr = packet->ciaddr;
  event->yiaddr = packet->yiaddr;
  __builtin_memcpy(event->chaddr, packet->chaddr, sizeof(event->chaddr));

  event->options_len = options_len;
  bpf_skb_load_bytes(skb, options - data, event->options, options_len);

  bpf_ringbuf_submit(event, 0);
  return TC_ACT_OK;
}

SEC("tcx/ingress") int dhcp_ingress_proc(struct __sk_buff *skb) {
  return handle_dhcp(skb);
}

SEC("tcx/egress") int dhcp_egress_proc(struct __sk_buff *skb) {
  return handle_dhcp(skb);
}

char __license[] SEC("license") = "Dual MIT/GPL";
