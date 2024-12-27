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

#define MAX_DHCP_OPTIONS 32

const static __u32 DHCP_CLIENT_PORT = 68;
const static __u32 DHCP_SERVER_PORT = 67;

enum {
  DHCP_MSG_TYPE_REQUEST = 3,
  DHCP_MSG_TYPE_ACK = 5,
  DHCP_MSG_TYPE_RELEASE = 7,
};

enum {
  DHCP_OPT_PAD = 0,           // 0x00
  DHCP_OPT_HOST_NAME = 12,    // 0x0c
  DHCP_OPT_REQUESTED_IP = 50, // 0x32
  DHCP_OPT_LEASE_TIME = 51,   // 0x33
  DHCP_OPT_TYPE = 53,         // 0x35
  DHCP_OPT_CLIENT_ID = 61,    // 0x3d
  DHCP_OPT_END = 255,         // 0xff;
};

struct dhcp_event {
  __u32 xid;          // Transaction ID
  __u32 elapsed_secs; // seconds elapsed since client began address acquisition
  __u32 lease_time;   // DHCP_OPT_LEASE_TIME in ACK

  __u8 hostname[64]; // DHCP_OPT_HOST_NAME
  __u8 ip_addr[4];   // DHCP_OPT_REQUESTED_IP, Your ip address
  __u8 mac_addr[6];  // Client mac address
  __u8 msg_type;     // request or release
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, struct dhcp_event);
  __uint(max_entries, 16);
} dhcp_aquires SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096);
} dhcp_events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
} dhcp_packet_offset_percpu_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct dhcp_event);
} dhcp_event_percpu_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
} dhcp_prog_array SEC(".maps");

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
};

// Get the DHCP message type from the options
static inline int parse_dhcp_options(struct __sk_buff *skb,
                                     struct dhcp_packet *packet,
                                     struct dhcp_event *event) {
  // pointer to options
  __u8 *cursor = (__u8 *)(packet + 1);
  __u8 *data_end = (__u8 *)(long)skb->data_end;

  for (__u8 count = 0; count < 1; count++) {
    // check option type is valid
    if (cursor + 1 > data_end) {
      return -1;
    }
    __u8 option_type = *cursor;
    cursor++;
    if (option_type == DHCP_OPT_PAD) {
      continue;
    }
    if (option_type == DHCP_OPT_END) {
      return 0;
    }

    // check option length is valid
    if (cursor + 1 > data_end) {
      return -1;
    }
    // get option length
    __u8 option_len = *cursor;
    cursor++;

    if (option_type == DHCP_OPT_TYPE) {
      if (option_len != 1 || cursor + 1 > data_end) {
        return -1;
      }
      event->msg_type = *cursor;
    } else if (option_type == DHCP_OPT_HOST_NAME) {
      __u32 len = option_len > sizeof(event->hostname) ? sizeof(event->hostname)
                                                       : option_len;
      if (len <= 0 || cursor + len > data_end) {
        return -1;
      }
      __u32 offset = cursor - (__u8 *)(long)skb->data;
      bpf_skb_load_bytes(skb, offset, event->hostname, len);
      event->hostname[len] = '\0';
    } else if (option_type == DHCP_OPT_LEASE_TIME) {
      if (option_len != sizeof(__u32) || cursor + option_len > data_end) {
        return -1;
      }
      event->lease_time = bpf_ntohl(*(__u32 *)cursor);
    }

    cursor += option_len;
  }

  return 0;
}

// Parse the DHCP options from the packet
static __always_inline int parse_event(struct __sk_buff *skb,
                                       struct dhcp_packet *packet,
                                       struct dhcp_event *event) {
  void *data = (void *)(long)skb->data;
  __u8 *data_end = (__u8 *)(long)skb->data_end;
  __u8 msg_type = event->msg_type;

  switch (msg_type) {
  case DHCP_MSG_TYPE_ACK: {
    bpf_skb_load_bytes(skb, (void *)packet->chaddr - data, event->mac_addr,
                       sizeof(event->mac_addr));
    bpf_skb_load_bytes(skb, (void *)(&packet->yiaddr) - data, event->ip_addr,
                       sizeof(event->ip_addr));
    event->elapsed_secs = bpf_ntohs(packet->secs);
    break;
  }
  case DHCP_MSG_TYPE_RELEASE: {
    bpf_skb_load_bytes(skb, (void *)packet->chaddr - data, event->mac_addr,
                       sizeof(event->mac_addr));
    bpf_skb_load_bytes(skb, (void *)(&packet->ciaddr) - data, event->ip_addr,
                       sizeof(event->ip_addr));
    break;
  }
  }
  return 0;
}

// Submit the event to the ring buffer
static inline void submit_event_to_ringbuf(struct dhcp_event *event) {
  struct dhcp_event *ringbuf_event =
      bpf_ringbuf_reserve(&dhcp_events, sizeof(*event), 0);
  if (ringbuf_event) {
    __builtin_memcpy(ringbuf_event, event, sizeof(*event));
    bpf_ringbuf_submit(ringbuf_event, 0);
  }
}

// Handle DHCP request packets
inline void handle_dhcp_request(struct dhcp_event *event) {
  bpf_map_update_elem(&dhcp_aquires, &event->xid, event, BPF_ANY);
}

// Handle DHCP release packets
inline void handle_dhcp_release(struct dhcp_event *event) {
  // Put the event into the ring buffer
  submit_event_to_ringbuf(event);
}

// Handle DHCP ACK packets
inline void handle_dhcp_ack(struct dhcp_event *event) {
  // Try to pop the event from the map
  struct dhcp_event *cached_event =
      bpf_map_lookup_elem(&dhcp_aquires, &event->xid);
  if (cached_event) {
    // Remove the event from the map
    __builtin_memcpy(event->hostname, cached_event->hostname,
                     sizeof(event->hostname));
    bpf_map_delete_elem(&dhcp_aquires, &event->xid);
  }

  submit_event_to_ringbuf(event);
}

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

int filter_dhcp(struct __sk_buff *skb) {
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

  struct dhcp_event event = {};
  if (parse_dhcp_options(skb, packet, &event) < 0) {
    return TC_ACT_OK;
  }
  if (parse_event(skb, packet, &event) < 0) {
    return TC_ACT_OK;
  }

  __u32 key = 0;
  bpf_map_update_elem(&dhcp_event_percpu_map, &key, &event, BPF_ANY);

  bpf_tail_call(skb, &dhcp_prog_array, 0);

  return TC_ACT_OK;
}

/*
SEC("tcx/parse_dhcp")
int parse_dhcp(struct __sk_buff *skb) {
  __u32 key = 0;
  __u32 *offset = bpf_map_lookup_elem(&dhcp_packet_offset_percpu_map, &key);
  if (!offset) {
    return TC_ACT_OK;
  }

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct dhcp_packet *packet = data + *offset;
  if ((void *)(packet + 1) > data_end) {
    return TC_ACT_OK;
  }
  struct dhcp_event event = {};
  if (parse_dhcp_options(skb, packet, &event) < 0) {
    return TC_ACT_OK;
  }
  if (parse_event(skb, packet, &event) < 0) {
    return TC_ACT_OK;
  }

  bpf_map_update_elem(&dhcp_event_percpu_map, &key, &event, BPF_ANY);

  bpf_tail_call(skb, &dhcp_prog_array, 1);

  return TC_ACT_OK;
}
*/

SEC("tcx/handle_dhcp")
int handle_dhcp(struct __sk_buff *skb) {
  __u32 key = 0;
  struct dhcp_event *event = bpf_map_lookup_elem(&dhcp_event_percpu_map, &key);
  if (!event) {
    return TC_ACT_OK;
  }

  switch (event->msg_type) {
  case DHCP_MSG_TYPE_REQUEST:
    handle_dhcp_request(event);
    break;
  case DHCP_MSG_TYPE_RELEASE:
    handle_dhcp_release(event);
    break;
  case DHCP_MSG_TYPE_ACK:
    handle_dhcp_ack(event);
    break;
  }

  return TC_ACT_OK;
}

SEC("tcx/ingress") int dhcp_ingress_proc(struct __sk_buff *skb) {
  return filter_dhcp(skb);
}

SEC("tcx/egress") int dhcp_egress_proc(struct __sk_buff *skb) {
  return filter_dhcp(skb);
}

char __license[] SEC("license") = "Dual MIT/GPL";
