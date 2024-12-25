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

#define MAX_DHCP_OPTIONS 10
#define MAX_PARSED_DHCP_OPTIONS 5

const static __u32 DHCP_CLIENT_PORT = 68;
const static __u32 DHCP_SERVER_PORT = 67;

enum {
  DHCP_MSG_TYPE_REQUEST = 3,
  DHCP_MSG_TYPE_ACK = 5,
  DHCP_MSG_TYPE_RELEASE = 7,
};

enum {
  DHCP_OPT_HOST_NAME = 12,    // 0x0c
  DHCP_OPT_REQUESTED_IP = 50, // 0x32
  DHCP_OPT_LEASE_TIME = 51,   // 0x33
  DHCP_OPT_TYPE = 53,         // 0x35
  DHCP_OPT_CLIENT_ID = 61,    // 0x3d
  DHCP_OPT_END = 255,         // 0xff;
};

struct dhcp_event {
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

// Handle DHCP packets
struct dhcp_packet_data {
  struct __sk_buff *skb;
  struct dhcp_packet *packet;
  __u8 *options;
  void *data_end;
};

// Calculate the offset to the DHCP payload within the packet
int dhcp_payload_offset(void *data, void *data_end) {
  int offset = 0;

  // Ether header 14 bytes
  int ethhdr_len = sizeof(struct ethhdr);
  offset += ethhdr_len;
  if (data + offset >= data_end) {
    return -1;
  }

  // IP header
  struct iphdr *iph = data + offset;
  if ((void *)(iph + 1) >= data_end) {
    return -1;
  }
  if (iph->protocol != IPPROTO_UDP) {
    return -1;
  }
  offset += sizeof(*iph);
  int ip_ext_len = iph->ihl * 4 - sizeof(*iph);
  if (ip_ext_len > 0) {
    offset += ip_ext_len;
  }

  // UDP header
  if (data + offset >= data_end) {
    return -1;
  }
  struct udphdr *udph = data + offset;
  if ((void *)(udph + 1) >= data_end) {
    return -1;
  }
  offset += sizeof(*udph);
  return offset;
}

// Load the DHCP packet from the data
struct dhcp_packet *load_dhcp_packet(void *data, void *data_end) {
  int offset = dhcp_payload_offset(data, data_end);
  if (offset < 0) {
    return NULL;
  }

  struct dhcp_packet *dhcp = data + offset;
  if ((void *)(dhcp + 1) > data_end) {
    return NULL;
  }

  return dhcp;
}

// Get the DHCP message type from the options
static __always_inline __u8
get_dhcp_message_type(struct dhcp_packet_data *packet_data) {
  __u8 *cursor = packet_data->options;
  __u8 *data_end = (__u8 *)packet_data->data_end;
  __u8 msg_type = 0;
  for (__u8 count = 0; count < MAX_DHCP_OPTIONS; count++) {
    // check option type is valid
    if (cursor + 1 > data_end) {
      break;
    }
    __u8 option_type = *cursor;
    if (option_type == DHCP_OPT_END) {
      break;
    }
    cursor++;

    // check option length is valid
    if (cursor + 1 > data_end) {
      break;
    }
    // get option length
    __u8 option_len = *cursor;
    cursor++;

    if (option_type == DHCP_OPT_TYPE) {
      if (option_len == 1 && cursor + option_len <= data_end) {
        msg_type = *cursor;
      }
      break;
    }

    cursor += option_len;
  }
  return msg_type;
}

// Parse the DHCP options from the packet
static __always_inline void parse_dhcp(struct dhcp_event *event,
                                       struct dhcp_packet_data *packet_data) {
  struct dhcp_packet *packet = packet_data->packet;
  struct __sk_buff *skb = packet_data->skb;
  void *data = (void *)(long)skb->data;
  __u8 *data_end = (__u8 *)packet_data->data_end;
  __u8 *option_ptr = packet_data->options;

  __u8 msg_type = get_dhcp_message_type(packet_data);
  event->msg_type = msg_type;

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

  // parse options by message type
  if (msg_type != DHCP_MSG_TYPE_REQUEST && msg_type != DHCP_MSG_TYPE_ACK) {
    return;
  }
  for (__u8 count = 0; count < MAX_DHCP_OPTIONS; count++) {
    // check option type is valid
    if (option_ptr + 1 > data_end) {
      break;
    }
    __u8 option_type = *option_ptr++;
    if (option_type == DHCP_OPT_END) {
      break;
    }

    // check option length is valid
    if (option_ptr + 1 > data_end) {
      break;
    }
    // get option length
    __u8 option_len = *option_ptr++;

    if (msg_type == DHCP_MSG_TYPE_REQUEST) {
      if (option_type == DHCP_OPT_HOST_NAME) {
        __u32 len = option_len > sizeof(event->hostname)
                        ? sizeof(event->hostname)
                        : option_len;
        if (len <= 0 || option_ptr + len > data_end) {
          break;
        }
        bpf_skb_load_bytes(skb, (void *)option_ptr - data, event->hostname,
                           len);
        event->hostname[len] = '\0';
      }
    }
    if (msg_type == DHCP_MSG_TYPE_ACK) {
      if (option_type == DHCP_OPT_LEASE_TIME) {
        if (option_len != sizeof(__u32) || option_ptr + option_len > data_end) {
          break;
        }
        event->lease_time = bpf_ntohl(*(__u32 *)option_ptr);
      }
    }

    option_ptr += option_len;
  }
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
inline void handle_dhcp_request(__u32 xid, struct dhcp_event *event) {
  bpf_map_update_elem(&dhcp_aquires, &xid, event, BPF_ANY);
}

// Handle DHCP release packets
inline void handle_dhcp_release(struct dhcp_event *event) {
  // Put the event into the ring buffer
  submit_event_to_ringbuf(event);
}

// Handle DHCP ACK packets
inline void handle_dhcp_ack(__u32 xid, struct dhcp_event *event) {
  // Try to pop the event from the map
  struct dhcp_event *cached_event = bpf_map_lookup_elem(&dhcp_aquires, &xid);
  if (cached_event) {
    // Remove the event from the map
    __builtin_memcpy(event->hostname, cached_event->hostname,
                     sizeof(event->hostname));
    bpf_map_delete_elem(&dhcp_aquires, &xid);
  }

  submit_event_to_ringbuf(event);
}

// Handle DHCP ingress packets
static __always_inline void
handle_dhcp_ingress(struct dhcp_packet_data *packet_data) {
  struct dhcp_event event = {};
  parse_dhcp(&event, packet_data);

  if (event.msg_type == DHCP_MSG_TYPE_RELEASE) {
    handle_dhcp_release(&event);
  } else if (event.msg_type == DHCP_MSG_TYPE_REQUEST) {
    handle_dhcp_request(packet_data->packet->xid, &event);
  }
  // TODO: handle other packet types.
}

// Handle DHCP egress packets
inline void handle_dhcp_egress(struct dhcp_packet_data *packet_data) {
  struct dhcp_event event = {};
  parse_dhcp(&event, packet_data);

  if (event.msg_type == DHCP_MSG_TYPE_ACK) {
    struct dhcp_event *event =
        bpf_ringbuf_reserve(&dhcp_events, sizeof(struct dhcp_event), 0);
    if (!event) {
      return;
    }
    // Try to pop the event from the map
    struct dhcp_packet *packet = packet_data->packet;
    __u32 key = packet->xid;
    struct dhcp_event *cached_event = bpf_map_lookup_elem(&dhcp_aquires, &key);
    if (cached_event) {
      // Remove the event from the map
      bpf_probe_read(event, sizeof(*event), cached_event);
      bpf_map_delete_elem(&dhcp_aquires, &key);
    }

    event->msg_type = DHCP_MSG_TYPE_ACK;
    bpf_probe_read(event->mac_addr, sizeof(event->mac_addr), packet->chaddr);
    bpf_probe_read(event->ip_addr, sizeof(event->ip_addr), &packet->yiaddr);
    event->elapsed_secs = bpf_ntohs(packet->secs);

    bpf_ringbuf_submit(event, 0);
  }
}

int check_and_get_dhcp(struct __sk_buff *skb,
                       struct dhcp_packet_data *packet_data) {
  if (skb->protocol != bpf_htons(ETH_P_IP)) {
    return -1;
  }

  __u32 local_port;
  if (bpf_skb_load_bytes(skb, offsetof(struct __sk_buff, local_port),
                         &local_port, sizeof(local_port)) < 0) {
    return -1;
  }
  if (local_port != DHCP_SERVER_PORT) {
    return -1;
  }

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  packet_data->packet = load_dhcp_packet(data, data_end);
  if (packet_data->packet == NULL) {
    return -1;
  }
  packet_data->skb = skb;
  packet_data->options = (__u8 *)(packet_data->packet + 1);
  packet_data->data_end = data_end;
  return 0;
}

// Ingress processing function
SEC("tcx/ingress")
int dhcp_ingress_proc(struct __sk_buff *skb) {
  struct dhcp_packet_data packet_data = {};
  if (check_and_get_dhcp(skb, &packet_data) < 0) {
    return TC_ACT_OK;
  }
  handle_dhcp_ingress(&packet_data);
  return TC_ACT_OK;
}

// Egress processing function
SEC("tcx/egress")
int dhcp_egress_proc(struct __sk_buff *skb) {
  struct dhcp_packet_data packet_data = {};
  struct dhcp_event event = {};
  if (check_and_get_dhcp(skb, &packet_data) < 0) {
    return TC_ACT_OK;
  }
  if (packet_data.data_end == NULL || packet_data.packet == NULL ||
      packet_data.options == NULL) {
    return TC_ACT_OK;
  }
  parse_dhcp(&event, &packet_data);

  if (event.msg_type == DHCP_MSG_TYPE_ACK) {
    handle_dhcp_ack(packet_data.packet->xid, &event);
  }

  return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";
