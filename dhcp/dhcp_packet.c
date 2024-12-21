// go:build ignore

#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>

#define MAX_DHCP_OPTIONS 16

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

struct dhcp_option {
  __u8 type;
  void *data_begin;
  __u32 data_len;
};

struct dhcp_options {
  struct dhcp_option
      options[MAX_DHCP_OPTIONS]; // Array to store parsed DHCP options
  __u8 options_count;            // Number of parsed options
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
  __uint(max_entries, 2048);
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
  __u8 options[0]; // Optional parameters field. Reference RFC2132 for more
                   // information.
};

// Calculate the offset to the DHCP payload within the packet
int dhcp_payload_offset(void *data, int data_len) {
  int offset = 0;

  // Ether header
  int ethhdr_len = sizeof(struct ethhdr);
  offset += ethhdr_len;
  if (offset >= data_len) {
    return -1;
  }

  // IP header
  struct iphdr *ip = data + offset;
  offset += sizeof(*ip);
  if (offset >= data_len) {
    return -1;
  }
  if (ethhdr_len + bpf_ntohs(ip->tot_len) > data_len) {
    return -1;
  }
  offset += ip->ihl * 4 - sizeof(*ip);

  // UDP header
  offset += sizeof(struct udphdr);
  return offset >= data_len ? -1 : offset;
}

// Load the DHCP packet from the data
struct dhcp_packet *load_dhcp_packet(void *data, void *data_end) {
  int offset = dhcp_payload_offset(data, data_end - data);
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
__u8 get_dhcp_message_type(struct dhcp_options *options) {
  for (int i = 0; i < options->options_count; i++) {
    if (options->options[i].type == DHCP_OPT_TYPE) {
      return *((__u8 *)options->options[i].data_begin);
    }
  }
  return 0; // Return 0 if no DHCP message type is found
}

// Fetch a specific DHCP option and handle null termination if required
void fetch_dhcp_option(struct dhcp_options *options, __u8 option_type,
                       void *buffer, __u32 buffer_size) {
  for (int i = 0; i < options->options_count; i++) {
    if (options->options[i].type == option_type) {
      __u32 len = options->options[i].data_len < buffer_size
                      ? options->options[i].data_len
                      : buffer_size;
      bpf_probe_read(buffer, len, options->options[i].data_begin);
      return;
    }
  }
}

// Fetch a specific DHCP option as a null-terminated string
void fetch_dhcp_option_str(struct dhcp_options *options, __u8 option_type,
                           __u8 *buffer, __u32 buffer_size) {
  for (int i = 0; i < options->options_count; i++) {
    if (options->options[i].type == option_type) {
      __u32 len = options->options[i].data_len < (buffer_size - 1)
                      ? options->options[i].data_len
                      : (buffer_size - 1);
      bpf_probe_read(buffer, len, options->options[i].data_begin);
      buffer[len] = '\0';
      return;
    }
  }
}

// Fetch a specific DHCP option of type __u32 and handle byte order conversion
void fetch_dhcp_option_u32(struct dhcp_options *options, __u8 option_type,
                           __u32 *buffer) {
  for (int i = 0; i < options->options_count; i++) {
    if (options->options[i].type == option_type) {
      if (options->options[i].data_len >= sizeof(__u32)) {
        *buffer = bpf_ntohl(*(__u32 *)options->options[i].data_begin);
      }
      return;
    }
  }
}

// Parse the DHCP options from the packet
void parse_dhcp_options(struct dhcp_packet *packet, int packet_len,
                        struct dhcp_options *options) {
  __u8 *option_ptr = packet->options;
  __u8 *end = (__u8 *)packet + packet_len;

  while (option_ptr < end && options->options_count < MAX_DHCP_OPTIONS) {
    __u8 option_type = *option_ptr++;
    if (option_type == DHCP_OPT_END) {
      break;
    }

    __u8 option_len = *option_ptr++;
    if (option_ptr + option_len > end) {
      break;
    }

    if (option_type == DHCP_OPT_HOST_NAME ||
        option_type == DHCP_OPT_REQUESTED_IP ||
        option_type == DHCP_OPT_LEASE_TIME || option_type == DHCP_OPT_TYPE ||
        option_type == DHCP_OPT_CLIENT_ID) {
      struct dhcp_option *opt = &options->options[options->options_count++];
      opt->type = option_type;
      opt->data_begin = option_ptr;
      opt->data_len = option_len;
    }

    option_ptr += option_len;
  }
}

// Submit the event to the ring buffer
static inline void submit_event_to_ringbuf(struct dhcp_event *event) {
  struct dhcp_event *ringbuf_event =
      bpf_ringbuf_reserve(&dhcp_events, sizeof(*event), 0);
  if (ringbuf_event) {
    bpf_probe_read(ringbuf_event, sizeof(*event), event);
    bpf_ringbuf_submit(ringbuf_event, 0);
  }
}

// Handle DHCP request packets
void handle_dhcp_request(struct dhcp_packet *packet,
                         struct dhcp_options *options) {
  struct dhcp_event event = {};
  event.msg_type = DHCP_MSG_TYPE_REQUEST;
  // Extract host name from options
  fetch_dhcp_option_str(options, DHCP_OPT_HOST_NAME, event.hostname,
                        sizeof(event.hostname));

  // Add the event into the map with xid as the key
  bpf_map_update_elem(&dhcp_aquires, &packet->xid, &event, BPF_ANY);
}

// Handle DHCP release packets
void handle_dhcp_release(struct dhcp_packet *packet) {
  struct dhcp_event event = {};
  event.msg_type = DHCP_MSG_TYPE_RELEASE;
  bpf_probe_read(event.ip_addr, sizeof(event.ip_addr), &packet->ciaddr);
  bpf_probe_read(event.mac_addr, sizeof(event.mac_addr), packet->chaddr);

  // Put the event into the ring buffer
  submit_event_to_ringbuf(&event);
}

// Handle DHCP ACK packets
void handle_dhcp_ack(struct dhcp_packet *packet, struct dhcp_options *options) {
  struct dhcp_event *event;
  struct dhcp_event new_event = {};
  __u32 key = packet->xid;

  // Try to pop the event from the map
  event = bpf_map_lookup_elem(&dhcp_aquires, &key);
  if (event) {
    // Remove the event from the map
    bpf_map_delete_elem(&dhcp_aquires, &key);
  } else {
    // If the event does not exist, create a new one
    event = &new_event;
  }

  event->msg_type = DHCP_MSG_TYPE_ACK;
  bpf_probe_read(event->mac_addr, sizeof(event->mac_addr), packet->chaddr);
  bpf_probe_read(event->ip_addr, sizeof(event->ip_addr), &packet->yiaddr);
  event->elapsed_secs = bpf_ntohs(packet->secs);
  fetch_dhcp_option_u32(options, DHCP_OPT_LEASE_TIME, &event->lease_time);

  // Submit the event to the ring buffer
  submit_event_to_ringbuf(event);
}

// Handle DHCP ingress packets
void handle_dhcp_ingress(struct dhcp_packet *packet, int packet_len) {
  struct dhcp_options options = {};
  parse_dhcp_options(packet, packet_len, &options);
  __u8 msg_type = get_dhcp_message_type(&options);

  if (msg_type == DHCP_MSG_TYPE_RELEASE) {
    handle_dhcp_release(packet);
  } else if (msg_type == DHCP_MSG_TYPE_REQUEST) {
    handle_dhcp_request(packet, &options);
  }
  // TODO: handle other packet types.
}

// Handle DHCP egress packets
void handle_dhcp_egress(struct dhcp_packet *packet, int packet_len) {
  struct dhcp_event event = {};
  struct dhcp_options options = {};
  parse_dhcp_options(packet, packet_len, &options);
  __u8 msg_type = get_dhcp_message_type(&options);

  if (msg_type == DHCP_MSG_TYPE_ACK) {
    handle_dhcp_ack(packet, &options);
  }
}

// Handle DHCP packets
int handle_dhcp(struct __sk_buff *skb,
                void (*handler)(struct dhcp_packet *, int)) {
  if (bpf_ntohl(skb->protocol) != ETH_P_IP) {
    return TC_ACT_OK;
  }

  if (skb->local_port != DHCP_SERVER_PORT) {
    return TC_ACT_OK;
  }

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct dhcp_packet *packet = load_dhcp_packet(data, data_end);
  int packet_len = data_end - (void *)packet;
  if (packet != NULL) {
    handler(packet, packet_len);
  }
  return TC_ACT_OK;
}

// Ingress processing function
SEC("tcx/ingress")
int dhcp_ingress_proc(struct __sk_buff *skb) {
  return handle_dhcp(skb, handle_dhcp_ingress);
}

// Egress processing function
SEC("tcx/egress")
int dhcp_egress_proc(struct __sk_buff *skb) {
  return handle_dhcp(skb, handle_dhcp_egress);
}

char __license[] SEC("license") = "Dual MIT/GPL";
