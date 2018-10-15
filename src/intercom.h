#pragma once

#include "vector.h"
#include "if.h"
#include "clientmgr.h"
#include "taskqueue.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#define L3ROAMD_PACKET_FORMAT_VERSION 0 
#define INFO_MAX 15 // this amount * sizeof(in6_addr) + 6 (mac-address) + 2 (type, lenght) must fit into uint8_t. If we have more than 15 IP addresses for a single client, we could implement sending multiple segments of type INFO_BASIC.
#define CLAIM_RETRY_MAX 15
#define INFO_RETRY_MAX 15

enum { INTERCOM_SEEK, INTERCOM_CLAIM, INTERCOM_INFO, INTERCOM_ACK };
enum { INFO_PLAT, INFO_BASIC };
enum { CLAIM_MAC };
enum { ACK_MAC };
enum { SEEK_ADDRESS };

typedef struct __attribute__((__packed__)) {
	uint8_t version;
	uint8_t ttl;
	uint8_t type;
	uint8_t empty;
	uint32_t nonce;
	uint8_t sender[16];
} intercom_packet_hdr;

typedef struct __attribute__((__packed__)) {
	intercom_packet_hdr hdr;
	// after this a dynamic buffer is appended to hold TLV - currently just an ipv6 address is allowed
} intercom_packet_seek;

typedef struct __attribute__((__packed__)) {
	intercom_packet_hdr hdr;
	// after this a dynamic buffer is appended to hold TLV. currently just mac address is allowed
} intercom_packet_claim;

typedef struct __attribute__((__packed__)) {
	intercom_packet_hdr hdr;
	// after this a dynamic buffer is appended to hold TLV. currently just mac address is allowed
} intercom_packet_ack;

typedef struct __attribute__((__packed__)) {
	intercom_packet_hdr hdr;
	// after this a dynamic buffer is appended for plat info and basic client info
} intercom_packet_info;

typedef struct __attribute__((__packed__)) {
	uint8_t type;
	uint8_t length;
	uint16_t lease;
	uint8_t platprefix[16];
} intercom_packet_info_plat;

typedef struct {
	uint8_t mac[ETH_ALEN];
} mac;

typedef  VECTOR(client_t) client_v;

typedef struct __attribute__((__packed__)) {
	uint8_t type;
	uint8_t length;
	uint8_t mac[ETH_ALEN];
	// afterwards an array of elements of type intercom_packet_info_entry is expected
} intercom_packet_info_basic;

typedef struct __attribute__((__packed__)) {
	uint8_t address[16];
} intercom_packet_info_entry;

typedef struct intercom_if {
	char *ifname;
	unsigned int ifindex;
	int mcast_recv_fd;
	bool ok;
} intercom_if_t;

typedef  VECTOR(intercom_if_t) intercom_if_v;

struct intercom_task {
	uint16_t packet_len;
	struct client *client;
	uint8_t *packet;
	struct in6_addr *recipient;
	taskqueue_t *check_task;
	uint8_t retries_left;
};


typedef struct {
	struct in6_addr ip;
	struct sockaddr_in6 groupaddr;
	struct l3ctx *l3ctx;
	VECTOR(intercom_packet_hdr) recent_packets;
	intercom_if_v interfaces;
	client_v repeatable_claims;
	client_v repeatable_infos;
	int unicast_nodeip_fd;
	int mtu;
} intercom_ctx;


// struct client;

void intercom_recently_seen_add(intercom_ctx *ctx, intercom_packet_hdr *hdr);
void intercom_send_packet(intercom_ctx *ctx, uint8_t *packet, ssize_t packet_len);
void intercom_seek(intercom_ctx *ctx, const struct in6_addr *address);
void intercom_init_unicast(intercom_ctx *ctx);
void intercom_init(intercom_ctx *ctx);
void intercom_handle_in(intercom_ctx *ctx, int fd);
bool intercom_add_interface(intercom_ctx *ctx, char *ifname);
bool intercom_del_interface(intercom_ctx *ctx, char *ifname);
void intercom_update_interfaces(intercom_ctx *ctx);
bool intercom_info(intercom_ctx *ctx, const struct in6_addr *recipient, struct client *client, bool relinquished);
bool intercom_claim(intercom_ctx *ctx, const struct in6_addr *recipient, struct client *client);
bool intercom_ack(intercom_ctx *ctx, const struct in6_addr *recipient, struct client *client);
