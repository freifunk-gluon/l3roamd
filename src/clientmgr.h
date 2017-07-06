#pragma once

#include "vector.h"
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <time.h>

#define CLIENT_TIMEOUT 300
#define NODE_CLIENT_PREFIX "fec0::"

enum ip_state {
	IP_INACTIVE = 0,
	IP_ACTIVE,
	IP_TENTATIVE
};

struct prefix {
	struct in6_addr prefix;
	int plen; /* in bits */
};

struct client_ip {
	enum ip_state state;
	int tentative_retries_left;
	struct in6_addr addr;
	struct timespec timestamp;
};

struct client {
	unsigned int ifindex;
	struct timespec timeout;
	uint8_t mac[6];
	VECTOR(struct client_ip) addresses;
};

typedef struct {
	struct l3ctx *l3ctx;
	struct prefix prefix;
	struct prefix v4prefix;
	unsigned int export_table;
	int nat46ifindex;
	VECTOR(struct client) clients;
} clientmgr_ctx;

struct client_task {
	clientmgr_ctx *ctx;
	uint8_t mac[6];
};

bool clientmgr_valid_address(clientmgr_ctx *ctx, struct in6_addr *ip);
bool clientmgr_is_ipv4(clientmgr_ctx *ctx, struct in6_addr *ip);
void clientmgr_add_address(clientmgr_ctx *ctx, struct in6_addr *address, uint8_t *mac, unsigned int ifindex);
void clientmgr_notify_mac(clientmgr_ctx *ctx, uint8_t *mac, unsigned int ifindex);
void clientmgr_handle_claim(clientmgr_ctx *ctx, const struct in6_addr *sender, uint8_t mac[6]);
void clientmgr_handle_info(clientmgr_ctx *ctx, struct client *foreign_client, bool relinquished);
void clientmgr_delete_client(clientmgr_ctx *ctx, const uint8_t mac[6]);
void client_ip_set_state(clientmgr_ctx *ctx, struct client *client, struct client_ip *ip, enum ip_state state);
struct client *get_client(clientmgr_ctx *ctx, const uint8_t mac[6]);
