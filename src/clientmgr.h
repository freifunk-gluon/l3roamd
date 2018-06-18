#pragma once

#include "vector.h"
#include "prefix.h"
#include "common.h"
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <time.h>

#define OLDCLIENTS_KEEP_SECONDS 5 * 60

enum ip_state {
	IP_INACTIVE = 0, // ip address is known but not in use
	IP_ACTIVE,   // address is in used
	IP_TENTATIVE // address was received info on intercom OR belongs to a re-activated local client
};

typedef VECTOR(struct client) client_vector;

struct client_ip {
	struct in6_addr addr;
	struct timespec timestamp;
	uint8_t tentative_retries_left;
	enum ip_state state;
};

typedef struct client {
	struct in6_addr platprefix;
	struct timespec timeout;
	VECTOR(struct client_ip) addresses;
	int fd;
	unsigned int ifindex;
	bool node_ip_initialized;
	bool claimed;
	uint8_t mac[ETH_ALEN];
} client_t;

typedef struct {
	struct l3ctx *l3ctx;
	struct prefix node_client_prefix;
	struct prefix v4prefix;
	struct in6_addr platprefix;
	VECTOR(struct prefix) prefixes;
	client_vector clients;
	client_vector oldclients;
	unsigned int export_table;
	int nat46ifindex;
	bool platprefix_set;
} clientmgr_ctx;

struct client_task {
	clientmgr_ctx *ctx;
	uint8_t mac[ETH_ALEN];
};

void print_client(struct client *client);
bool clientmgr_valid_address(clientmgr_ctx *ctx, const struct in6_addr *ip);
void clientmgr_add_address(clientmgr_ctx *ctx, const struct in6_addr *address, const uint8_t *mac, const unsigned int ifindex);
void clientmgr_remove_address(clientmgr_ctx *ctx, struct client *client, struct in6_addr *address);
void clientmgr_notify_mac(clientmgr_ctx *ctx, uint8_t *mac, unsigned int ifindex);
bool clientmgr_handle_claim(clientmgr_ctx *ctx, const struct in6_addr *sender, uint8_t mac[ETH_ALEN]);
bool clientmgr_handle_info(clientmgr_ctx *ctx, struct client *foreign_client);
void clientmgr_purge_clients(clientmgr_ctx *ctx);
void clientmgr_delete_client(clientmgr_ctx *ctx, uint8_t mac[ETH_ALEN]);
void client_ip_set_state(clientmgr_ctx *ctx, struct client *client, struct client_ip *ip, enum ip_state state);
struct client *get_client(const uint8_t mac[ETH_ALEN]);
bool clientmgr_is_known_address(clientmgr_ctx *ctx, const struct in6_addr *address, struct client **client);
void add_special_ip(clientmgr_ctx *ctx, struct client *client);
struct client_ip *get_client_ip(struct client *client, const struct in6_addr *address);
struct in6_addr mac2ipv6(uint8_t mac[ETH_ALEN], struct prefix *prefix);
void clientmgr_init();
bool client_is_active(const struct client *client);
bool ip_is_active(const struct client_ip *ip);

int client_compare_by_mac ( const client_t *a, const client_t *b );
