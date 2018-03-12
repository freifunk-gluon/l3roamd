#pragma once

#include "vector.h"
#include "prefix.h"
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
	enum ip_state state;
	int tentative_retries_left;
	struct in6_addr addr;
	struct timespec timestamp;
};

typedef struct client {
	unsigned int ifindex;
	struct timespec timeout;
	uint8_t mac[6];
	VECTOR(struct client_ip) addresses;
	int fd;
	bool node_ip_initialized;
} client_t;

typedef struct {
	struct l3ctx *l3ctx;
	VECTOR(struct prefix) prefixes;
	struct prefix v4prefix;
	unsigned int export_table;
	int nat46ifindex;
	struct prefix node_client_prefix;
	client_vector clients;
	client_vector oldclients;
	struct in_addr start;
	struct in_addr end;
} clientmgr_ctx;

struct client_task {
	clientmgr_ctx *ctx;
	uint8_t mac[6];
};

void print_client(struct client *client);
bool clientmgr_valid_address(clientmgr_ctx *ctx, struct in6_addr *ip);
bool clientmgr_is_ipv4(clientmgr_ctx *ctx, struct in6_addr *ip);
void clientmgr_add_address(clientmgr_ctx *ctx, struct in6_addr *address, uint8_t *mac, unsigned int ifindex);
void clientmgr_remove_address(clientmgr_ctx *ctx, struct client *client, struct in6_addr *address);
void clientmgr_notify_mac(clientmgr_ctx *ctx, uint8_t *mac, unsigned int ifindex);
void clientmgr_handle_claim(clientmgr_ctx *ctx, const struct in6_addr *sender, uint8_t mac[6]);
void clientmgr_handle_info(clientmgr_ctx *ctx, struct client *foreign_client, bool relinquished);
void clientmgr_purge_clients(clientmgr_ctx *ctx);
void clientmgr_delete_client(clientmgr_ctx *ctx, uint8_t mac[6]);
void client_ip_set_state(clientmgr_ctx *ctx, struct client *client, struct client_ip *ip, enum ip_state state);
struct client *get_client(const uint8_t mac[6]);
bool clientmgr_is_known_address(clientmgr_ctx *ctx, const struct in6_addr *address, struct client **client);
void add_special_ip(clientmgr_ctx *ctx, struct client *client);
struct client_ip *get_client_ip(struct client *client, const struct in6_addr *address);
void mac_addr_n2a(char *mac_addr, unsigned char *arg);
struct in6_addr mac2ipv6(uint8_t mac[6], struct prefix *prefix);
void clientmgr_init();
bool client_is_active(const struct client *client);
bool ip_is_active(const struct client_ip *ip);

