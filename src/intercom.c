#include "intercom.h"
#include "error.h"
#include "l3roamd.h"
#include "if.h"
#include "icmp6.h"
#include "syscallwrappers.h"
#include "prefix.h"
#include "util.h"
#include "alloc.h"

#include "clientmgr.h"

#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>

#define INTERCOM_GROUP "ff02::5523"
#define INTERCOM_MAX_RECENT 100

#define CLAIM_RETRY_MAX 5


void schedule_claim_retry(struct claim_task*, int timeout);

bool join_mcast(const int sock, const struct in6_addr addr, intercom_if *iface) {
	struct ipv6_mreq mreq;

	mreq.ipv6mr_multiaddr = addr;
	mreq.ipv6mr_interface = iface->ifindex;

	if (mreq.ipv6mr_interface == 0)
		goto error;

	if (setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) == 0)
		return true;
	else if (errno == EADDRINUSE)
		return true;

error:
	fprintf(stderr, "Could not join multicast group on %s: ", iface->ifname);
	perror(NULL);
	return false;
}

void intercom_update_interfaces(intercom_ctx *ctx) {
	for (int i = 0; i < VECTOR_LEN(ctx->interfaces); i++) {
		intercom_if *iface = &VECTOR_INDEX(ctx->interfaces, i);

		iface->ifindex = if_nametoindex(iface->ifname);

		if (!iface->ifindex)
			continue;

		iface->ok = join_mcast(VECTOR_INDEX(ctx->interfaces, i).mcast_recv_fd, ctx->groupaddr.sin6_addr, iface);
		// TODO: do we have to re-bind?
	}
}

bool intercom_has_ifname(intercom_ctx *ctx, char *ifname) {
	for (int i = 0; i < VECTOR_LEN(ctx->interfaces); i++) {
		intercom_if *iface = &VECTOR_INDEX(ctx->interfaces, i);

		if (strcmp(ifname, iface->ifname) == 0)
			return true;
	}

	return false;
}

void intercom_add_interface(intercom_ctx *ctx, char *ifname) {
	if (intercom_has_ifname(ctx, ifname))
		return;

	int ifindex = if_nametoindex(ifname);

	intercom_if iface = {
		.ok = false,
		.ifname = ifname,
		.ifindex = ifindex
	};

	VECTOR_ADD(ctx->interfaces, iface);

}

void obtainll(const char *ifname, struct in6_addr *ret) {
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in6 *sa;
	struct in6_addr ll = {};

	inet_pton(AF_INET6, "fe80::", &ll);

	getifaddrs (&ifap);
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr && ifa->ifa_addr->sa_family==AF_INET6) {
			if (!memcmp(ifname, ifa->ifa_name, strlen(ifname))) {
				sa = (struct sockaddr_in6 *) ifa->ifa_addr;
				struct prefix p = {
					.plen = 64,
					.prefix = ll
				};
				if (prefix_contains(&p, &sa->sin6_addr)) {
					memcpy(ret, &sa->sin6_addr, sizeof(struct in6_addr));
					goto end;
				}
			}
		}
	}

end:
	freeifaddrs(ifap);
}

void intercom_init(intercom_ctx *ctx) {

	struct in6_addr mgroup_addr;
	inet_pton(AF_INET6, INTERCOM_GROUP, &mgroup_addr); // TODO Fehler abfangen

	ctx->groupaddr = (struct sockaddr_in6) {
		.sin6_family = AF_INET6,
		.sin6_addr = mgroup_addr,
		.sin6_port = htons(INTERCOM_PORT),
	};

	// bind sockets to receive multicast
	for (int i=VECTOR_LEN(ctx->interfaces)-1;i>=0;i--) {
		int fd = socket(PF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
		if (fd < 0)
			exit_error("creating socket");

		ctx->groupaddr.sin6_scope_id = VECTOR_INDEX(ctx->interfaces, i).ifindex;
		if (bind(fd, (struct sockaddr *)&ctx->groupaddr, sizeof(ctx->groupaddr)) < 0) {
			perror("bind to multicast-address failed");
			exit(EXIT_FAILURE);
		}

		VECTOR_INDEX(ctx->interfaces, i).mcast_recv_fd = fd;
		printf("ASSIGNING fd: %i to mcast_recv_fd on interface %s\n", fd, VECTOR_INDEX(ctx->interfaces, i).ifname);
	}

	struct sockaddr_in6 server_addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(INTERCOM_PORT),
	};

	ctx->unicast_nodeip_fd = socket(PF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (ctx->unicast_nodeip_fd < 0)
		exit_error("creating socket for intercom on node-IP");

	memcpy(&server_addr.sin6_addr, ctx->ip.s6_addr, 16);
	if (bind(ctx->unicast_nodeip_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("bind socket to node-IP failed");
		exit(EXIT_FAILURE);
	}

	printf("ASSIGNING fd: %i to unicast_nodeip_fd\n", ctx->unicast_nodeip_fd);

	intercom_update_interfaces(ctx);
}

int assemble_header(intercom_packet_hdr  *hdr, uint8_t ttl, uint8_t type) {
	uint32_t nonce;
	hdr->type = type;
	hdr->version = L3ROAMD_PACKET_FORMAT_VERSION;
	hdr->ttl = ttl;
	hdr->empty = 0;
	obtainrandom(&nonce, sizeof(uint32_t), 0);
	hdr->nonce = htonl(nonce);
	memcpy(&hdr->sender, &l3ctx.intercom_ctx.ip, 16);

	return sizeof(intercom_packet_hdr);
}


int assemble_seek_address(uint8_t *packet, const struct in6_addr *address) {
	packet[0] = SEEK_ADDRESS;
	packet[1] = 20;
	packet[2] = packet[3] = 0;
	memcpy(&packet[4], address, 16);

	return packet[1];
}

int assemble_macinfo(uint8_t *packet, uint8_t *mac, uint8_t type) {
	packet[0] = type;
	packet[1] = 8;
	memcpy(&packet[2], mac, 6);
	return packet[1];
}

uint8_t assemble_platinfo(uint8_t *packet) {
	uint16_t lease=htons(0);
	packet[0] = INFO_PLAT;
	packet[1] = 20;
	memcpy(&packet[2], &lease , 2);
	memcpy(&packet[4], &l3ctx.clientmgr_ctx.platprefix, 16);
	return packet[1];
}

uint8_t assemble_basicinfo(uint8_t *packet, struct client *client) {
	uint8_t num_addresses = 0;
	
	packet[0] = INFO_BASIC;
	memcpy(&packet[2], client->mac, 6);

	intercom_packet_info_entry *entry = (intercom_packet_info_entry*)((uint8_t*)(packet) + sizeof(client->mac) + 2 );

	for (int i = 0; i < VECTOR_LEN(client->addresses) && num_addresses < INFO_MAX; i++) {
		struct client_ip *ip = &VECTOR_INDEX(client->addresses, i);
		if (ip_is_active(ip)) {
			memcpy(&entry->address, ip->addr.s6_addr, sizeof(uint8_t) * 16);
			entry++;
			num_addresses++;
		}
	}

	if (l3ctx.debug) {
		printf("added %i addresses to info packet for client ", num_addresses);
		print_client(client);
	}

	// fill length field
	packet[1] = num_addresses * sizeof(intercom_packet_info_entry) + sizeof(client->mac) + 2;
	return packet[1];
}


void intercom_seek(intercom_ctx *ctx, const struct in6_addr *address) {
	intercom_packet_seek *packet = l3roamd_alloc(sizeof(intercom_packet_seek) + 20);

	int offset = assemble_header(&packet->hdr, 255, INTERCOM_SEEK);
	offset += assemble_seek_address((void*)packet + offset, address);

	intercom_recently_seen_add(ctx, &packet->hdr);

	intercom_send_packet(ctx, (uint8_t*)packet, offset);
	free(packet);
}

bool intercom_send_packet_unicast(intercom_ctx *ctx, const struct in6_addr *recipient, uint8_t *packet, ssize_t packet_len) {
	struct sockaddr_in6 addr = (struct sockaddr_in6) {
		.sin6_family = AF_INET6,
		.sin6_port = htons(INTERCOM_PORT),
		.sin6_addr = *recipient
	};

	// printf("fd: %i, packet %p, length: %zi\n", ctx->unicast_nodeip_fd, packet, packet_len);
	ssize_t rc = sendto(ctx->unicast_nodeip_fd, packet, packet_len, 0, (struct sockaddr*)&addr, sizeof(addr));
	log_debug("sent intercom packet rc: %zi to %s\n", rc, print_ip(recipient));

	if (rc < 0)
		perror("sendto failed");

	return rc >= 0;
}

void intercom_send_packet(intercom_ctx *ctx, uint8_t *packet, ssize_t packet_len) {
	for (int i = 0; i < VECTOR_LEN(ctx->interfaces); i++) {
		intercom_if *iface = &VECTOR_INDEX(ctx->interfaces, i);
//		int fd = VECTOR_INDEX(ctx->interfaces, i).mcast_send_fd ;
		int fd = ctx->unicast_nodeip_fd;

		if (!iface->ok)
			continue;

		struct sockaddr_in6 _groupaddr = {};
		memcpy(&_groupaddr, &ctx->groupaddr, sizeof(struct sockaddr_in6));

		_groupaddr.sin6_scope_id = iface->ifindex;

		ssize_t rc = sendto(fd, packet, packet_len, 0, (struct sockaddr*)&_groupaddr, sizeof(struct sockaddr_in6));
		if (l3ctx.debug) {
			char str[INET6_ADDRSTRLEN+1];
			inet_ntop(AF_INET6, &_groupaddr.sin6_addr, str, INET6_ADDRSTRLEN);
			printf("sent intercom packet to %s on iface %s rc: %zi\n",str , iface->ifname,rc);
		}
		if (rc < 0)
			iface->ok = false;
	}
}

bool intercom_recently_seen(intercom_ctx *ctx, intercom_packet_hdr *hdr) {
	for (int i = 0; i < VECTOR_LEN(ctx->recent_packets); i++) {
		intercom_packet_hdr *ref_hdr = &VECTOR_INDEX(ctx->recent_packets, i);

		if (ref_hdr->nonce == hdr->nonce && ref_hdr->type == hdr->type)
			return true;
	}
	return false;
}

void intercom_recently_seen_add(intercom_ctx *ctx, intercom_packet_hdr *hdr) {
	if (VECTOR_LEN(ctx->recent_packets) > INTERCOM_MAX_RECENT)
		VECTOR_DELETE(ctx->recent_packets, 0);

	VECTOR_ADD(ctx->recent_packets, *hdr);
}

int parse_address(const uint8_t *packet, struct in6_addr *address){
	if (l3ctx.debug)
		printf("parsing seek packet segment: address\n");
	memcpy(address, &packet[4], 16);
	return packet[1];
}

int parse_mac(const uint8_t *packet, claim *claim){
	if (l3ctx.debug)
		printf("parsing claim packet segment: mac\n");
	memcpy(claim, &packet[2],6);
	return packet[1];
}

int parse_plat(const uint8_t *packet, struct client *client){
	if (l3ctx.debug)
		printf("parsing info packet plat\n");
	memcpy(&l3ctx.clientmgr_ctx.platprefix, &packet[4], 16);
	return packet[1];
}

int parse_basic(const uint8_t *packet,  struct client *client){
	memcpy(client->mac, &packet[2], sizeof(uint8_t) * 6);
	uint8_t length = packet[1];
	int num_addresses = (length - 2 - 6) / 16;

	if (l3ctx.debug) {
		printf("handling info segment with %i addresses for client ", num_addresses);
		print_client(client);
	}

	struct client_ip ip = { 0 };
	ip.state = IP_INACTIVE;

	intercom_packet_info_entry *entry = (intercom_packet_info_entry*)(packet + 8);

	for (int i = 0; i < num_addresses; i++) {
		memcpy(&ip.addr.s6_addr, &entry->address, sizeof(uint8_t) * 16);
		VECTOR_ADD(client->addresses, ip);
		log_debug("%s learnt from info packet\n", print_ip(&ip.addr));
		entry++;
	}

	return length;
}

// handler returns true if packet should be forwarded
bool intercom_handle_seek(intercom_ctx *ctx, intercom_packet_seek *packet, int packet_len) {
	struct in6_addr address= {};
	int currentoffset = sizeof(intercom_packet_info);
	uint8_t *packetpointer;
	uint8_t type;

	while (currentoffset < packet_len) {
		packetpointer = &((uint8_t*)packet)[currentoffset];
		type = *packetpointer;
		log_debug("offset: %i %p %p\n", currentoffset, packet ,packetpointer);
		switch (type) {
			case SEEK_ADDRESS:
				currentoffset += parse_address(packetpointer, &address);

				printf("\x1b[36mSEEK: Looking for %s\x1b[0m\n", print_ip(&address));

				if (address_is_ipv4(&address))
					arp_send_request(CTX(arp), &address);
				else
					icmp6_send_solicitation(CTX(icmp6), &address);
				break;
			default:
				printf("unknown segment of type %i found in info packet. ignoring this piece\n", type);
				break;

		}
	}
	return true;
}

bool intercom_handle_claim(intercom_ctx *ctx, intercom_packet_claim *packet, int packet_len) {
	struct in6_addr sender;
	int currentoffset = sizeof(intercom_packet_info);
	uint8_t *packetpointer;
	uint8_t type;

	claim claim = { };
	memcpy(&sender.s6_addr, &packet->hdr.sender, sizeof(uint8_t) * 16);
	printf("handling claim from: %s\n", print_ip(&sender));

	while (currentoffset < packet_len) {
		packetpointer = &((uint8_t*)packet)[currentoffset];
		type = *packetpointer;
		if (l3ctx.debug)
			printf("offset: %i %p %p\n", currentoffset, packet ,packetpointer);
		switch (type) {
			case CLAIM_MAC:
				currentoffset += parse_mac(packetpointer, &claim);
				break;
			default:
				printf("unknown segment of type %i found in info packet. ignoring this piece\n", type);
				break;

		}
	}

	return !clientmgr_handle_claim(CTX(clientmgr), &sender, claim.mac);
}



/** Finds the entry for a peer with a specified ID in the array \e ctx.peers */
/*
static int peer_id_cmp(fastd_peer_t *const *a, fastd_peer_t *const *b) {
if ((*a)->id == (*b)->id)
return 0;
else if ((*a)->id < (*b)->id)
return -1;
else
return 1;
}
static fastd_peer_t ** peer_p_find_by_id(uint64_t id) {
	fastd_peer_t key = {.id = id};
	fastd_peer_t *const keyp = &key;

	return VECTOR_BSEARCH(&keyp, ctx.peers, peer_id_cmp);
}
*/

bool find_repeatable_claim(uint8_t mac[ETH_ALEN], int *index) {
	// TODO: replace this with VECTOR_BSEARCH -- see the example above
	for (*index=0;*index<VECTOR_LEN(l3ctx.intercom_ctx.repeatable_claims);(*index)++) {
		struct client *client = &VECTOR_INDEX(l3ctx.intercom_ctx.repeatable_claims, *index);
		if (!memcmp(client->mac, mac, 6))
			return true;
	}
	return false;
}

bool intercom_handle_info(intercom_ctx *ctx, intercom_packet_info *packet, int packet_len) {
	uint8_t type, *packetpointer;
	struct client client = { 0 };
	int currentoffset = sizeof(intercom_packet_info);
	struct in6_addr sender;

	memcpy(&sender.s6_addr, &packet->hdr.sender, sizeof(uint8_t) * 16);

	log_debug("parsing info packet with length %i from: %s\n", packet_len, print_ip(&sender));

	while (currentoffset < packet_len) {
		packetpointer = &((uint8_t*)packet)[currentoffset];
		type = *packetpointer;
		if (l3ctx.debug)
			printf("offset: %i %p %p\n", currentoffset, packet ,packetpointer);
		switch (type) {
			case INFO_PLAT:
				currentoffset += parse_plat(packetpointer, &client);
				break;
			case INFO_BASIC:
				currentoffset += parse_basic(packetpointer, &client);
				break;
			default:
				printf("unknown segment of type %i found in info packet. ignoring this piece\n", type);
				break;

		}
	}

	int i = 0;
	if (find_repeatable_claim(client.mac, &i))
		VECTOR_DELETE(ctx->repeatable_claims, i);

	bool acted_on_local_client = clientmgr_handle_info(CTX(clientmgr), &client);

	VECTOR_FREE(client.addresses);
	return !acted_on_local_client;
}

void intercom_handle_packet(intercom_ctx *ctx, uint8_t *packet, ssize_t packet_len) {
	intercom_packet_hdr *hdr = (intercom_packet_hdr*) packet;
	bool forward = true;

	if (hdr->version == L3ROAMD_PACKET_FORMAT_VERSION) {

		if (intercom_recently_seen(ctx, hdr))
			return;

		intercom_recently_seen_add(ctx, hdr);
		if (hdr->type == INTERCOM_SEEK)
			forward = intercom_handle_seek(ctx, (intercom_packet_seek*)packet, packet_len);

		if (hdr->type == INTERCOM_CLAIM)
			forward = intercom_handle_claim(ctx, (intercom_packet_claim*)packet, packet_len);

		if (hdr->type == INTERCOM_INFO)
			forward = intercom_handle_info(ctx, (intercom_packet_info*)packet, packet_len);

		hdr->ttl--;
		if (hdr->ttl > 0 && forward)
			intercom_send_packet(ctx, packet, packet_len);
	}
	else {
		// if the packet version is unknown we cannot decrement ttl because we do not know where it is in the packet. Also the check whether we have already seen it fails.
		// all we can do is self-preservation and not crash and forward. However if we forward while having no already_seen_checks we will break the network. => dropping the packet.
		printf("unknown packet with version %i received on intercom. Ignoring content and dropping the packet that could have originated from: %s or %s. We are guessing here because the format may have shifted.\n ", hdr->version, print_ip((void*)&packet[6]), print_ip((void*)hdr->sender));
	}
}

void intercom_handle_in(intercom_ctx *ctx, int fd) {
	ssize_t count;
	uint8_t buf[ctx->mtu];

	log_debug("HANDLING INTERCOM PACKET on fd %i using buffersize of %i ", fd, ctx->mtu);

	while (1) {
		count = read(fd, buf, ctx->mtu);
		log_debug("- read %zi Bytes of data\n", count);
		if (count == -1) {
			/* If errno == EAGAIN, that means we have read all
				 data. So go back to the main loop.
			   if the last intercom packet was a claim for a local client, then we have just dropped the local client and will receive EBADF on the fd for the node-client-IP. This is not an error.*/
			if (errno == EBADF) {
				perror("read error - if we just dropped a local client due to this intercom packet being a claim then this is all right. otherwise there is something crazy going on. - returning to the main loop");
				printf("fd: %i\n", fd);
			}
			else if (errno != EAGAIN) {
				perror("read error - this should not happen - going back to main loop");
			}
			break;
		} else if (count == 0) {
			/* End of file. The remote has closed the
				 connection. */
			break;
		}

	// TODO if this is a claim for a local client, we should just stop iterating and get rid of the EBADF check above
		intercom_handle_packet(ctx, buf, count);
	}
}

/* recipient = NULL -> send to neighbours */
void intercom_info(intercom_ctx *ctx, const struct in6_addr *recipient, struct client *client, bool relinquished) {
	char str_mac[18];

	intercom_packet_info *packet = l3roamd_alloc(sizeof(intercom_packet_info) + sizeof(intercom_packet_info_plat) +  (8 + INFO_MAX * sizeof(intercom_packet_info_entry)));
	log_debug("allocated packet at %p\n", packet);

	mac_addr_n2a(str_mac, client->mac);

	log_debug("packet %p\n", packet);

	int currentoffset = assemble_header(&packet->hdr, 255, INTERCOM_INFO);
	log_debug("currentoffset: %i\n", currentoffset);

	currentoffset += assemble_platinfo((void*)packet + currentoffset );
	currentoffset += assemble_basicinfo((void*)packet + currentoffset, client);


	if (recipient != NULL) {
		packet->hdr.ttl = 1;
		log_debug("sending unicast info with length %i for client %s to %s\n",  currentoffset, str_mac, print_ip(recipient));
		intercom_send_packet_unicast(ctx, recipient, (uint8_t*)packet, currentoffset);
	}
	else {
		// forward packet to other l3roamd instances
		log_debug("sending info for client %s to l3roamd neighbours\n", str_mac);

		intercom_recently_seen_add(ctx, &packet->hdr);
		intercom_send_packet(ctx, (uint8_t*)packet, currentoffset);
	}
	free(packet);
}

void claim_retry_task(void *d) {
	struct claim_task *data = d;

	int repeatable_claim_index;
	if (!find_repeatable_claim(data->client->mac, &repeatable_claim_index))
		return;

	if (data->recipient != NULL) {
		log_debug("sending unicast claim for client %02x:%02x:%02x:%02x:%02x:%02x to %s\n",  data->client->mac[0], data->client->mac[1], data->client->mac[2], data->client->mac[3], data->client->mac[4], data->client->mac[5], print_ip(data->recipient));
		if (!intercom_send_packet_unicast(&l3ctx.intercom_ctx, data->recipient, (uint8_t*)data->packet, data->packet_len) ) {
			intercom_recently_seen_add(&l3ctx.intercom_ctx, &data->packet->hdr);
			intercom_send_packet(&l3ctx.intercom_ctx, (uint8_t*)data->packet, data->packet_len); // sending unicast did not work (node too new in the network OR client new to the network), fall back to multicast for now. Althogh this puts unnecessary load on the intercom network whenever a truly new client appears.
		}
	} else {
		log_debug("sending multicast claim for client %02x:%02x:%02x:%02x:%02x:%02x\n",  data->client->mac[0], data->client->mac[1], data->client->mac[2], data->client->mac[3], data->client->mac[4], data->client->mac[5]);
		intercom_recently_seen_add(&l3ctx.intercom_ctx, &data->packet->hdr);
		intercom_send_packet(&l3ctx.intercom_ctx, (uint8_t*)&data->packet, data->packet_len);
	}

	if (data->retries_left > 0)
		schedule_claim_retry(data,1);
	else {
		// we have not received an info message, otherwise we would not have run out of retries => noone knew the client and it is new to the mesh.
		// => adding the special IP
		VECTOR_DELETE(l3ctx.intercom_ctx.repeatable_claims, repeatable_claim_index);
		add_special_ip(&l3ctx.clientmgr_ctx, get_client(data->client->mac));
	}

}

void free_claim_task(void *d) {
	struct claim_task *data = d;
	free(data->packet);
	free(data->client);
	free(data->recipient);
	free(data);
}

void schedule_claim_retry(struct claim_task *data, int timeout) {
	if (data->retries_left == 0)
		return;

	struct claim_task *ndata = l3roamd_alloc(sizeof(struct claim_task));

	ndata->client = l3roamd_alloc(sizeof(struct client));
	memcpy(ndata->client, data->client,sizeof(struct client));

	ndata->packet_len = data->packet_len;
	ndata->packet = l3roamd_alloc(data->packet_len);
	memcpy(ndata->packet, data->packet, ndata->packet_len);

	ndata->recipient = NULL;
	if (data->recipient) {
		ndata->recipient = l3roamd_alloc_aligned(sizeof(struct in6_addr), sizeof(struct in6_addr));
		memcpy(ndata->recipient, data->recipient, sizeof(struct in6_addr));
	}

	ndata->retries_left = data->retries_left -1;
	ndata->check_task = post_task(&l3ctx.taskqueue_ctx, timeout, 0, claim_retry_task, free_claim_task, ndata);
}

bool intercom_claim(intercom_ctx *ctx, const struct in6_addr *recipient, struct client *client) {
	int i;
	char mac_str[18];

	if (l3ctx.debug)
		mac_addr_n2a(mac_str, client->mac);

	if (find_repeatable_claim(client->mac, &i)) {
		if (l3ctx.debug) {
			printf("   WOULD BE RUNNING CLAIM for [%s] but a repeatable claim is still in the queue - returning\n",mac_str);
		}
		return true;
	}
	else {
		if (l3ctx.debug)
			printf("CLAIMING client [%s]\n", mac_str);
	}

	struct claim_task *data = l3roamd_alloc(sizeof(struct claim_task));
	data->packet = l3roamd_alloc(sizeof(intercom_packet_claim) + 8);

	data->packet_len = assemble_header(&data->packet->hdr, 255, INTERCOM_CLAIM);
	data->packet_len += assemble_macinfo((void*)(data->packet) + data->packet_len, client->mac, CLAIM_MAC);

	intercom_recently_seen_add(ctx, &data->packet->hdr);

	VECTOR_ADD(ctx->repeatable_claims, *client);

	data->client = l3roamd_alloc(sizeof(struct client));
	memcpy(data->client, client,sizeof(struct client));
	data->retries_left = CLAIM_RETRY_MAX;
	data->check_task = NULL;
	data->recipient = NULL;

	if (recipient) {
		data->recipient = l3roamd_alloc_aligned(sizeof(struct in6_addr),16);
		memcpy(data->recipient, recipient, sizeof(struct in6_addr));
		data->packet->hdr.ttl = 1; // when sending unicast, do not continue to forward this packet at the destination
	}

	data->check_task = post_task(&l3ctx.taskqueue_ctx, 0, 0, claim_retry_task, free_claim_task, data);
	return true;
}
