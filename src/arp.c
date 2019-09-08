/*
 * This file is part of project l3roamd. It's copyrighted by the contributors
 * recorded in the version control history of the file, available from
 * its original location https://github.com/freifunk-gluon/l3roamd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "arp.h"
#include "l3roamd.h"

#include <error.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <sys/ioctl.h>
#include "util.h"

void arp_handle_in(arp_ctx *ctx, int fd) {
	struct msghdr msghdr;
	memset(&msghdr, 0, sizeof(msghdr));

	char cbuf[CMSG_SPACE(sizeof(int))];

	struct arp_packet packet;

	struct iovec iov = {.iov_base = &packet, .iov_len = sizeof(packet)};

	struct sockaddr_ll lladdr;

	struct msghdr hdr = {.msg_name = &lladdr,
			     .msg_namelen = sizeof(lladdr),
			     .msg_iov = &iov,
			     .msg_iovlen = 1,
			     .msg_control = cbuf,
			     .msg_controllen = sizeof(cbuf)};

	ssize_t rc = recvmsg(fd, &hdr, 0);

	if (rc == -1)
		return;

	log_debug("handling arp event\n");

	if (packet.op != htons(ARP_REPLY))
		return;

	if (memcmp(packet.spa, "\x00\x00\x00\x00", 4) == 0)  // IP is 0.0.0.0 - not sensible to add that.
		return;

	uint8_t *mac = lladdr.sll_addr;

	struct in6_addr address = ctx->prefix;

	memcpy(&address.s6_addr[12], packet.spa, 4);

	char str[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &address, str, INET6_ADDRSTRLEN);
	log_verbose("ARP Response from %s (MAC %s)\n", str, print_mac(mac));

	clientmgr_add_address(&l3ctx.clientmgr_ctx, &address, packet.sha, ctx->ifindex);
}

void arp_send_request(arp_ctx *ctx, const struct in6_addr *addr) {
	struct arp_packet packet = {.hd = htons(1), .pr = htons(0x800), .hdl = 6, .prl = 4, .op = htons(ARP_REQUEST)};

	memcpy(&packet.sha, ctx->mac, 6);
	memcpy(&packet.spa, "\x00\x00\x00\x00", 4);
	memcpy(&packet.dha, "\xff\xff\xff\xff\xff\xff", 6);
	memcpy(&packet.dpa, &addr->s6_addr[12], 4);

	log_verbose("Send ARP to %s\n", print_ip(addr));

	struct sockaddr_ll dst = {
	    .sll_ifindex = ctx->ifindex, .sll_protocol = htons(ETH_P_ARP), .sll_family = PF_PACKET, .sll_halen = 6,
	};

	memcpy(&dst.sll_addr, "\xff\xff\xff\xff\xff\xff", 6);

	sendto(ctx->fd, &packet, sizeof(packet), 0, (struct sockaddr *)&dst, sizeof(dst));
}

void arp_init(arp_ctx *ctx) {
	ctx->fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
	if (ctx->fd < 0)
		exit_errno("Can't create socket(PF_PACKET)");

	arp_setup_interface(ctx);
};

void arp_setup_interface(arp_ctx *ctx) {
	obtain_mac_from_if(ctx->mac, ctx->clientif);
	ctx->ifindex = if_nametoindex(ctx->clientif);

	struct sockaddr_ll lladdr = {
	    .sll_family = PF_PACKET,
	    .sll_protocol = htons(ETH_P_ARP),
	    .sll_ifindex = ctx->ifindex,
	    .sll_hatype = 0,
	    .sll_pkttype = PACKET_BROADCAST,
	    .sll_halen = ETH_ALEN,
	};

	while (bind(ctx->fd, (struct sockaddr *)&lladdr, sizeof(lladdr)) < 0) {
		perror("bind on arp fd failed, retrying");
	}

	log_verbose("initialized arp-fd (%i) on interface with index: %i\n", ctx->fd, ctx->ifindex);
}

void arp_interface_changed(arp_ctx *ctx, int type, const struct ifinfomsg *msg) {
	char ifname[IFNAMSIZ];

	if (if_indextoname(msg->ifi_index, ifname) == NULL)
		return;

	if (strcmp(ifname, ctx->clientif) != 0)
		return;

	log_verbose("arp interface change detected\n");

	switch (type) {
		case RTM_NEWLINK:
		case RTM_SETLINK:
			log_verbose("arp interface changed - NEW or SET\n");
			if (msg->ifi_index > 0 && ctx->ifindex != (size_t)msg->ifi_index) {
				log_verbose("re-initializing arp interface %s\n", ifname);
				arp_setup_interface(ctx);
			}
			break;

		case RTM_DELLINK:
			log_verbose("arp interfce not ok\n");
			break;
	}
}
