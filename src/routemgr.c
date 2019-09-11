/*
 * This file is part of project l3roamd. It's copyrighted by the contributors
 * recorded in the version control history of the file, available from
 * its original location https://github.com/freifunk-gluon/l3roamd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "routemgr.h"
#include "error.h"
#include "l3roamd.h"
#include "alloc.h"

#include <unistd.h>
#include "clientmgr.h"
#include "icmp6.h"
#include "if.h"
#include "util.h"

#include <sys/epoll.h>

static void rtnl_change_address(routemgr_ctx *ctx, struct in6_addr *address, int type, int flags);
static void rtnl_handle_link(const struct nlmsghdr *nh);

int parse_rtattr_flags(struct rtattr *tb[], int max, struct rtattr *rta, int len, unsigned short flags) {
	unsigned short type;

	while (RTA_OK(rta, len)) {
		type = rta->rta_type & ~flags;
		if ((type <= max) && (!tb[type])) {
			tb[type] = rta;
		}
		rta = RTA_NEXT(rta, len);
	}
	if (len)
		fprintf(stderr, "!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);
	return 0;
}

int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len) {
	return parse_rtattr_flags(tb, max, rta, len, 0);
}

void rtmgr_client_probe_addresses(struct client *client) {
	for (size_t i = 0; i < VECTOR_LEN(client->addresses); i++) {
		routemgr_probe_neighbor(&l3ctx.routemgr_ctx, client->ifindex, &VECTOR_INDEX(client->addresses, i).addr,
					client->mac);
	}
}

void rtmgr_client_remove_address(struct in6_addr *dst_address) {
	struct client *_client = NULL;
	log_debug("removing address %s\n", print_ip(dst_address));
	if (clientmgr_is_known_address(&l3ctx.clientmgr_ctx, dst_address, &_client)) {
		log_debug("removing address %s from client [%s]\n", print_ip(dst_address), print_mac(_client->mac));
		clientmgr_remove_address(&l3ctx.clientmgr_ctx, _client, dst_address);
		rtmgr_client_probe_addresses(_client);
	} else {
		log_debug("removal of address %s was scheduled but corresponding client could not be identified.\n",
			  print_ip(dst_address));
	}
}

void rtmgr_remove_addr_task(void *dst_address) {
	rtmgr_client_remove_address((struct in6_addr*)dst_address);
}

void copy_rtmgr_task(struct rtmgr_task *old, struct rtmgr_task *new) {
	memcpy(&new->address, &old->address, sizeof(struct in6_addr));
	new->retries_left = old->retries_left;
	new->family = old->family;
}

void schedule_rtmgr_retries(struct rtmgr_task *data, int ms_timeout, void (*processor)(void *data)) {
	struct rtmgr_task *ndata = l3roamd_alloc(sizeof(struct intercom_task));
	copy_rtmgr_task(data, ndata);
	ndata->retries_left--;

	post_task(&l3ctx.taskqueue_ctx, 0, ms_timeout, processor, free, ndata);
}

void send_ns_task(void *d) {
	struct rtmgr_task *td = d;

	log_debug("sending scheduled ns to %s\n", print_ip(&td->address));

	if (td->family == AF_INET) {
		arp_send_request(&l3ctx.arp_ctx, &td->address);
	} else {
		icmp6_send_solicitation(&l3ctx.icmp6_ctx, &td->address);
	}

	if (td->retries_left > 0)
		schedule_rtmgr_retries(td, 300, send_ns_task);
}

bool ns_retry(struct in6_addr *dst_address, int family) {
	struct rtmgr_task task_data;
	task_data.retries_left = 4;
	task_data.family = family;
	memcpy(&task_data.address, dst_address, sizeof(struct in6_addr));
	send_ns_task(&task_data);
	return true;
}

struct client *schedule_removal(struct in6_addr *dst_address) {
	struct client *client  = NULL;
	if (clientmgr_is_known_address(&l3ctx.clientmgr_ctx, dst_address, &client)) {
		struct client_ip *ip = NULL;
		ip = get_client_ip(client, dst_address);

		if (ip && !ip->removal_task) {
			log_debug("REMOVING (DELNEIGH/NUD_FAILED) %s [%s] in 2 Minutes.\n", print_ip(&ip->addr),
				  print_mac(client->mac));
			struct in6_addr *task_data_addr = l3roamd_alloc(sizeof(struct in6_addr));
			memcpy(task_data_addr, dst_address, sizeof(struct in6_addr));
			ip->removal_task =
			    post_task(&l3ctx.taskqueue_ctx, 120, 0, rtmgr_remove_addr_task, free, task_data_addr);
		}
		return client;
	}
	return NULL;
}

void rtnl_handle_neighbour(routemgr_ctx *ctx, const struct nlmsghdr *nh) {
	struct rtattr *tb[NDA_MAX + 1];
	memset(tb, 0, sizeof(struct rtattr *) * (NDA_MAX + 1));
	char mac_str[18] = {};
	char ip_str[INET6_ADDRSTRLEN] = {};

	struct ndmsg *msg = NLMSG_DATA(nh);
	parse_rtattr(tb, NDA_MAX, NDA_RTA(msg), nh->nlmsg_len - NLMSG_LENGTH(sizeof(*msg)));

	if (!(ctx->clientif.index == msg->ndm_ifindex || ctx->client_bridge.index == msg->ndm_ifindex))
		return;

	if (tb[NDA_LLADDR])
		memcpy(mac_str, print_mac(RTA_DATA(tb[NDA_LLADDR])), 18);
	else  // The only thing we could do without mac is send arp to an ip
		// address. whenever there is an ip, there is also a mac
		return;

	struct in6_addr dst_address = {};

	if (tb[NDA_DST]) {
		if (msg->ndm_family == AF_INET) {
			mapv4_v6(RTA_DATA(tb[NDA_DST]), &dst_address);
		} else {
			memcpy(&dst_address, RTA_DATA(tb[NDA_DST]), 16);
		}

		inet_ntop(AF_INET6, &dst_address, ip_str, INET6_ADDRSTRLEN);
	}

	char ifname[IFNAMSIZ + 1] = "";
	log_debug("neighbour [%s] (%s) changed on interface %s, type: %i, state: %i ... (msgif: %i cif: %i brif: %i)\n",
		  mac_str, ip_str, if_indextoname(msg->ndm_ifindex, ifname), nh->nlmsg_type, msg->ndm_state,
		  msg->ndm_ifindex, ctx->clientif.index,
		  ctx->client_bridge.index);  // see include/uapi/linux/neighbour.h NUD_REACHABLE for numeric values

	if ((nh->nlmsg_type == RTM_NEWNEIGH) && (msg->ndm_state & NUD_REACHABLE)) {
		log_debug("Status-Change to NUD_REACHABLE, notifying change for client-mac [%s]\n", mac_str);
		clientmgr_notify_mac(&l3ctx.clientmgr_ctx, RTA_DATA(tb[NDA_LLADDR]), msg->ndm_ifindex);
		if (tb[NDA_DST]) {
			log_debug("Status-Change to NUD_REACHABLE, ADDING address %s [%s]\n", ip_str, mac_str);
			clientmgr_add_address(&l3ctx.clientmgr_ctx, &dst_address, RTA_DATA(tb[NDA_LLADDR]), msg->ndm_ifindex);
		}
	} else if ((nh->nlmsg_type == RTM_NEWNEIGH) && (msg->ndm_state & ( NUD_PROBE | NUD_FAILED))) {
		log_debug("NEWNEIGH and NUD_PROBE or NUD_FAILED received - scheduling removal and attempting to re-activate %s [%s]\n",
			  ip_str, mac_str);
		if (schedule_removal(&dst_address)) {
			// we cannot directly use probe here because that would lead to an endless loop.
			log_debug(
			    "NEWNEIGH and either NUD_PROBE or NUD_FAILED received for one of our clients [%s] IPs (%s) - sending NS\n",
			    mac_str, ip_str);
			ns_retry(&dst_address, msg->ndm_family);
		}
		log_debug("ending handling of NUD_PROBE / NUD_FAILED\n");
	} else if (nh->nlmsg_type == RTM_DELNEIGH) {
		struct client *client = schedule_removal(&dst_address);
		if (client)
			rtmgr_client_probe_addresses(client);
	} else if (msg->ndm_state & NUD_NOARP) {
		log_debug("REMOVING (NOARP) %s [%s] now\n", ip_str, mac_str);
		rtmgr_client_remove_address(&dst_address);
	}
}

void client_bridge_changed(const struct nlmsghdr *nh, const struct ifinfomsg *msg) {
	struct rtattr *tb[IFLA_MAX + 1];
	memset(tb, 0, sizeof(struct rtattr *) * (IFLA_MAX + 1));
	char ifname[IFNAMSIZ];
	if (if_indextoname(msg->ifi_index, ifname) == 0)
		return;

	if (!strncmp(ifname, l3ctx.routemgr_ctx.client_bridge.ifname, strlen(ifname))) {
		parse_rtattr(tb, IFLA_MAX, IFLA_RTA(msg), nh->nlmsg_len - NLMSG_LENGTH(sizeof(*msg)));

		if (!tb[IFLA_ADDRESS]) {
			log_debug(
			    "client_bridge_changed called but mac could not be "
			    "extracted - ignoring event.\n");
			return;
		}

		if (!memcmp(RTA_DATA(tb[IFLA_ADDRESS]), l3ctx.routemgr_ctx.bridge_mac, 6)) {
			log_debug(
			    "client_bridge_changed called, change detected BUT "
			    "mac [%s] address is the mac of the bridge, not "
			    "triggering any client actions\n",
			    print_mac(RTA_DATA(tb[IFLA_ADDRESS])));
			return;
		}

		switch (nh->nlmsg_type) {
			case RTM_NEWLINK:
				log_verbose("new station [%s] found in fdb on interface %s\n",
					    print_mac(RTA_DATA(tb[IFLA_ADDRESS])), ifname);
				clientmgr_notify_mac(&l3ctx.clientmgr_ctx, RTA_DATA(tb[IFLA_ADDRESS]), msg->ifi_index);
				break;

			case RTM_SETLINK:
				log_verbose("set link %i\n", msg->ifi_index);
				break;

			case RTM_DELLINK:
				log_verbose("del link on %i, fdb-entry was removed for [%s].\n", msg->ifi_index,
					    print_mac(RTA_DATA(tb[IFLA_ADDRESS])));
				clientmgr_delete_client(&l3ctx.clientmgr_ctx, RTA_DATA(tb[IFLA_ADDRESS]));
				break;
		}
	}
}

void rtnl_handle_link(const struct nlmsghdr *nh) {
	const struct ifinfomsg *msg = NLMSG_DATA(nh);

	if (l3ctx.clientif_set)
		client_bridge_changed(nh, msg);

	interfaces_changed(nh->nlmsg_type, msg);
}

bool handle_kernel_routes(const struct nlmsghdr *nh, struct kernel_route *route) {
	int len = nh->nlmsg_len;
	struct rtmsg *rtm;

	rtm = (struct rtmsg *)NLMSG_DATA(nh);
	len -= NLMSG_LENGTH(0);

	/* Ignore cached routes, advertised by some kernels (linux 3.x). */
	if (rtm->rtm_flags & RTM_F_CLONED)
		return false;

	if (parse_kernel_route_rta(rtm, len, route) < 0)
		return false;

	/* Ignore default unreachable routes; no idea where they come from. */
	if (route->plen == 0 && route->metric >= KERNEL_INFINITY)
		return false;

	/* only interested in host routes */
	if ((route->plen != 128))
		return false;
	return true;
}

void rtnl_handle_msg(routemgr_ctx *ctx, const struct nlmsghdr *nh) {
	if (!nh || ctx->nl_disabled)
		return;

	switch (nh->nlmsg_type) {
		case RTM_NEWROUTE:
			//		case RTM_DELROUTE:
			log_debug("handling netlink message for route change\n");
			struct kernel_route route;
			if (handle_kernel_routes(nh, &route))
				if (clientmgr_valid_address(&l3ctx.clientmgr_ctx, &route.prefix))
					ipmgr_route_appeared(&l3ctx.ipmgr_ctx, &route.prefix);
			break;
		case RTM_NEWNEIGH:
		case RTM_DELNEIGH:
			log_debug("handling netlink message for neighbour change\n");
			rtnl_handle_neighbour(ctx, nh);
			break;
		case RTM_NEWLINK:
		case RTM_DELLINK:
		case RTM_SETLINK:
			log_debug("handling netlink message for link change\n");
			rtnl_handle_link(nh);
			break;
		default:
			log_debug("not handling unknown netlink message with type: %i\n", nh->nlmsg_type);
			return;
	}
}

/* obtain all neighbours by sending GETNEIGH request
**/
static void routemgr_initial_neighbours(routemgr_ctx *ctx, uint8_t family) {
	struct nlneighreq req = {.nl =
				     {
					 .nlmsg_type = RTM_GETNEIGH,
					 .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
					 .nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg)),
				     },
				 .nd =
				     {
					 .ndm_family = family,
				     }

	};
	rtmgr_rtnl_talk(ctx->fd, (struct nlmsghdr *)&req);
}

void routemgr_init(routemgr_ctx *ctx) {
	log_verbose("initializing routemgr\n");
	ctx->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, NETLINK_ROUTE);
	if (ctx->fd < 0)
		exit_error("can't open RTNL socket");

	struct sockaddr_nl snl = {
	    .nl_family = AF_NETLINK, .nl_groups = RTMGRP_IPV6_ROUTE | RTMGRP_LINK | RTMGRP_IPV4_ROUTE,
	};

	if (l3ctx.clientif_set)
		snl.nl_groups |= RTMGRP_NEIGH;

	if (bind(ctx->fd, (struct sockaddr *)&snl, sizeof(snl)) < 0)
		exit_error("can't bind RTNL socket");

	for (size_t i = 0; i < VECTOR_LEN(l3ctx.clientmgr_ctx.prefixes); i++) {
		struct prefix *prefix = &(VECTOR_INDEX(l3ctx.clientmgr_ctx.prefixes, i));
		log_verbose("Activating route for prefix %s/%i on device %s(%i) in main routing-table\n",
			    print_ip(&prefix->prefix), prefix->plen, l3ctx.ipmgr_ctx.ifname,
			    if_nametoindex(l3ctx.ipmgr_ctx.ifname));

		if (prefix->isv4) {
			struct in_addr ip4 = extractv4_v6(&prefix->prefix);
			log_verbose("ipv4: %s\n", print_ip4(&ip4));
			routemgr_insert_route4(ctx, 254, if_nametoindex(l3ctx.ipmgr_ctx.ifname), &ip4, prefix->plen - 96);
		} else
			routemgr_insert_route(ctx, 254, if_nametoindex(l3ctx.ipmgr_ctx.ifname),
					      (struct in6_addr *)(prefix->prefix.s6_addr), prefix->plen);
	}

	if (!l3ctx.clientif_set) {
		log_error("warning: we were started without -i - not initializing any client interfaces.\n");
		return;
	}


	obtain_mac_from_if(ctx->client_bridge.mac, ctx->client_bridge.ifname);

	ctx->clientif.index = if_nametoindex(ctx->clientif.ifname);
	ctx->client_bridge.index = if_nametoindex(ctx->client_bridge.ifname);

	routemgr_initial_neighbours(ctx, AF_INET);
	routemgr_initial_neighbours(ctx, AF_INET6);
}

int parse_kernel_route_rta(struct rtmsg *rtm, int len, struct kernel_route *route) {
	len -= NLMSG_ALIGN(sizeof(*rtm));

	memset(route, 0, sizeof(struct kernel_route));
	route->proto = rtm->rtm_protocol;

	for (struct rtattr *rta = RTM_RTA(rtm); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		switch (rta->rta_type) {
			case RTA_DST:
				if (rtm->rtm_family == AF_INET6) {
					route->plen = rtm->rtm_dst_len;
					memcpy(route->prefix.s6_addr, RTA_DATA(rta), 16);

				} else if (rtm->rtm_family == AF_INET) {
					struct in_addr ipv4;
					memcpy(&ipv4.s_addr, RTA_DATA(rta), 4);
					mapv4_v6(&ipv4, &route->prefix);
					route->plen = rtm->rtm_dst_len + 96;
				}
				log_debug("parsed route, found dst: %s\n", print_ip(&route->prefix));
				break;
			case RTA_SRC:
				if (rtm->rtm_family == AF_INET6) {
					route->src_plen = rtm->rtm_src_len;
					memcpy(route->src_prefix.s6_addr, RTA_DATA(rta), 16);
				} else if (rtm->rtm_family == AF_INET) {
					struct in_addr ipv4;
					memcpy(&ipv4.s_addr, RTA_DATA(rta), 4);
					mapv4_v6(&ipv4, &route->src_prefix);
					route->plen = rtm->rtm_src_len + 96;
				}
				break;
			case RTA_GATEWAY:
				if (rtm->rtm_family == AF_INET6) {
					memcpy(route->gw.s6_addr, RTA_DATA(rta), 16);
				} else if (rtm->rtm_family == AF_INET) {
					struct in_addr ipv4;
					memcpy(&ipv4.s_addr, RTA_DATA(rta), 4);
					mapv4_v6(&ipv4, &route->prefix);
				}
				break;
			case RTA_OIF:
				route->ifindex = *(int *)RTA_DATA(rta);
				break;
			case RTA_PRIORITY:
				route->metric = *(int *)RTA_DATA(rta);
				if (route->metric < 0 || route->metric > KERNEL_INFINITY)
					route->metric = KERNEL_INFINITY;
				break;
			default:
				break;
		}
	}

	return 1;
}

void routemgr_handle_in(routemgr_ctx *ctx, int fd) {
	log_debug("handling routemgr_in event ");
	ssize_t count;
	uint8_t readbuffer[8192];

	struct nlmsghdr *nh;
	struct nlmsgerr *ne;
	while (1) {
		count = recv(fd, readbuffer, sizeof readbuffer, 0);
		if ((count == -1) && (errno != EAGAIN)) {
			perror("read error");
			break;
		} else if (count == -1) {
			break;  // errno must be EAGAIN - we have read all data.
		} else if (count <= 0)
			break;  // TODO: shouldn't we re-open the fd in this
				// case?

		log_debug("read %zi Bytes from netlink socket, readbuffer-size is %zi, ... parsing data now.\n", count,
			  sizeof(readbuffer));

		nh = (struct nlmsghdr *)readbuffer;
		if (NLMSG_OK(nh, count)) {
			switch (nh->nlmsg_type) {
				case NLMSG_DONE:
					continue;
				case NLMSG_ERROR:
					perror("handling netlink error-message");
					ne = NLMSG_DATA(nh);
					if (ne->error <= 0)
						continue;
				/* Falls through. */
				default:
					rtnl_handle_msg(ctx, nh);
			}
		}
	}
}


int rtnl_addattr(struct nlmsghdr *n, int maxlen, int type, void *data, int datalen) {
	int len = RTA_LENGTH(datalen);
	struct rtattr *rta;
	if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen)
		return -1;
	rta = (struct rtattr *)(((char *)n) + NLMSG_ALIGN(n->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, datalen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;
	return 0;
}

void rtnl_add_address(routemgr_ctx *ctx, struct in6_addr *address) {
	log_debug("Adding special address to lo: %s\n", print_ip(address));
	rtnl_change_address(ctx, address, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL | NLM_F_REQUEST);
}

void rtnl_remove_address(routemgr_ctx *ctx, struct in6_addr *address) {
	rtnl_change_address(ctx, address, RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK);
}

void rtnl_change_address(routemgr_ctx *ctx, struct in6_addr *address, int type, int flags) {
	struct {
		struct nlmsghdr nl;
		struct ifaddrmsg ifa;
		char buf[1024];
	} req = {.nl =
		     {
			 .nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg)), .nlmsg_type = type, .nlmsg_flags = flags,
		     },
		 .ifa =
		     {
			 .ifa_family = AF_INET6,
			 .ifa_prefixlen = 128,
			 .ifa_index = 1,  // get the loopback index
			 .ifa_scope = 0,
		     }};

	rtnl_addattr(&req.nl, sizeof(req), IFA_LOCAL, address, sizeof(struct in6_addr));

	rtmgr_rtnl_talk(ctx->fd, (struct nlmsghdr *)&req);
}

void routemgr_probe_neighbor(routemgr_ctx *ctx, const int ifindex, struct in6_addr *address, uint8_t mac[ETH_ALEN]) {
	int family = AF_INET6;
	size_t addr_len = 16;
	void *addr = address->s6_addr;

	if (address_is_ipv4(address)) {
		log_debug("probing for IPv4-address! %s\n", print_ip(addr));
		addr = address->s6_addr + 12;
		addr_len = 4;
		family = AF_INET;
	} else {
		log_debug("probing for IPv6-address! %s\n", print_ip(address));
	}

	struct nlneighreq req = {
	    .nl =
		{
		    .nlmsg_type = RTM_NEWNEIGH,
		    .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
		    .nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg)),
		},
	    .nd =
		{
		    .ndm_family = family, .ndm_state = NUD_PROBE, .ndm_ifindex = ifindex,
		},
	};

	rtnl_addattr(&req.nl, sizeof(req), NDA_DST, (void *)addr, addr_len);
	rtnl_addattr(&req.nl, sizeof(req), NDA_LLADDR, mac, sizeof(uint8_t) * 6);

	rtmgr_rtnl_talk(ctx->fd, (struct nlmsghdr *)&req);
}

void routemgr_insert_neighbor(routemgr_ctx *ctx, const int ifindex, struct in6_addr *address, uint8_t mac[ETH_ALEN]) {
	struct nlneighreq req = {
	    .nl =
		{
		    .nlmsg_type = RTM_NEWNEIGH,
		    .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
		    .nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg)),
		},
	    .nd =
		{
		    .ndm_family = AF_INET6, .ndm_state = NUD_REACHABLE, .ndm_ifindex = ifindex,
		},
	};

	rtnl_addattr(&req.nl, sizeof(req), NDA_DST, (void *)address, sizeof(struct in6_addr));
	rtnl_addattr(&req.nl, sizeof(req), NDA_LLADDR, mac, sizeof(uint8_t) * 6);

	rtmgr_rtnl_talk(ctx->fd, (struct nlmsghdr *)&req);
}

void routemgr_remove_neighbor(routemgr_ctx *ctx, const int ifindex, struct in6_addr *address, uint8_t mac[ETH_ALEN]) {
	struct nlneighreq req = {
	    .nl =
		{
		    .nlmsg_type = RTM_DELNEIGH,
		    .nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE,
		    .nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg)),
		},
	    .nd = {.ndm_family = AF_INET6, .ndm_ifindex = ifindex, .ndm_flags = NTF_PROXY},
	};

	rtnl_addattr(&req.nl, sizeof(req), NDA_DST, (void *)address, sizeof(struct in6_addr));
	rtnl_addattr(&req.nl, sizeof(req), NDA_LLADDR, mac, sizeof(uint8_t) * 6);

	rtmgr_rtnl_talk(ctx->fd, (struct nlmsghdr *)&req);
}

void routemgr_insert_route(routemgr_ctx *ctx, const int table, const int ifindex, struct in6_addr *address,
			   const int prefix_length) {
	struct nlrtreq req = {
	    .nl =
		{
		    .nlmsg_type = RTM_NEWROUTE,
		    .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
		    .nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
		},
	    .rt = {.rtm_family = AF_INET6,
		   .rtm_table = table,
		   .rtm_protocol = ROUTE_PROTO,
		   .rtm_scope = RT_SCOPE_UNIVERSE,
		   .rtm_type = RTN_UNICAST,
		   .rtm_dst_len = prefix_length},
	};

	rtnl_addattr(&req.nl, sizeof(req), RTA_DST, (void *)address, sizeof(struct in6_addr));
	rtnl_addattr(&req.nl, sizeof(req), RTA_OIF, (void *)&ifindex, sizeof(ifindex));

	rtmgr_rtnl_talk(ctx->fd, (struct nlmsghdr *)&req);
}

void routemgr_remove_route(routemgr_ctx *ctx, const int table, struct in6_addr *address, const int prefix_length) {
	struct nlrtreq req1 = {
	    .nl =
		{
		    .nlmsg_type = RTM_NEWROUTE,
		    .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
		    .nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
		},
	    .rt = {.rtm_family = AF_INET6, .rtm_table = table, .rtm_type = RTN_THROW, .rtm_dst_len = prefix_length}};

	rtnl_addattr(&req1.nl, sizeof(req1), RTA_DST, (void *)address, sizeof(struct in6_addr));
	rtmgr_rtnl_talk(ctx->fd, (struct nlmsghdr *)&req1);

	struct nlrtreq req2 = {.nl =
				   {
				       .nlmsg_type = RTM_DELROUTE,
				       .nlmsg_flags = NLM_F_REQUEST,
				       .nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
				   },
			       .rt = {.rtm_family = AF_INET6, .rtm_table = table, .rtm_dst_len = prefix_length}};

	rtnl_addattr(&req2.nl, sizeof(req2), RTA_DST, (void *)address, sizeof(struct in6_addr));
	rtmgr_rtnl_talk(ctx->fd, (struct nlmsghdr *)&req2);
}

void rtmgr_rtnl_talk(int fd, struct nlmsghdr *req) {
	struct sockaddr_nl nladdr = {.nl_family = AF_NETLINK};

	struct iovec iov = {req, 0};
	struct msghdr msg = {&nladdr, sizeof(nladdr), &iov, 1, NULL, 0, 0};

	iov.iov_len = req->nlmsg_len;

	int count = 0;
	while (sendmsg(fd, &msg, 0) <= 0 && count < 5) {
		fprintf(stderr, "retrying(%i/5) ", ++count);
		perror("sendmsg on rtmgr_rtnl_talk()");
		if (errno == EBADF) {
			del_fd(l3ctx.efd, fd);
			close(fd);
			routemgr_init(&l3ctx.routemgr_ctx);
			add_fd(l3ctx.efd, l3ctx.routemgr_ctx.fd, EPOLLIN);
		}
	}
}

void routemgr_insert_neighbor4(routemgr_ctx *ctx, const int ifindex, struct in_addr *address, uint8_t mac[ETH_ALEN]) {
	struct nlneighreq req = {
	    .nl =
		{
		    .nlmsg_type = RTM_NEWNEIGH,
		    .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
		    .nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg)),
		},
	    .nd =
		{
		    .ndm_family = AF_INET, .ndm_state = NUD_REACHABLE, .ndm_ifindex = ifindex,
		},
	};

	rtnl_addattr(&req.nl, sizeof(req), NDA_DST, (void *)address, sizeof(struct in_addr));
	rtnl_addattr(&req.nl, sizeof(req), NDA_LLADDR, mac, sizeof(uint8_t) * 6);

	rtmgr_rtnl_talk(ctx->fd, (struct nlmsghdr *)&req);
}

void routemgr_remove_neighbor4(routemgr_ctx *ctx, const int ifindex, struct in_addr *address, uint8_t mac[ETH_ALEN]) {
	struct nlneighreq req = {
	    .nl =
		{
		    .nlmsg_type = RTM_NEWNEIGH,
		    .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
		    .nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg)),
		},
	    .nd =
		{
		    .ndm_family = AF_INET, .ndm_state = NUD_NONE, .ndm_ifindex = ifindex,
		},
	};

	rtnl_addattr(&req.nl, sizeof(req), NDA_DST, (void *)address, sizeof(struct in_addr));
	rtnl_addattr(&req.nl, sizeof(req), NDA_LLADDR, mac, sizeof(uint8_t) * 6);

	rtmgr_rtnl_talk(ctx->fd, (struct nlmsghdr *)&req);
}

void routemgr_insert_route4(routemgr_ctx *ctx, const int table, const int ifindex, struct in_addr *address,
			    const int plen) {
	struct nlrtreq req = {
	    .nl =
		{
		    .nlmsg_type = RTM_NEWROUTE,
		    .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
		    .nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
		},
	    .rt = {.rtm_family = AF_INET,
		   .rtm_table = table,
		   .rtm_protocol = ROUTE_PROTO,
		   .rtm_scope = RT_SCOPE_UNIVERSE,
		   .rtm_type = RTN_UNICAST,
		   .rtm_dst_len = plen},
	};

	rtnl_addattr(&req.nl, sizeof(req), RTA_DST, (void *)address, sizeof(struct in_addr));
	rtnl_addattr(&req.nl, sizeof(req), RTA_OIF, (void *)&ifindex, sizeof(ifindex));

	rtmgr_rtnl_talk(ctx->fd, (struct nlmsghdr *)&req);
}

void routemgr_remove_route4(routemgr_ctx *ctx, const int table, struct in_addr *address, const int plen) {
	struct nlrtreq req1 = {
	    .nl =
		{
		    .nlmsg_type = RTM_NEWROUTE,
		    .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
		    .nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
		},
	    .rt = {.rtm_family = AF_INET, .rtm_table = table, .rtm_type = RTN_THROW, .rtm_dst_len = plen}};

	rtnl_addattr(&req1.nl, sizeof(req1), RTA_DST, (void *)&address[12], sizeof(struct in_addr));
	rtmgr_rtnl_talk(ctx->fd, (struct nlmsghdr *)&req1);

	struct nlrtreq req2 = {.nl =
				   {
				       .nlmsg_type = RTM_DELROUTE,
				       .nlmsg_flags = NLM_F_REQUEST,
				       .nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
				   },
			       .rt = {.rtm_family = AF_INET, .rtm_table = table, .rtm_dst_len = 32}};

	rtnl_addattr(&req2.nl, sizeof(req2), RTA_DST, (void *)address, sizeof(struct in_addr));
	rtmgr_rtnl_talk(ctx->fd, (struct nlmsghdr *)&req2);
}
