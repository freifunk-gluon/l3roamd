#include "routemgr.h"
#include "error.h"
#include "l3roamd.h"

#include "clientmgr.h"
#include "if.h"
#include <unistd.h>
#include "icmp6.h"
#include "util.h"

#include <sys/epoll.h>
#include <sys/ioctl.h>

static void rtnl_change_address ( routemgr_ctx *ctx, struct in6_addr *address, int type, int flags );
static void rtnl_handle_link ( const struct nlmsghdr *nh );
static int rtnl_addattr ( struct nlmsghdr *n, int maxlen, int type, void *data, int datalen );
static void rtmgr_rtnl_talk ( routemgr_ctx *ctx, struct nlmsghdr *req );

int parse_rtattr_flags ( struct rtattr *tb[], int max, struct rtattr *rta,
                         int len, unsigned short flags )
{
    unsigned short type;

    while ( RTA_OK ( rta, len ) ) {
        type = rta->rta_type & ~flags;
        if ( ( type <= max ) && ( !tb[type] ) ) {
            tb[type] = rta;
        }
        rta = RTA_NEXT ( rta,len );
    }
    if ( len )
        fprintf ( stderr, "!!!Deficit %d, rta_len=%d\n", len, rta->rta_len );
    return 0;
}

int parse_rtattr ( struct rtattr *tb[], int max, struct rtattr *rta, int len )
{
    return parse_rtattr_flags ( tb, max, rta, len, 0 );
}

void rtmgr_client_remove_address ( struct in6_addr *dst_address )
{
    struct client *_client = NULL;
    if ( clientmgr_is_known_address ( &l3ctx.clientmgr_ctx, dst_address, &_client ) ) {
        clientmgr_remove_address ( &l3ctx.clientmgr_ctx, _client, dst_address );
        for ( int i=0; i < VECTOR_LEN ( _client->addresses ); i++ ) {
            routemgr_probe_neighbor ( &l3ctx.routemgr_ctx, _client->ifindex, &VECTOR_INDEX ( _client->addresses, i ).addr, _client->mac );
        }
    }

}

void rtnl_handle_neighbour ( routemgr_ctx *ctx, const struct nlmsghdr *nh )
{
    struct rtattr * tb[NDA_MAX+1];
    memset ( tb, 0, sizeof ( struct rtattr * ) * ( NDA_MAX + 1 ) );
    char mac_str[18] = {};
    char ip_str[INET6_ADDRSTRLEN] = {};

    struct ndmsg *msg = NLMSG_DATA ( nh );
    parse_rtattr ( tb, NDA_MAX, NDA_RTA ( msg ), nh->nlmsg_len - NLMSG_LENGTH ( sizeof ( *msg ) ) );


    if ( ! ( ctx->clientif_index == msg->ndm_ifindex || ctx->client_bridge_index == msg->ndm_ifindex ) )
        return;

    if ( tb[NDA_LLADDR] )
        mac_addr_n2a ( mac_str, RTA_DATA ( tb[NDA_LLADDR] ) );

    struct in6_addr dst_address = {};

    if ( tb[NDA_DST] ) {
        if ( msg->ndm_family == AF_INET ) {
            mapv4_v6 ( RTA_DATA ( tb[NDA_DST] ), &dst_address );
        } else
            memcpy ( &dst_address, RTA_DATA ( tb[NDA_DST] ), 16 );

        inet_ntop ( AF_INET6, &dst_address, ip_str, INET6_ADDRSTRLEN );
    }


    if ( nh->nlmsg_type == RTM_NEWNEIGH && msg->ndm_state & NUD_REACHABLE && tb[NDA_LLADDR] ) {
        log_debug ( "Status-Change to NUD_REACHABLE, notifying change for client-mac [%s]\n", mac_str ) ;
        clientmgr_notify_mac ( CTX ( clientmgr ), RTA_DATA ( tb[NDA_LLADDR] ), msg->ndm_ifindex );
    }

    char ifname[IFNAMSIZ+1] = "";
    log_debug ( "neighbour [%s] (%s) changed on interface %s, type: %i, state: %i ... (msgif: %i cif: %i brif: %i)\n", mac_str, ip_str, if_indextoname ( msg->ndm_ifindex, ifname ), nh->nlmsg_type, msg->ndm_state, msg->ndm_ifindex, ctx->clientif_index, ctx->client_bridge_index ); // see include/uapi/linux/neighbour.h NUD_REACHABLE for numeric values

    if ( msg->ndm_state & NUD_REACHABLE ) {
        if ( nh->nlmsg_type == RTM_NEWNEIGH && tb[NDA_DST] && tb[NDA_LLADDR] ) {
            log_debug ( "Status-Change to NUD_REACHABLE, ADDING address %s [%s]\n", ip_str, mac_str ) ;
            clientmgr_add_address ( CTX ( clientmgr ), &dst_address, RTA_DATA ( tb[NDA_LLADDR] ), msg->ndm_ifindex );
        }
    } else if ( msg->ndm_state & NUD_FAILED ) {
        if ( nh->nlmsg_type == RTM_NEWNEIGH ) { // TODO: re-try sending NS if no NA is received
	    if (clientmgr_valid_address(&l3ctx.clientmgr_ctx, &dst_address)) {
                log_debug ( "NEWNEIGH & NUD_FAILED received - sending NS for ip %s [%s]\n", ip_str, mac_str );

                // we cannot directly use probe here because
                // that would lead to an endless loop.
                // TODO: let the kernel do the probing and
                // remember how often we where in this state
                // for each client. If that was >3 times,
                // remove client.
                if ( msg->ndm_family == AF_INET ) {
                    arp_send_request ( CTX ( arp ), &dst_address );
                } else {
                    icmp6_send_solicitation ( CTX ( icmp6 ), &dst_address );
                }
	    }
        } else if ( nh->nlmsg_type == RTM_DELNEIGH ) {
            log_debug ( "REMOVING (DELNEIGH) %s [%s]\n", ip_str, mac_str );
            rtmgr_client_remove_address ( &dst_address );
        }
    } else if ( msg->ndm_state & NUD_NOARP ) {
        log_debug ( "REMOVING (NOARP) %s [%s]\n", ip_str, mac_str );
        rtmgr_client_remove_address ( &dst_address );
    }
}

void client_bridge_changed ( const struct nlmsghdr *nh, const struct ifinfomsg *msg )
{
    struct rtattr * tb[IFLA_MAX+1];
    memset ( tb, 0, sizeof ( struct rtattr * ) * ( IFLA_MAX + 1 ) );
    char ifname[IFNAMSIZ];
    char str_mac[6*3];
    if ( if_indextoname ( msg->ifi_index,ifname ) == 0 )
        return;

    if ( !strncmp ( ifname,l3ctx.routemgr_ctx.client_bridge,strlen ( ifname ) ) ) {

        parse_rtattr ( tb, IFLA_MAX, IFLA_RTA ( msg ), nh->nlmsg_len - NLMSG_LENGTH ( sizeof ( *msg ) ) );

        if ( !tb[IFLA_ADDRESS] ) {
            printf ( "client_bridge_changed called but mac could not be extracted - ignoring event.\n" );
            return;
        }

        if ( !memcmp ( RTA_DATA ( tb[IFLA_ADDRESS] ), l3ctx.routemgr_ctx.bridge_mac, 6 ) ) {
            printf ( "client_bridge_changed called, change detected BUT mac [%s] address is the mac of the bridge, not triggering any client actions\n", str_mac );
            return;
        }

        mac_addr_n2a ( str_mac, RTA_DATA ( tb[IFLA_ADDRESS] ) );
        switch ( nh->nlmsg_type ) {
        case RTM_NEWLINK:
            printf ( "new station [%s] found in fdb on interface %s\n", str_mac, ifname );
            clientmgr_notify_mac ( &l3ctx.clientmgr_ctx, RTA_DATA ( tb[IFLA_ADDRESS] ), msg->ifi_index );
            break;

        case RTM_SETLINK:
            printf ( "set link %i\n", msg->ifi_index );
            break;

        case RTM_DELLINK:
            printf ( "del link %i\n", msg->ifi_index );
            printf ( "fdb-entry was removed for [%s].\n", str_mac ); // TODO: move client to old-queue
            break;
        }
    }

}

void rtnl_handle_link ( const struct nlmsghdr *nh )
{
    const struct ifinfomsg *msg = NLMSG_DATA ( nh );

    if ( l3ctx.clientif_set )
        client_bridge_changed ( nh, msg );

    interfaces_changed ( nh->nlmsg_type, msg );
}

void handle_kernel_routes ( routemgr_ctx *ctx, const struct nlmsghdr *nh )
{
    struct kernel_route route;
    int len = nh->nlmsg_len;
    struct rtmsg *rtm;

    rtm = ( struct rtmsg* ) NLMSG_DATA ( nh );
    len -= NLMSG_LENGTH ( 0 );

    /* Ignore cached routes, advertised by some kernels (linux 3.x). */
    if ( rtm->rtm_flags & RTM_F_CLONED )
        return;

    if ( parse_kernel_route_rta ( rtm, len, &route ) < 0 )
        return;

    /* Ignore default unreachable routes; no idea where they come from. */
    if ( route.plen == 0 && route.metric >= KERNEL_INFINITY )
        return;

    /* only interested in host routes */
    if ( ( route.plen != 128 ) )
        return;


    if ( clientmgr_valid_address ( &l3ctx.clientmgr_ctx, &route.prefix ) ) {
        ipmgr_route_appeared ( CTX ( ipmgr ), &route.prefix );
    }
}

void rtnl_handle_msg ( routemgr_ctx *ctx, const struct nlmsghdr *nh )
{
    if ( ctx->nl_disabled )
        return;

    switch ( nh->nlmsg_type ) {
    case RTM_NEWROUTE:
        //		case RTM_DELROUTE:
        log_debug ( "handling netlink message for route change\n" );
        handle_kernel_routes ( ctx, nh );
        break;
    case RTM_NEWNEIGH:
    case RTM_DELNEIGH:
        log_debug ( "handling netlink message for neighbour change\n" );
        rtnl_handle_neighbour ( ctx, nh );
        break;
    case RTM_NEWLINK:
    case RTM_DELLINK:
    case RTM_SETLINK:
        log_debug ( "handling netlink message for link change\n" );
        rtnl_handle_link ( nh );
        break;
    default:
        log_debug ( "not handling unknown netlink message with type: %i\n", nh->nlmsg_type );
        return;
    }
}

/* obtain all neighbours by sending GETNEIGH request
**/
static void routemgr_initial_neighbours ( routemgr_ctx *ctx, uint8_t family )
{
    struct nlneighreq req = {
        .nl = {
            .nlmsg_type = RTM_GETNEIGH,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
            .nlmsg_len = NLMSG_LENGTH ( sizeof ( struct ndmsg ) ),
        },
        .nd = {
            .ndm_family = family,
        }

    };
    rtmgr_rtnl_talk ( ctx, ( struct nlmsghdr * ) &req );
}

void routemgr_init ( routemgr_ctx *ctx )
{
    printf ( "initializing routemgr\n" );
    ctx->fd = socket ( AF_NETLINK, SOCK_RAW|SOCK_NONBLOCK, NETLINK_ROUTE );
    if ( ctx->fd < 0 )
        exit_error ( "can't open RTNL socket" );

    struct sockaddr_nl snl = {
        .nl_family = AF_NETLINK,
        .nl_groups = RTMGRP_IPV6_ROUTE | RTMGRP_LINK | RTMGRP_IPV4_ROUTE,
    };

    if ( l3ctx.clientif_set )
        snl.nl_groups |=  RTMGRP_NEIGH;

    if ( bind ( ctx->fd, ( struct sockaddr * ) &snl, sizeof ( snl ) ) < 0 )
        exit_error ( "can't bind RTNL socket" );

    for ( int i=0; i<VECTOR_LEN ( CTX ( clientmgr )->prefixes ); i++ ) {
        char str[INET6_ADDRSTRLEN+1];
        struct prefix *prefix = & ( VECTOR_INDEX ( CTX ( clientmgr )->prefixes, i ) );
        inet_ntop ( AF_INET6, prefix->prefix.s6_addr, str, INET6_ADDRSTRLEN );
        printf ( "Activating route for prefix %s/%i on device %s(%i) in main routing-table\n", str, prefix->plen, CTX ( ipmgr )->ifname, if_nametoindex ( CTX ( ipmgr )->ifname ) );
        if ( prefix->isv4 ) {
            struct in_addr ip4  = extractv4_v6 ( &prefix->prefix );
            printf("ipv4: %s\n",print_ip4(&ip4));
            routemgr_insert_route4 ( ctx, 254, if_nametoindex ( CTX ( ipmgr )->ifname ), &ip4, prefix->plen - 96 );
        } else
            routemgr_insert_route ( ctx, 254, if_nametoindex ( CTX ( ipmgr )->ifname ), ( struct in6_addr* ) ( prefix->prefix.s6_addr ), prefix->plen );
    }

    if ( !l3ctx.clientif_set ) {
        fprintf ( stderr, "warning: we were started without -i - not initializing any client interfaces.\n" );
        return;
    }
    // determine mac address of client-bridge
    memset ( ctx->bridge_mac, 0, 6 );
    struct ifreq req = {};
    strncpy ( req.ifr_name, ctx->client_bridge, IFNAMSIZ-1 );
    ioctl ( ctx->fd, SIOCGIFHWADDR, &req );
    memcpy ( ctx->bridge_mac, req.ifr_hwaddr.sa_data, 6 );

    if ( l3ctx.debug ) {
        char str_mac[18];
        mac_addr_n2a ( str_mac, ctx->bridge_mac );
        printf ( "extracted mac of client-bridge: %s\n",str_mac );
    }

    ctx->clientif_index = if_nametoindex ( ctx->clientif );
    ctx->client_bridge_index = if_nametoindex ( ctx->client_bridge );

    routemgr_initial_neighbours ( ctx, AF_INET );
    routemgr_initial_neighbours ( ctx, AF_INET6 );
}


int parse_kernel_route_rta ( struct rtmsg *rtm, int len, struct kernel_route *route )
{
    len -= NLMSG_ALIGN ( sizeof ( *rtm ) );

    memset ( route, 0, sizeof ( struct kernel_route ) );
    route->proto = rtm->rtm_protocol;

    for ( struct rtattr *rta = RTM_RTA ( rtm ); RTA_OK ( rta, len ); rta = RTA_NEXT ( rta, len ) ) {
        switch ( rta->rta_type ) {
        case RTA_DST:

            if ( rtm->rtm_family == AF_INET6 ) {
                route->plen = rtm->rtm_dst_len;
                memcpy ( route->prefix.s6_addr, RTA_DATA ( rta ), 16 );
                log_debug ( "parsed route, found dst: %s\n", print_ip ( &route->prefix ) );

            } else if ( rtm->rtm_family == AF_INET ) {
                struct in_addr ipv4;
                memcpy ( &ipv4.s_addr, RTA_DATA ( rta ), 4 );
                mapv4_v6 ( &ipv4, &route->prefix );
                route->plen = rtm->rtm_dst_len + 96;
                log_debug ( "parsed route, found dst: %s\n", print_ip ( &route->prefix ) );
            }
            break;
        case RTA_SRC:
            if ( rtm->rtm_family == AF_INET6 ) {
                route->src_plen = rtm->rtm_src_len;
                memcpy ( route->src_prefix.s6_addr, RTA_DATA ( rta ), 16 );
            } else if ( rtm->rtm_family == AF_INET ) {
                struct in_addr ipv4;
                memcpy ( &ipv4.s_addr, RTA_DATA ( rta ), 4 );
                mapv4_v6 ( &ipv4, &route->src_prefix );
                route->plen = rtm->rtm_src_len + 96;
            }
            break;
        case RTA_GATEWAY:
            if ( rtm->rtm_family == AF_INET6 ) {
                memcpy ( route->gw.s6_addr, RTA_DATA ( rta ), 16 );
            } else if ( rtm->rtm_family == AF_INET ) {
                struct in_addr ipv4;
                memcpy ( &ipv4.s_addr, RTA_DATA ( rta ), 4 );
                mapv4_v6 ( &ipv4, &route->prefix );
            }
            break;
        case RTA_OIF:
            route->ifindex = * ( int* ) RTA_DATA ( rta );
            break;
        case RTA_PRIORITY:
            route->metric = * ( int* ) RTA_DATA ( rta );
            if ( route->metric < 0 || route->metric > KERNEL_INFINITY )
                route->metric = KERNEL_INFINITY;
            break;
        default:
            break;
        }
    }

    return 1;
}

void routemgr_handle_in ( routemgr_ctx *ctx, int fd )
{
    if ( l3ctx.debug )
        printf ( "handling routemgr_in event " );
    ssize_t count;
    uint8_t readbuffer[8192];

    struct nlmsghdr *nh;
    struct nlmsgerr *ne;
    while ( 1 ) {
        count = recv ( fd, readbuffer, sizeof readbuffer, 0 );
        if ( ( count == -1 ) && ( errno != EAGAIN ) ) {
            perror ( "read error" );
            break;
        } else if ( count == -1 ) {
            break; // errno must be EAGAIN - we have read all data.
        } else if ( count <= 0 )
            break; // TODO: shouldn't we re-open the fd in this case?

        if ( l3ctx.debug )
            printf ( "read %zi Bytes from netlink socket, readbuffer-size is %zi, ... parsing data now.\n", count, sizeof ( readbuffer ) );

        nh = ( struct nlmsghdr * ) readbuffer;
        if ( NLMSG_OK ( nh, count ) )  {
            switch ( nh->nlmsg_type ) {
            case NLMSG_DONE:
                continue;
            case NLMSG_ERROR:
                perror ( "handling netlink error-message" );
                ne = NLMSG_DATA ( nh );
                if ( ne->error <= 0 )
                    continue;
		/* Falls through. */
            default:
                rtnl_handle_msg ( ctx, nh );
            }
        }
    }
}

int rtnl_addattr ( struct nlmsghdr *n, int maxlen, int type, void *data, int datalen )
{
    int len = RTA_LENGTH ( datalen );
    struct rtattr *rta;
    if ( NLMSG_ALIGN ( n->nlmsg_len ) + len > maxlen )
        return -1;
    rta = ( struct rtattr* ) ( ( ( char* ) n ) + NLMSG_ALIGN ( n->nlmsg_len ) );
    rta->rta_type = type;
    rta->rta_len = len;
    memcpy ( RTA_DATA ( rta ), data, datalen );
    n->nlmsg_len = NLMSG_ALIGN ( n->nlmsg_len ) + len;
    return 0;
}

void rtnl_add_address ( routemgr_ctx *ctx, struct in6_addr *address )
{
    log_debug ( "Adding special address to lo: %s\n", print_ip ( address ) );
    rtnl_change_address ( ctx, address, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL | NLM_F_REQUEST );
}

void rtnl_remove_address ( routemgr_ctx *ctx, struct in6_addr *address )
{
    rtnl_change_address ( ctx, address, RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK );
}

void rtnl_change_address ( routemgr_ctx *ctx, struct in6_addr *address, int type, int flags )
{
    struct {
        struct nlmsghdr nl;
        struct ifaddrmsg ifa;
        char buf[1024];
    } req = {
        .nl = {
            .nlmsg_len = NLMSG_LENGTH ( sizeof ( struct ifaddrmsg ) ),
            .nlmsg_type = type,
            .nlmsg_flags = flags,
        },
        .ifa = {
            .ifa_family = AF_INET6,
            .ifa_prefixlen = 128,
            .ifa_index = 1, // get the loopback index
            .ifa_scope = 0,
        }
    };

    rtnl_addattr ( &req.nl, sizeof ( req ), IFA_LOCAL, address, sizeof ( struct in6_addr ) );

    rtmgr_rtnl_talk ( ctx, ( struct nlmsghdr* ) &req );
}

void routemgr_probe_neighbor ( routemgr_ctx *ctx, const int ifindex, struct in6_addr *address, uint8_t mac[ETH_ALEN] )
{
    int family = AF_INET6;
    size_t addr_len = 16;
    void *addr = address->s6_addr;

    if ( address_is_ipv4 ( address ) ) {
        log_debug ( "probing for IPv4-address! %s\n", print_ip ( ( struct in6_addr* ) addr ) );
        addr = address->s6_addr + 12;
        addr_len = 4;
        family = AF_INET;
    } else {
        log_debug ( "probing for IPv6-address! %s\n", print_ip ( ( struct in6_addr* ) address ) );
    }

    struct nlneighreq req = {
        .nl = {
            .nlmsg_type = RTM_NEWNEIGH,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
            .nlmsg_len = NLMSG_LENGTH ( sizeof ( struct ndmsg ) ),
        },
        .nd = {
            .ndm_family = family,
            .ndm_state = NUD_PROBE,
            .ndm_ifindex = ifindex,
        },
    };

    rtnl_addattr ( &req.nl, sizeof ( req ), NDA_DST, ( void* ) addr, addr_len );
    rtnl_addattr ( &req.nl, sizeof ( req ), NDA_LLADDR, mac, sizeof ( uint8_t ) * 6 );

    rtmgr_rtnl_talk ( ctx, ( struct nlmsghdr* ) &req );
}

void routemgr_insert_neighbor ( routemgr_ctx *ctx, const int ifindex, struct in6_addr *address, uint8_t mac[ETH_ALEN] )
{
    struct nlneighreq req = {
        .nl = {
            .nlmsg_type = RTM_NEWNEIGH,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
            .nlmsg_len = NLMSG_LENGTH ( sizeof ( struct ndmsg ) ),
        },
        .nd = {
            .ndm_family = AF_INET6,
            .ndm_state = NUD_REACHABLE,
            .ndm_ifindex = ifindex,
        },
    };

    rtnl_addattr ( &req.nl, sizeof ( req ), NDA_DST, ( void* ) address, sizeof ( struct in6_addr ) );
    rtnl_addattr ( &req.nl, sizeof ( req ), NDA_LLADDR, mac, sizeof ( uint8_t ) * 6 );

    rtmgr_rtnl_talk ( ctx, ( struct nlmsghdr* ) &req );
}


void routemgr_remove_neighbor ( routemgr_ctx *ctx, const int ifindex, struct in6_addr *address, uint8_t mac[ETH_ALEN] )
{
    struct nlneighreq req = {
        .nl = {
            .nlmsg_type = RTM_DELNEIGH,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE,
            .nlmsg_len = NLMSG_LENGTH ( sizeof ( struct ndmsg ) ),
        },
        .nd = {
            .ndm_family = AF_INET6,
            .ndm_ifindex = ifindex,
            .ndm_flags = NTF_PROXY
        },
    };

    rtnl_addattr ( &req.nl, sizeof ( req ), NDA_DST, ( void* ) address, sizeof ( struct in6_addr ) );
    rtnl_addattr ( &req.nl, sizeof ( req ), NDA_LLADDR, mac, sizeof ( uint8_t ) * 6 );

    rtmgr_rtnl_talk ( ctx, ( struct nlmsghdr* ) &req );
}

void routemgr_insert_route ( routemgr_ctx *ctx, const int table, const int ifindex, struct in6_addr *address, const int prefix_length )
{
    struct nlrtreq req = {
        .nl = {
            .nlmsg_type = RTM_NEWROUTE,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
            .nlmsg_len = NLMSG_LENGTH ( sizeof ( struct rtmsg ) ),
        },
        .rt = {
            .rtm_family = AF_INET6,
            .rtm_table = table,
            .rtm_protocol = ROUTE_PROTO,
            .rtm_scope = RT_SCOPE_UNIVERSE,
            .rtm_type = RTN_UNICAST,
            .rtm_dst_len = prefix_length
        },
    };

    rtnl_addattr ( &req.nl, sizeof ( req ), RTA_DST, ( void* ) address, sizeof ( struct in6_addr ) );
    rtnl_addattr ( &req.nl, sizeof ( req ), RTA_OIF, ( void* ) &ifindex, sizeof ( ifindex ) );

    rtmgr_rtnl_talk ( ctx, ( struct nlmsghdr * ) &req );
}

void routemgr_remove_route ( routemgr_ctx *ctx, const int table, struct in6_addr *address, const int prefix_length )
{
    struct nlrtreq req1 = {
        .nl = {
            .nlmsg_type = RTM_NEWROUTE,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
            .nlmsg_len = NLMSG_LENGTH ( sizeof ( struct rtmsg ) ),
        },
        .rt = {
            .rtm_family = AF_INET6,
            .rtm_table = table,
            .rtm_type = RTN_THROW,
            .rtm_dst_len = prefix_length
        }
    };

    rtnl_addattr ( &req1.nl, sizeof ( req1 ), RTA_DST, ( void* ) address, sizeof ( struct in6_addr ) );
    rtmgr_rtnl_talk ( ctx, ( struct nlmsghdr * ) &req1 );

    struct nlrtreq req2 = {
        .nl = {
            .nlmsg_type = RTM_DELROUTE,
            .nlmsg_flags = NLM_F_REQUEST,
            .nlmsg_len = NLMSG_LENGTH ( sizeof ( struct rtmsg ) ),
        },
        .rt = {
            .rtm_family = AF_INET6,
            .rtm_table = table,
            .rtm_dst_len = 128
        }
    };

    rtnl_addattr ( &req2.nl, sizeof ( req2 ), RTA_DST, ( void* ) address, sizeof ( struct in6_addr ) );
    rtmgr_rtnl_talk ( ctx, ( struct nlmsghdr * ) &req2 );
}

static void rtmgr_rtnl_talk ( routemgr_ctx *ctx, struct nlmsghdr *req )
{
    struct sockaddr_nl nladdr = {
        .nl_family = AF_NETLINK
    };

    struct iovec iov = {req, 0};
    struct msghdr msg = {&nladdr, sizeof ( nladdr ), &iov, 1, NULL, 0, 0};

    iov.iov_len = req->nlmsg_len;

    int count=0;
    while ( sendmsg ( ctx->fd, &msg, 0 ) <= 0 && count < 5 ) {
        fprintf ( stderr, "retrying(%i/5) ", ++count );
        perror ( "sendmsg on rtmgr_rtnl_talk()" );
        if ( errno == EBADF ) {
            del_fd ( l3ctx.efd, ctx->fd );
            close ( ctx->fd );
            routemgr_init ( &l3ctx.routemgr_ctx );
            add_fd ( l3ctx.efd, l3ctx.routemgr_ctx.fd, EPOLLIN );
        }
    }
}


void routemgr_insert_neighbor4 ( routemgr_ctx *ctx, const int ifindex, struct in_addr *address, uint8_t mac[ETH_ALEN] )
{
    struct nlneighreq req = {
        .nl = {
            .nlmsg_type = RTM_NEWNEIGH,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
            .nlmsg_len = NLMSG_LENGTH ( sizeof ( struct ndmsg ) ),
        },
        .nd = {
            .ndm_family = AF_INET,
            .ndm_state = NUD_REACHABLE,
            .ndm_ifindex = ifindex,
        },
    };

    rtnl_addattr ( &req.nl, sizeof ( req ), NDA_DST, ( void* ) address, sizeof ( struct in_addr ) );
    rtnl_addattr ( &req.nl, sizeof ( req ), NDA_LLADDR, mac, sizeof ( uint8_t ) * 6 );

    rtmgr_rtnl_talk ( ctx, ( struct nlmsghdr* ) &req );
}

void routemgr_remove_neighbor4 ( routemgr_ctx *ctx, const int ifindex, struct in_addr *address, uint8_t mac[ETH_ALEN] )
{
    struct nlneighreq req = {
        .nl = {
            .nlmsg_type = RTM_NEWNEIGH,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
            .nlmsg_len = NLMSG_LENGTH ( sizeof ( struct ndmsg ) ),
        },
        .nd = {
            .ndm_family = AF_INET,
            .ndm_state = NUD_NONE,
            .ndm_ifindex = ifindex,
        },
    };

    rtnl_addattr ( &req.nl, sizeof ( req ), NDA_DST, ( void* ) address, sizeof ( struct in_addr ) );
    rtnl_addattr ( &req.nl, sizeof ( req ), NDA_LLADDR, mac, sizeof ( uint8_t ) * 6 );

    rtmgr_rtnl_talk ( ctx, ( struct nlmsghdr* ) &req );
}

void routemgr_insert_route4 ( routemgr_ctx *ctx, const int table, const int ifindex, struct in_addr *address , const int plen )
{

    struct nlrtreq req = {
        .nl = {
            .nlmsg_type = RTM_NEWROUTE,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
            .nlmsg_len = NLMSG_LENGTH ( sizeof ( struct rtmsg ) ),
        },
        .rt = {
            .rtm_family = AF_INET,
            .rtm_table = table,
            .rtm_protocol = ROUTE_PROTO,
            .rtm_scope = RT_SCOPE_UNIVERSE,
            .rtm_type = RTN_UNICAST,
            .rtm_dst_len = plen
        },
    };

    rtnl_addattr ( &req.nl, sizeof ( req ), RTA_DST, ( void* ) address, sizeof ( struct in_addr ) );
    rtnl_addattr ( &req.nl, sizeof ( req ), RTA_OIF, ( void* ) &ifindex, sizeof ( ifindex ) );

    rtmgr_rtnl_talk ( ctx, ( struct nlmsghdr * ) &req );
}

void routemgr_remove_route4 ( routemgr_ctx *ctx, const int table, struct in_addr *address, const int plen )
{
    struct nlrtreq req1 = {
        .nl = {
            .nlmsg_type = RTM_NEWROUTE,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
            .nlmsg_len = NLMSG_LENGTH ( sizeof ( struct rtmsg ) ),
        },
        .rt = {
            .rtm_family = AF_INET,
            .rtm_table = table,
            .rtm_type = RTN_THROW,
            .rtm_dst_len = plen
        }
    };

    rtnl_addattr ( &req1.nl, sizeof ( req1 ), RTA_DST, ( void* ) &address[12], sizeof ( struct in_addr ) );
    rtmgr_rtnl_talk ( ctx, ( struct nlmsghdr * ) &req1 );

    struct nlrtreq req2 = {
        .nl = {
            .nlmsg_type = RTM_DELROUTE,
            .nlmsg_flags = NLM_F_REQUEST,
            .nlmsg_len = NLMSG_LENGTH ( sizeof ( struct rtmsg ) ),
        },
        .rt = {
            .rtm_family = AF_INET,
            .rtm_table = table,
            .rtm_dst_len = 32
        }
    };

    rtnl_addattr ( &req2.nl, sizeof ( req2 ), RTA_DST, ( void* ) address, sizeof ( struct in_addr ) );
    rtmgr_rtnl_talk ( ctx, ( struct nlmsghdr * ) &req2 );
}
