/*
   Copyright (c) 2015, Nils Schneider <nils@nilsschneider.net>
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
   CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */

#include "version.h"
#include "vector.h"
#include "ipmgr.h"
#include "error.h"
#include "icmp6.h"
#include "routemgr.h"
#include "intercom.h"
#include "config.h"
#include "socket.h"
#include "prefix.h"
#include "l3roamd.h"
#include "types.h"
#include "alloc.h"
#include "util.h"

#define SIGTERM_MSG "Exiting. Removing routes for prefixes and clients.\n"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <fcntl.h>
#include <signal.h>

l3ctx_t l3ctx = {};




void sig_term_handler ( int signum, siginfo_t *info, void *ptr )
{
    write ( STDERR_FILENO, SIGTERM_MSG, sizeof ( SIGTERM_MSG ) );
    struct prefix _prefix = {};

    for ( int i=VECTOR_LEN ( l3ctx.clientmgr_ctx.prefixes ); i>0; i-- ) {
        del_prefix ( &l3ctx.clientmgr_ctx.prefixes, _prefix );
        routemgr_remove_route ( &l3ctx.routemgr_ctx, 254, ( struct in6_addr* ) ( _prefix.prefix.s6_addr ), _prefix.plen );
    }
    clientmgr_purge_clients ( &l3ctx.clientmgr_ctx );
    _exit ( EXIT_SUCCESS );
}

bool intercom_ready ( const int fd )
{
    for ( int j=VECTOR_LEN ( l3ctx.intercom_ctx.interfaces ) - 1; j>=0; j-- ) {
        if ( VECTOR_INDEX ( l3ctx.intercom_ctx.interfaces, j ).mcast_recv_fd == fd ) {
            log_debug ( "received intercom packet on one of the mesh interfaces\n" );
            return true;
        }
    }

    for ( int j=VECTOR_LEN ( l3ctx.clientmgr_ctx.clients ) - 1; j>=0; j-- ) {
        if ( VECTOR_INDEX ( l3ctx.clientmgr_ctx.clients, j ).fd == fd ) {
            log_debug ( "received intercom packet for a locally connected client\n" );
            return true;
        }
    }

    if ( l3ctx.intercom_ctx.unicast_nodeip_fd == fd ) {
        log_debug ( "received intercom packet for unicast_nodeip\n" );
        return true;
    }

    return false;
}

bool reconnect_fd ( int fd )
{
    del_fd ( l3ctx.efd, fd );
    char c;
    while (read(fd, &c , 1 ) > 0 );
    if (close ( fd ) < 0 )
	    perror("close");
    
    if ( fd == l3ctx.routemgr_ctx.fd ) {
        routemgr_init ( &l3ctx.routemgr_ctx );
        add_fd ( l3ctx.efd, l3ctx.routemgr_ctx.fd, EPOLLIN );
        return true;
    } else if ( fd == l3ctx.arp_ctx.fd ) {
        arp_init ( &l3ctx.arp_ctx );
        add_fd ( l3ctx.efd, l3ctx.arp_ctx.fd, EPOLLIN );
        return true;
    } else if ( fd == l3ctx.icmp6_ctx.fd ) {
        del_fd ( l3ctx.efd,l3ctx.icmp6_ctx.nsfd );
        close ( l3ctx.icmp6_ctx.nsfd );
        icmp6_init ( &l3ctx.icmp6_ctx );
        add_fd ( l3ctx.efd, l3ctx.icmp6_ctx.fd, EPOLLIN );
        add_fd ( l3ctx.efd, l3ctx.icmp6_ctx.nsfd, EPOLLIN );
        return true;
    } else if ( fd == l3ctx.icmp6_ctx.nsfd ) {
        del_fd ( l3ctx.efd,l3ctx.icmp6_ctx.fd );
        close ( l3ctx.icmp6_ctx.fd );
        icmp6_init ( &l3ctx.icmp6_ctx );
        add_fd ( l3ctx.efd, l3ctx.icmp6_ctx.fd, EPOLLIN );
        add_fd ( l3ctx.efd, l3ctx.icmp6_ctx.nsfd, EPOLLIN );
        return true;
    }
    return false;
}


void loop()
{
    int efd;
    int maxevents = 64;
    struct epoll_event *events;

    efd = epoll_create1 ( 0 );
    if ( efd == -1 ) {
        perror ( "epoll_create" );
        abort();
    }

    l3ctx.efd = efd;

    add_fd ( efd, l3ctx.ipmgr_ctx.fd, EPOLLIN );
    add_fd ( efd, l3ctx.routemgr_ctx.fd, EPOLLIN );
    add_fd ( efd, l3ctx.icmp6_ctx.unreachfd6, EPOLLIN );
    add_fd ( efd, l3ctx.icmp6_ctx.unreachfd4, EPOLLIN );
    add_fd ( efd, l3ctx.intercom_ctx.unicast_nodeip_fd, EPOLLIN );
    add_fd ( efd, l3ctx.taskqueue_ctx.fd, EPOLLIN );

    if ( l3ctx.clientif_set ) {
        printf ( "adding icmp6-fd to epoll\n" );
        add_fd ( efd, l3ctx.icmp6_ctx.fd, EPOLLIN );
        add_fd ( efd, l3ctx.icmp6_ctx.nsfd, EPOLLIN );

        printf ( "adding arp-fd to epoll\n" );
        add_fd ( efd, l3ctx.arp_ctx.fd, EPOLLIN );

        if ( l3ctx.wifistations_ctx.fd >= 0 )
            add_fd ( efd, l3ctx.wifistations_ctx.fd, EPOLLIN );
    }

    for ( int i=VECTOR_LEN ( l3ctx.intercom_ctx.interfaces ) - 1; i>=0; i-- ) {
        add_fd ( efd, VECTOR_INDEX ( l3ctx.intercom_ctx.interfaces, i ).mcast_recv_fd, EPOLLIN );
    }

    if ( l3ctx.socket_ctx.fd >= 0 )
        add_fd ( efd, l3ctx.socket_ctx.fd, EPOLLIN );

    /* Buffer where events are returned */
    events = l3roamd_alloc0_array ( maxevents, sizeof ( struct epoll_event ) );
    log_verbose ( "starting loop\n" );

    /* The event loop */
    while ( 1 ) {
        int n = epoll_wait ( efd, events, maxevents, -1 );
        for ( int i = 0; i < n; i++ ) {
            log_debug ( "handling event on fd %i. taskqueue.fd: %i routemgr: %i ipmgr: %i icmp6: %i icmp6.ns: %i arp: %i socket: %i, wifistations: %i, intercom_unicast_nodeip_fd: %i - ", events[i].data.fd, l3ctx.taskqueue_ctx.fd, l3ctx.routemgr_ctx.fd, l3ctx.ipmgr_ctx.fd, l3ctx.icmp6_ctx.fd, l3ctx.icmp6_ctx.nsfd, l3ctx.arp_ctx.fd, l3ctx.socket_ctx.fd, l3ctx.wifistations_ctx.fd, l3ctx.intercom_ctx.unicast_nodeip_fd );

            if ( ( events[i].events & EPOLLERR ) || ( events[i].events & EPOLLHUP ) || ( ! ( events[i].events & EPOLLIN ) ) ) {
                fprintf ( stderr, "epoll error received on fd %i. Dumping fd: taskqueue.fd: %i routemgr: %i ipmgr: %i icmp6: %i icmp6.ns: %i arp: %i socket: %i, wifistations: %i ... continuing\n", events[i].data.fd, l3ctx.taskqueue_ctx.fd, l3ctx.routemgr_ctx.fd, l3ctx.ipmgr_ctx.fd, l3ctx.icmp6_ctx.fd, l3ctx.icmp6_ctx.nsfd, l3ctx.arp_ctx.fd, l3ctx.socket_ctx.fd, l3ctx.wifistations_ctx.fd );
                if ( reconnect_fd ( events[i].data.fd ) )
                    continue;
                perror ( "epoll error without contingency plan. Exiting now." );
                sig_term_handler ( 0, 0, 0 );
            } else if ( l3ctx.wifistations_ctx.fd == events[i].data.fd ) {
                wifistations_handle_in ( &l3ctx.wifistations_ctx );
            } else if ( l3ctx.taskqueue_ctx.fd == events[i].data.fd ) {
                taskqueue_run ( &l3ctx.taskqueue_ctx );
            } else if ( l3ctx.routemgr_ctx.fd == events[i].data.fd ) {
                if ( events[i].events & EPOLLIN ) {
			log_debug ( " INBOUND\n" );
			routemgr_handle_in ( &l3ctx.routemgr_ctx, events[i].data.fd );
                } else {
			log_debug ( "\n" );
                }
            } else if ( l3ctx.ipmgr_ctx.fd == events[i].data.fd ) {
                if ( events[i].events & EPOLLIN )
                    ipmgr_handle_in ( &l3ctx.ipmgr_ctx, events[i].data.fd );
            } else if ( l3ctx.icmp6_ctx.unreachfd6 == events[i].data.fd ) {
                unsigned char trash[l3ctx.client_mtu];
                int amount = read ( l3ctx.icmp6_ctx.unreachfd6, trash, l3ctx.client_mtu ); // TODO: why do we even have to read here? This should be write-only
                log_debug ( "ignoring bogus data on unreachfd6, %i Bytes\n", amount );
            } else if ( l3ctx.icmp6_ctx.unreachfd4 == events[i].data.fd ) {
                unsigned char trash[l3ctx.client_mtu];
                int amount = read ( l3ctx.icmp6_ctx.unreachfd4, trash, l3ctx.client_mtu ); // TODO: why do we even have to read here? This should be write-only
                log_debug ( "ignoring bogus data on unreachfd4, %i Bytes\n", amount );
            } else if ( l3ctx.icmp6_ctx.fd == events[i].data.fd ) {
                if ( events[i].events & EPOLLIN )
                    icmp6_handle_in ( &l3ctx.icmp6_ctx, events[i].data.fd );
            } else if ( l3ctx.icmp6_ctx.nsfd == events[i].data.fd ) {
                if ( events[i].events & EPOLLIN )
                    icmp6_handle_ns_in ( &l3ctx.icmp6_ctx, events[i].data.fd );
            } else if ( l3ctx.arp_ctx.fd == events[i].data.fd ) {
                if ( events[i].events & EPOLLIN )
                    arp_handle_in ( &l3ctx.arp_ctx, events[i].data.fd );
            } else if ( l3ctx.socket_ctx.fd == events[i].data.fd ) {
                socket_handle_in ( &l3ctx.socket_ctx );
            } else if ( intercom_ready ( events[i].data.fd ) ) {
                log_debug ( "handling intercom event\n" );
                if ( events[i].events & EPOLLIN )
                    intercom_handle_in ( &l3ctx.intercom_ctx, events[i].data.fd );
            } else {
                char buffer[512];
                int tmp = read ( events[i].data.fd, buffer, 512 );
                printf ( "  WE JUST READ %i Byte from unknown socket %i with content %s - If this was 0 bytes, then this was a closed socket and everything is fine.\n", tmp, events[i].data.fd, buffer );
            }
        }
    }

    free ( events );
}

void usage()
{
    puts ( "Usage: l3roamd [-h] [-d] [-b <client-bridge>] -a <ip6> [-n <clatif>] -p <prefix> [-e <prefix>] [-i <clientif>] -m <meshif> ... -t <export table> [-4 prefix] [-D <devicename>]" );
    puts( "The order of options matters. -d and -4 should be specified first.\n");
    puts ( "  -a <ip6>           ip address of this node" );
    puts ( "  -b <client-bridge> this is the bridge where all clients are connected" );
    puts ( "  -d                 use debug logging" );
    puts ( "  -c <file>          configuration file" ); // TODO: do we really need this?
    puts ( "  -p <prefix>        Accept queries for this prefix. May be provided multiple times." );
    puts ( "  -P <prefix>        Defines the node-client prefix. Default: fec0::/64." );
    puts ( "  -e <prefix>        Defines the plat-prefix if this node is to be a local exit. This must be a /96" );
    puts ( "  -s <socketpath>    provide statistics and allow control using this socket. See below for usage instructions." );
    puts ( "  -i <clientif>      client interface" );
    puts ( "  -m <meshif>        mesh interface. may be specified multiple times" );
    puts ( "  -n <clatif>        clat-interface." );
    puts ( "  -t <export table>  export routes to this table" );
    puts ( "  -4 <prefix>        IPv4 translation prefix" );
    puts ( "  -V|--version       show version information" );
    puts ( "  -v                 verbose output" );
    puts ( "  -d                 debug output" );
    puts ( "  -D                 Device name for the l3roamd tun-device" );
    puts ( "  --no-netlink       do not use fdb or neighbour-table to learn new clients" );
    puts ( "  --no-ndp           do not use ndp to learn new clients" );
    puts ( "  --no-nl80211       do not use nl80211 to learn new clients" );
    puts ( "  -h|--help          this help\n" );

    puts ( "The socket will accept the following commands:" );
    puts ( "get_clients              The daemon will reply with a json structure, currently providing client count." );
    puts ( "get_prefixes             This return a list of all prefixes being handled by l3roamd." );
    puts ( "add_meshif <interface>   Add <interface> to mesh interfaces. Does the same as -m" );
    puts ( "del_meshif <interface>   Remove <interface> from mesh interfaces. Reverts add_meshif" );
    puts ( "add_prefix <prefix>      This will treat <prefix> as if it was added using -p" );
    puts ( "del_prefix <prefix>      This will remove <prefix> from the list of client-prefixes and stop accepting queries for clients within that prefix." );
    puts ( "add_address <addr> <mac> This will add the ipv6 address to the client represented by <mac>" );
    puts ( "del_address <addr> <mac> This will remove the ipv6 address from the client represented by <mac>" );
    puts ( "probe <addr> <mac>       This will start a neighbour discovery for a neighbour <mac> with address <addr>" );
}


void catch_sigterm()
{
    static struct sigaction _sigact;

    memset ( &_sigact, 0, sizeof ( _sigact ) );
    _sigact.sa_sigaction = sig_term_handler;
    _sigact.sa_flags = SA_SIGINFO;

    sigaction ( SIGTERM, &_sigact, NULL );
}

int main ( int argc, char *argv[] )
{
    char *socketpath = NULL;

    signal ( SIGPIPE, SIG_IGN );


    l3ctx.wifistations_ctx.l3ctx = &l3ctx;
    l3ctx.clientmgr_ctx.l3ctx = &l3ctx;
    l3ctx.intercom_ctx.l3ctx = &l3ctx;
    l3ctx.ipmgr_ctx.l3ctx = &l3ctx;
    l3ctx.routemgr_ctx.l3ctx = &l3ctx;
    l3ctx.socket_ctx.l3ctx = &l3ctx;
    l3ctx.taskqueue_ctx.l3ctx = &l3ctx;
    l3ctx.icmp6_ctx.l3ctx = &l3ctx;
    l3ctx.arp_ctx.l3ctx = &l3ctx;

    l3ctx.client_mtu = 1500;
    l3ctx.intercom_ctx.mtu = 1500;

    l3ctx.routemgr_ctx.client_bridge = strdup ( "\0" );
    l3ctx.routemgr_ctx.clientif = strdup ( "\0" );
    l3ctx.icmp6_ctx.clientif = strdup ( "\0" );
    l3ctx.arp_ctx.clientif = strdup ( "\0" );
    l3ctx.clientmgr_ctx.export_table = 254;
    bool v4_initialized = false;
    bool a_initialized = false;
    bool p_initialized = false;
    bool m_initialized = false;
    l3ctx.clientif_set = false;
    l3ctx.routemgr_ctx.nl_disabled = false;
    l3ctx.wifistations_ctx.nl80211_disabled = false;
    l3ctx.icmp6_ctx.ndp_disabled = false;

    l3ctx.verbose = false;
    l3ctx.debug = false;
    l3ctx.l3device = strdup ( "l3roam0" );

    struct prefix _tprefix = {};
    parse_prefix ( &_tprefix, "fec0::/64" );
    l3ctx.clientmgr_ctx.node_client_prefix = _tprefix;
    l3ctx.clientmgr_ctx.platprefix_set = false;

    parse_prefix ( &l3ctx.clientmgr_ctx.v4prefix, "0:0:0:0:0:ffff::/96" );
    l3ctx.arp_ctx.prefix = l3ctx.clientmgr_ctx.v4prefix.prefix;

    int option_index = 0;
    struct option long_options[] = {
        { "help",       0, NULL, 'h' },
        { "no-netlink",     0, NULL, 'F' },
        { "no-nl80211", 0, NULL, 'N' },
        { "no-ndp",     0, NULL, 'X' },
        { "version",     0, NULL, 'V' }
    };

    intercom_init ( &l3ctx.intercom_ctx );
    int c;
    while ( ( c = getopt_long ( argc, argv, "dhva:b:e:p:i:m:t:c:4:n:s:d:VD:P:", long_options, &option_index ) ) != -1 )
        switch ( c ) {
        case 'V':
            printf ( "l3roamd %s\n", SOURCE_VERSION );
#if defined(GIT_BRANCH) && defined(GIT_COMMIT_HASH)
            printf ( "branch: %s\n commit: %s\n", GIT_BRANCH, GIT_COMMIT_HASH );
#endif
            exit ( EXIT_SUCCESS );
        case 'b':
            free ( l3ctx.routemgr_ctx.client_bridge );
            l3ctx.routemgr_ctx.client_bridge = strdupa ( optarg );
            break;
        case 'h':
            usage();
            exit ( EXIT_SUCCESS );
        case 'a':
	    if (a_initialized)
		    exit_error( "-a must not be specified more than once");

            if ( inet_pton ( AF_INET6, optarg, &l3ctx.intercom_ctx.ip ) != 1 )
                exit_error ( "Can not parse IP address" );
	    intercom_init_unicast(&l3ctx.intercom_ctx);
            a_initialized=true;
            break;
        case 'c':
            //TODO: this is not implemented.
            parse_config ( optarg );
            break;
        case 'P':
            ;
            printf ( "parsing prefix %s\n",optarg );
            struct prefix _ncprefix = {};
            if ( !parse_prefix ( &_ncprefix, optarg ) )
                exit_error ( "Can not parse node-client-prefix that passed by -P" );
            l3ctx.clientmgr_ctx.node_client_prefix = _ncprefix;
            break;
        case 'p': {
            struct prefix _prefix = {};
            if ( !parse_prefix ( &_prefix, optarg ) ) {
                fprintf ( stderr, "prefix: %s - ", optarg );
                exit_error ( "Can not parse prefix" );
            }
            add_prefix ( &l3ctx.clientmgr_ctx.prefixes, _prefix );
            p_initialized=true;
        }
        break;
        case 'e': {
            struct prefix _prefix = {};
            if ( !parse_prefix ( &_prefix, optarg ) )
                exit_error ( "Can not parse PLAT-prefix" );
            if ( _prefix.plen != 96 )
                exit_error ( "PLAT-prefix must be /96" );

            l3ctx.clientmgr_ctx.platprefix = _prefix.prefix;
            l3ctx.clientmgr_ctx.platprefix_set = true;
        }
        break;
        case '4':
            if ( !parse_prefix ( &l3ctx.clientmgr_ctx.v4prefix, optarg ) )
                exit_error ( "Can not parse IPv4 prefix" );

            //if (l3ctx.clientmgr_ctx.v4prefix.plen != 96)
            //	exit_error("IPv4 prefix must be /96");

            l3ctx.arp_ctx.prefix = l3ctx.clientmgr_ctx.v4prefix.prefix;

            v4_initialized=true;
            break;
        case 'i':
            if ( if_nametoindex ( optarg ) && !l3ctx.clientif_set ) {
                free ( l3ctx.routemgr_ctx.clientif );
                free ( l3ctx.icmp6_ctx.clientif );
                free ( l3ctx.arp_ctx.clientif );
                l3ctx.routemgr_ctx.clientif = strdupa ( optarg );
                l3ctx.icmp6_ctx.clientif = strdupa ( optarg );
                l3ctx.arp_ctx.clientif = strdupa ( optarg );
                l3ctx.clientif_set=true;
            } else {
                fprintf ( stderr, "ignoring unknown client-interface %s or client-interface was already set. Only the first client-interface will be considered.\n", optarg );
            }
            break;
        case 'm':
	    intercom_add_interface ( &l3ctx.intercom_ctx, strdupa ( optarg ) );
	    m_initialized = true;
            break;
        case 't':
            l3ctx.clientmgr_ctx.export_table = atoi ( optarg );
            break;
        case 's':
            socketpath = optarg;
            break;
        case 'd':
            l3ctx.debug = true;
	    /* Falls through. */
        case 'v':
            l3ctx.verbose = true;
            break;
        case 'n':
            l3ctx.clientmgr_ctx.nat46ifindex = if_nametoindex ( optarg );
            break;
        case 'D':
            free ( l3ctx.l3device );
            l3ctx.l3device = strdupa ( optarg );
            break;
        case 'F':
            l3ctx.routemgr_ctx.nl_disabled = true;
            break;
        case 'N':
            l3ctx.icmp6_ctx.ndp_disabled = true;
            break;
        case 'X':
            l3ctx.wifistations_ctx.nl80211_disabled = true;
            break;
        default:
            fprintf ( stderr, "Invalid parameter %c ignored.\n", c );
        }

    if ( !v4_initialized ) {
        fprintf ( stderr, "-4 was not specified. Defaulting to 0:0:0:0:0:ffff::/96\n" );
        v4_initialized = true;
    }

    // clients have ll-addresses too
    struct prefix _prefix = {};
    parse_prefix ( &_prefix, "fe80::/64" );
    add_prefix ( &l3ctx.clientmgr_ctx.prefixes, _prefix );

    if ( !a_initialized )
        exit_error ( "specifying -a is mandatory" );
    if ( !p_initialized )
        exit_error ( "specifying -p is mandatory" );
    if ( !m_initialized )
        exit_error ( "specifying -m is mandatory" );

    catch_sigterm();

    socket_init ( &l3ctx.socket_ctx, socketpath );
    if ( !ipmgr_init ( &l3ctx.ipmgr_ctx, l3ctx.l3device, 9000 ) )
        exit_error ( "could not open the tun device for l3roamd. exiting now\n" );

    routemgr_init ( &l3ctx.routemgr_ctx );
    if ( l3ctx.clientif_set ) {
        wifistations_init ( &l3ctx.wifistations_ctx );
        arp_init ( &l3ctx.arp_ctx );
    }

    taskqueue_init ( &l3ctx.taskqueue_ctx );
    clientmgr_init();
    icmp6_init ( &l3ctx.icmp6_ctx );

    loop();

    return 0;
}
