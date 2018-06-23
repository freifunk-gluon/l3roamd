#include "error.h"
#include "ipmgr.h"
#include "timespec.h"
#include "if.h"
#include "intercom.h"
#include "l3roamd.h"
#include "util.h"
#include "alloc.h"
#include "packet.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_tun.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/in6.h>

static void seek_task ( void *d );
static void ipmgr_purge_task ( void *d );


static int entry_compare_by_address ( const struct unknown_address *a, const struct unknown_address *b )
{
	return memcmp ( &a->address, &b->address, sizeof ( struct in6_addr ) );
}


/* find an entry in the ipmgr's unknown-clients list*/
struct unknown_address *find_entry ( ipmgr_ctx *ctx, const struct in6_addr *k, int *elementindex )
{
	struct unknown_address key = { .address = *k};
	struct unknown_address *ret = VECTOR_LSEARCH ( &key, ctx->addrs, entry_compare_by_address );
	if ( ret != NULL && elementindex != NULL )
		*elementindex = ( ( void* ) ret - ( void* ) &VECTOR_INDEX ( ctx->addrs, 0 ) ) / sizeof ( struct unknown_address );
	log_debug ( "%s is on the unknown-clients list", print_ip ( k ) );
	if ( elementindex )
		log_debug ( " on index %i", *elementindex );
	log_debug ( "\n" );
	return ret;
}


struct unknown_address *add_entry ( const struct in6_addr *dst )
{
	struct unknown_address e = {
		.address = *dst
	};

	return VECTOR_ADD ( l3ctx.ipmgr_ctx.addrs, e );
}

/** This will remove an entry from the ipmgr unknown-clients list */
void delete_entry ( const struct in6_addr *k )
{
	int i;
	find_entry ( &l3ctx.ipmgr_ctx, k, &i );
	VECTOR_DELETE ( ( &l3ctx.ipmgr_ctx )->addrs, i );
}

struct ns_task *create_ns_task ( struct in6_addr *dst, struct timespec tv, int retries, bool force ) {
	struct ns_task *task = l3roamd_alloc ( sizeof ( struct ns_task ) ); //should this be aligned?

	if (retries < 0 )
		retries = -1;

	task->interval = tv;
	task->ctx = &l3ctx.ipmgr_ctx;
	task->retries_left = retries;
	task->force = force;
	memcpy ( &task->address, dst, sizeof ( struct in6_addr ) );
	return task;
}

struct ip_task *create_task ( struct in6_addr *dst )
{
	struct ip_task *task = l3roamd_alloc ( sizeof ( struct ip_task ) ); //should this be aligned?

	task->ctx = &l3ctx.ipmgr_ctx;
	memcpy ( &task->address, dst, sizeof ( struct in6_addr ) );
	return task;
}

taskqueue_t *schedule_purge_task ( struct in6_addr *destination, int timeout )
{
	struct ip_task *purge_data = create_task ( destination );
	return post_task ( &l3ctx.taskqueue_ctx, timeout, 0, ipmgr_purge_task, free, purge_data );
}

/** This will seek an address by checking locally and if needed querying the network by scheduling a task */
void ipmgr_seek_address ( ipmgr_ctx *ctx, struct in6_addr *addr )
{
	struct timespec interval = {
		.tv_sec = SEEK_INTERVAL,
		.tv_nsec = 0,
	};
	struct ns_task *ns_data = create_ns_task ( addr, interval, -1, false);
	post_task ( CTX ( taskqueue ), 0, 0, ipmgr_ns_task, free, ns_data );

	// schedule an intercom-seek operation that in turn will only be executed if there is no local client known
	struct ip_task *data = create_task ( addr );
	post_task ( CTX ( taskqueue ), 0, 300, seek_task, free, data );
}


static bool ismulticast ( const struct in6_addr *addr )
{
	if ( address_is_ipv4 ( addr ) ) {
		if ( addr->s6_addr[12] >= 224 && addr->s6_addr[12] < 240 )
			return true;
	} else {
		if ( addr->s6_addr[0] == 0xff )
			return true;
	}
	return false;
}

static void handle_packet ( ipmgr_ctx *ctx, uint8_t packet[], ssize_t packet_len )
{
	struct in6_addr dst = packet_get_dst ( packet );

	if ( ismulticast ( &dst ) )
		return;

	if ( !clientmgr_valid_address ( CTX ( clientmgr ), &dst ) ) {
		log_verbose ( "The destination of the packet (%s) is not within the client prefixes. Ignoring packet\n", print_ip( &dst ) );
		return;
	}

	struct in6_addr src = packet_get_src ( packet );
	log_verbose ( "Got packet from %s ", print_ip ( &src ) );
	log_verbose ( "destined to %s\n", print_ip ( &dst ) );


	struct timespec now;
	clock_gettime ( CLOCK_MONOTONIC, &now );

	struct unknown_address *e = find_entry ( ctx, &dst, NULL );

	bool new_unknown_dst = !e;

	if ( new_unknown_dst )
		e = add_entry ( &dst );


	struct packet p;

	p.timestamp = now;
	p.len = packet_len;
	p.data = l3roamd_alloc ( packet_len );

	memcpy ( p.data, packet, packet_len );

	VECTOR_ADD ( e->packets, p );

	if ( new_unknown_dst ) {
		ipmgr_seek_address ( ctx, &dst );
		e->check_task = schedule_purge_task ( &dst, PACKET_TIMEOUT );
	}
}

static bool should_we_really_seek ( struct in6_addr *destination, bool force)
{
	struct client *client = NULL;
	struct unknown_address *e = find_entry ( &l3ctx.ipmgr_ctx, destination, NULL );
	// if a route to this client appeared, the queue will be emptied -- no seek necessary
	if ( !e ) {
		log_debug ( "seek task was scheduled but no packets to be delivered to host: %s\n",  print_ip ( destination ) );
		if ( force  &&  ( ! clientmgr_is_known_address ( &l3ctx.clientmgr_ctx, destination, &client ) ) ) {
			log_debug ( "seeking because we do not know this IP yet: %s\n", print_ip ( destination ) );
			return true;
		}
		else {
			return false;
		}
	}

	if ( clientmgr_is_known_address ( &l3ctx.clientmgr_ctx, destination, &client ) && client_is_active ( client ) ) {
		log_error ( "ERROR: seek task was scheduled, there are packets to be delivered to the host: %s, which is a known client. This should never happen. Flushing packets for this destination\n", print_ip ( destination ) );
		ipmgr_route_appeared ( &l3ctx.ipmgr_ctx, destination );

		return false;
	}

	return true;
}

static void remove_packet_from_vector ( struct unknown_address *entry, int element )
{
	struct packet p = VECTOR_INDEX ( entry->packets, element );

	free ( p.data );

	VECTOR_DELETE ( entry->packets, element );
}

static int purge_old_packets ( struct in6_addr *destination )
{
	int elementindex = 0;
	struct unknown_address *e = find_entry ( &l3ctx.ipmgr_ctx, destination, &elementindex );

	if ( !e )
		return 0;

	struct timespec now;
	if ( clock_gettime ( CLOCK_MONOTONIC, &now ) < 0 ) {
		perror ( "clock_gettime" );
		return -1; //skip this purging-cycle
	}

	struct timespec then = {
		.tv_sec = now.tv_sec - PACKET_TIMEOUT,
		.tv_nsec = now.tv_nsec
	};

	for ( int i = VECTOR_LEN ( e->packets ) - 1; i>=0; i-- ) {
		struct packet p = VECTOR_INDEX ( e->packets, i );
		if ( timespec_cmp ( p.timestamp, then ) <= 0 ) {
			log_debug ( "deleting old packet with destination %s\n", print_ip ( &e->address ) );

			struct in6_addr src = packet_get_src ( p.data );
			// TODO run arp request here if src is an ipv4 address
			if ( !address_is_ipv4 ( &src ) )
				icmp6_send_dest_unreachable ( &src, &p );
			remove_packet_from_vector ( e, i );
		}
	}

	if ( VECTOR_LEN ( e->packets ) == 0 ) {
		VECTOR_FREE ( e->packets );
		VECTOR_DELETE ( l3ctx.ipmgr_ctx.addrs, elementindex );
		return 0;
	}

	return VECTOR_LEN ( e->packets );
}


void ipmgr_purge_task ( void *d )
{
	struct ip_task *data = d;
	struct unknown_address *e = find_entry ( &l3ctx.ipmgr_ctx, &data->address, NULL );
	if ( purge_old_packets ( &data->address ) )
		e->check_task = schedule_purge_task ( &data->address, 1 );
}

void ipmgr_ns_task ( void *d )
{
	struct ns_task *data = d;

	if ( ! l3ctx.clientif_set )
		return;

	if ( ! should_we_really_seek ( &data->address, data->force ) )
		return;

	log_error ( "\x1b[36mLooking for %s locally\x1b[0m\n", print_ip( &data->address ) );
	log_debug ( "ns_task: force = %i\n", data->force);

	if ( address_is_ipv4 ( &data->address ) )
		arp_send_request ( &l3ctx.arp_ctx, &data->address );
	else
		icmp6_send_solicitation ( &l3ctx.icmp6_ctx, &data->address );

	if ( !! data->retries_left ) {
		struct ns_task *ns_data = create_ns_task ( &data->address, data->interval, data->retries_left -1, data->force );
		post_task ( &l3ctx.taskqueue_ctx, data->interval.tv_sec, data->interval.tv_nsec, ipmgr_ns_task, free, ns_data );
	}
}

void seek_task ( void *d )
{
	struct ip_task *data = d;

	if ( should_we_really_seek ( &data->address, false) ) {
		printf ( "\x1b[36mseeking on intercom for client with the address %s\x1b[0m\n", print_ip ( &data->address ) );

		intercom_seek ( &l3ctx.intercom_ctx, ( const struct in6_addr* ) & ( data->address ) );

		struct ip_task *_data = create_task ( &data->address );
		post_task ( &l3ctx.taskqueue_ctx, SEEK_INTERVAL, 0, seek_task, free, _data );
	}
}

void ipmgr_handle_in ( ipmgr_ctx *ctx, int fd )
{
	ssize_t count;
	uint8_t buf[l3ctx.client_mtu];
	log_debug ( "handling ipmgr event\n" );

	while ( 1 ) {
		count = read ( fd, buf, sizeof ( buf ) );

		if ( count == -1 ) {
			/* If errno == EAGAIN, that means we have read all data. So go back to the main loop. */
			if ( errno != EAGAIN )
				perror ( "read" );
			break;
		} else if ( count == 0 ) {
			/* End of file. The remote has closed the connection. */
			break;
		}

		handle_packet ( ctx, buf, count );
	}
}

void ipmgr_handle_out ( ipmgr_ctx *ctx, int fd )
{
	struct timespec now, then;

	while ( VECTOR_LEN ( ctx->output_queue ) > 0 ) {

		struct packet *packet = &VECTOR_INDEX ( ctx->output_queue, 0 );

		// TODO: handle ipv4 packets correctly
		if ( write ( fd, packet->data, packet->len ) == -1 ) {
			if ( errno != EAGAIN )
				perror ( "Could not send packet to newly visible client, discarding this packet." );
			else {
				clock_gettime ( CLOCK_MONOTONIC, &now );
				then = now;
				then.tv_sec -= PACKET_TIMEOUT;
				perror ( "Could not send packet to newly visible client." );
				if ( timespec_cmp ( packet->timestamp, then ) <= 0 ) {
					log_error ( "could not send packet - packet is still young enough, requeueing\n" );
					// TODO: consider if output_queue
					// really is the correct queue when
					// requeueing
					VECTOR_ADD ( ctx->output_queue, *packet );
				} else {
					log_error ( "could not send packet - packet is too old, discarding.\n" );
				}
			}

			break;
		} else {
			// write was successful, free data structures
			free ( packet->data );
		}
		VECTOR_DELETE ( ctx->output_queue, 0 );
	}
}

void ipmgr_route_appeared ( ipmgr_ctx *ctx, const struct in6_addr *destination )
{
	struct unknown_address *e = find_entry ( ctx, destination, NULL );

	if ( !e ) {
		//        log_debug ( "route appeared for client %s, which is not on the unknown-list.\n", print_ip ( destination ) );
		return;
	}

	for ( int i = 0; i < VECTOR_LEN ( e->packets ); i++ ) {
		struct packet p = VECTOR_INDEX ( e->packets, i );
		VECTOR_ADD ( ctx->output_queue, p );
	}

	VECTOR_FREE ( e->packets );

	delete_entry ( destination );

	ipmgr_handle_out ( ctx, ctx->fd );
}

/* open l3roamd's tun device that is used to obtain packets for unknown clients */
static bool tun_open ( ipmgr_ctx *ctx, const char *ifname, uint16_t mtu, const char *dev_name )
{
	int ctl_sock = -1;
	struct ifreq ifr = {};

	ctx->fd = open ( dev_name, O_RDWR|O_NONBLOCK );
	if ( ctx->fd < 0 )
		exit_errno ( "could not open TUN/TAP device file" );

	if ( ifname )
		strncpy ( ifr.ifr_name, ifname, IFNAMSIZ-1 );

	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	if ( ioctl ( ctx->fd, TUNSETIFF, &ifr ) < 0 ) {
		puts ( "unable to open TUN/TAP interface: TUNSETIFF ioctl failed" );
		goto error;
	}

	ctx->ifname = strndup ( ifr.ifr_name, IFNAMSIZ-1 );

	ctl_sock = socket ( PF_INET, SOCK_DGRAM, IPPROTO_UDP );
	if ( ctl_sock < 0 )
		exit_errno ( "socket" );

	if ( ioctl ( ctl_sock, SIOCGIFMTU, &ifr ) < 0 )
		exit_errno ( "SIOCGIFMTU ioctl failed" );

	if ( ifr.ifr_mtu != mtu ) {
		ifr.ifr_mtu = mtu;
		if ( ioctl ( ctl_sock, SIOCSIFMTU, &ifr ) < 0 ) {
			puts ( "unable to set TUN/TAP interface MTU: SIOCSIFMTU ioctl failed" );
			goto error;
		}
	}

	ifr.ifr_flags = IFF_UP | IFF_RUNNING| IFF_MULTICAST | IFF_NOARP | IFF_POINTOPOINT;
	if ( ioctl ( ctl_sock, SIOCSIFFLAGS, &ifr ) < 0 )
		exit_errno ( "unable to set TUN/TAP interface UP: SIOCSIFFLAGS ioctl failed" );

	if ( close ( ctl_sock ) )
		puts ( "close of ctl_sock failed." );

	return true;

error:
	if ( ctl_sock >= 0 ) {
		if ( close ( ctl_sock ) )
			puts ( "close" );
	}
	free ( ctx->ifname );

	close ( ctx->fd );
	ctx->fd = -1;
	return false;
}

bool ipmgr_init ( ipmgr_ctx *ctx, char *tun_name, unsigned int mtu )
{
	return tun_open ( ctx, tun_name, mtu, "/dev/net/tun" );
}
