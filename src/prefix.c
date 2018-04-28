/*
  Copyright (c) 2017,2018 Christof Schulze <christof.schulze@gmx.net>
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

#include "prefix.h"
#include <string.h>

#include "util.h"
#include <stdio.h>
/* this will parse the string str and return a prefix struct
*/
bool parse_prefix ( struct prefix *prefix, const char *str )
{
    char *saveptr;
    char *tmp = strdup ( str );

    prefix->isv4 = true;
    if ( strchr ( tmp, ':' ) )
        prefix->isv4 = false;

    log_debug ( "parsing prefix %s, ipv4-state: %i\n", str, prefix->isv4 );

    char *ptr = strtok_r ( tmp, "/", &saveptr );

    if ( prefix->isv4 ) {
        struct in_addr v4;
        if ( inet_pton ( AF_INET, ptr, &v4 ) != 1 )
            goto error;
        mapv4_v6 ( &v4, &prefix->prefix );
    } else {
        if ( inet_pton ( AF_INET6, ptr, &prefix->prefix ) != 1 )
            goto error;
    }
    ptr = strtok_r ( NULL, "/", &saveptr );
    if ( ptr == NULL )
        goto error;

    prefix->plen = atoi ( ptr );
    if ( prefix->isv4 )
        prefix->plen += 96;

    if ( prefix->plen < 0 || prefix->plen > 128 )
        goto error;

    free ( tmp );
    return true;

error:
    free ( tmp );
    return false;
}


/* this will add a prefix to the prefix vector, causing l3roamd  to
** accept packets to this prefix as client-prefix
*/
bool add_prefix ( void *prefixes, struct prefix _prefix )
{
    VECTOR ( struct prefix ) *_prefixes = prefixes;
    VECTOR_ADD ( *_prefixes, _prefix );

    return true;
}

/* this will remove a prefix from the prefix vector, causing l3roamd not to
** accept packets to this prefix as client-prefix
*/
bool del_prefix ( void *prefixes, struct prefix _prefix )
{
    VECTOR ( struct prefix ) *_prefixes = prefixes;
    for ( int i=0; i<VECTOR_LEN ( *_prefixes ); i++ ) {
        if ( !memcmp ( &VECTOR_INDEX ( *_prefixes, i ), &_prefix, sizeof ( _prefix ) ) ) {
            VECTOR_DELETE ( *_prefixes, i );
            return true;
        }
    }

    return false;
}

bool prefix_contains ( const struct prefix* prefix, const struct in6_addr* addr )
{
//     int offset=0;
//     if ( prefix->isv4 )  {
//         offset = 12; // ipv4 addresses are stored from the 12th byte onwards in an in6_addr
//     }

		log_debug("checking if prefix %s contains ", print_ip(&prefix->prefix));
		log_debug("address %s\n", print_ip(addr));

    int mask=0xff;
    for ( int remaining_plen = prefix->plen, i=0; remaining_plen > 0; remaining_plen-= 8 ) {
        if ( remaining_plen < 8 )
            mask = 0xff & ( 0xff00 >>remaining_plen );

        if ( ( addr->s6_addr[i ] & mask ) != prefix->prefix.s6_addr[i] )
            return false;
        i++;
    }
    return true;
}



