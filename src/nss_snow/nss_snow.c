/*	snow
	Copyright (C) 2012-2014 David Geib, Trustiosity LLC
	This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License Version 3
	(AGPLv3) with the following Supplemental Terms:
	
	A. Supplemental Terms. These supplemental terms are a part of the agreement
	and are not "further restrictions" under the AGPLv3. All licensees
	including all downstream licensees are subject to these supplemental terms.
	These supplemental terms also apply to anyone who propagates, receives or
	runs a copy of the Program notwithstanding Section 9 of the AGPLv3. 

	B. Governing Law; Venue. The laws of the State of Connecticut and the
	federal laws of the United States of America, without reference to conflict
	of law rules, govern this agreement and any dispute of any sort that might
	arise regarding this agreement or the Software. Any dispute relating in any
	way to this agreement or the Software where a party seeks aggregate relief
	of $500 or more, or an injunction or similar equitable relief, will be
	adjudicated in any state or federal court located in the State of
	Connecticut. You consent to exclusive jurisdiction and venue in those
	courts. The United Nations Convention for the International Sale of Goods
	does not apply to this agreement. 

	C. Export. You may not export the Software into any country or jurisdiction
	or receive or use the Software in any country or jurisdiction if doing so
	would be a violation of applicable law or could cause any licensor to be
	subject to civil or criminal liability or penalties in that or another
	country or jurisdiction. For example, you may not export the Software if
	doing so would violate United States Export Administration Regulations or
	International Traffic in Arms Regulations, or if the Software would
	infringe a proprietary right of a third party that is recognized in the
	jurisidiction in question. 
	
	This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include<stdio.h>
#include<netdb.h>
#include<nss.h>
#include<errno.h>
#include<string.h>

#include<unistd.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>


#ifndef NULL
#define NULL ((void*)0)
#endif

#ifndef DEBUG
#define DEBUG 0
#endif

// TODO: nsswitch.conf allows specifying that other sevices should not be attempted based on the response from earlier services
	// we might want to do something like [TRYAGAIN=return] for snow
	// and then always return TRY_AGAIN for any lookup failure for a name ending in ".key" or ".key."
	// that way a lookup failure for key names don't go to DNS just because the peer is offline


enum nss_status _nss_snow_sethostent(int stayopen)
{
	// do init (e.g. open files/sockets) for repeated calls, TODO: implement this (performance improvement)
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_snow_endhostent(void)
{
	// close sockets/files &c opened above
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_snow_gethostent_r(struct hostent * result, char * buf, size_t buflen, int *errnop, int *h_errnop)
{
	// get next host entry: just return NSS_STATUS_NOTFOUND
	*errnop = ENOENT;
	*h_errnop = HOST_NOT_FOUND;
	return NSS_STATUS_NOTFOUND;
	// TODO: possibly consider returning entries for already-connected hosts? (probably not: worsens information leak on multiuser machines)
}

static ssize_t nss_snow_get_response(const void* sendbuf, size_t sendbuf_size, void* recvbuf, size_t recvbuf_size, unsigned timeout_secs, int *errnop)
{
	ssize_t ret_val = -1;
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock >= 0) {
        struct timeval tv;
        tv.tv_sec = timeout_secs; tv.tv_usec = 0;
        if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0 && setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0) {
            struct sockaddr_in sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET;
            sa.sin_addr.s_addr = htonl(0x7f000001); // 127.0.0.1
            sa.sin_port = htons(8); // TODO: don't hard code port (or address)
            if(sendto(sock, sendbuf, sendbuf_size, 0, (struct sockaddr*)&sa, sizeof(sa)) == (ssize_t)sendbuf_size) {
                if((ret_val = recv(sock, recvbuf, recvbuf_size, 0)) <= 0)
                    if(DEBUG) perror("E: recv()");
            } else {
				if(DEBUG) perror("E: send()");
			}
        } else {
            if(DEBUG) perror("E: setsockopt()");
        }
        *errnop = errno; // set *errnop before calling close()
        close(sock);
	} else {
		if(DEBUG) perror("E: socket()");
		*errnop = errno;
	} 
	return ret_val;
}

/*
	h_errno possible values (from 'man h_errno'):
		HOST_NOT_FOUND: The specified host is unknown (NXDOMAIN?)
		NO_ADDRESS or NO_DATA: The requested name is valid but does not have an IP address (this might not ever be used here)
		NO_RECOVERY: A nonrecoverable name server error occurred
		TRY_AGAIN: A temporary error occurred on an authoritative name server. Try again later. 
*/
enum nss_status _nss_snow_gethostbyname_r(const char * name, struct hostent * result_buf, char * buf, size_t buflen, int *errnop, int *h_errnop)
{
	// TODO: probably no good reason be using AF_INET instead of AF_LOCAL here (and then could possibly authenticate snow user acct on the other end)
	if(DEBUG) printf("gethostbyname %s\n", name);
	const size_t IPv4ADDR_SIZE = 4;
	size_t namelen, bufneeded;
	if(NULL==name){
		if(DEBUG) printf("E: NULL==name\n");
		*errnop = ENOENT;
		*h_errnop = HOST_NOT_FOUND;
		return NSS_STATUS_NOTFOUND; 
	}
	namelen = strlen(name) + 1; // string length + '\0' 
	// return NOT FOUND if TLD is not ".key"
	if(namelen <= 6 || (strcasecmp(name+namelen-5, ".key") != 0 && strcasecmp(name+namelen-6, ".key."))) {
		if(DEBUG) printf("E: namelen or strcasecmp\n");
		*errnop = ENOENT;
		*h_errnop = HOST_NOT_FOUND;
		return NSS_STATUS_NOTFOUND; 
	}

	/* populate result_buf with the IPv4 address(es) of host named 'name'
	 (for pointers in struct hostent, point to memory inside user-supplied 'buf') */
	bufneeded =
		namelen // for h_name 
		// + sizeof(char*) // terminator for [empty] h_aliases (don't need, just use NULL terminator below) 
		+ sizeof(char*) // pointer to h_addr_list[0] 
		+ sizeof(char*) // NULL terminator for h_addr_list 
		+ IPv4ADDR_SIZE; // for sole entry of h_addr_list 
	if(bufneeded > buflen) {
		if(DEBUG) printf("E: buf too small\n");
		*errnop = ERANGE;
		*h_errnop = TRY_AGAIN;
		return NSS_STATUS_TRYAGAIN; // try again with bigger buffer 
	}

	result_buf->h_addr_list = (char**) buf;
	buf += sizeof(char*); // leave space for pointer to h_addr_list[0]
	result_buf->h_addr_list[1] = NULL; // list will have one entry, then NULL to terminate
	result_buf->h_aliases = (char**) buf; // no aliases: point to same NULL pointer
	buf += sizeof(char*); // space used by dual-purpose NULL pointer
	result_buf->h_name = buf; // will put name here
	result_buf->h_addrtype = AF_INET; // only one supported address family
	result_buf->h_length = IPv4ADDR_SIZE;
	
	enum nss_status ret_val = NSS_STATUS_UNAVAIL;
	ssize_t nbytes = nss_snow_get_response(name, namelen, buf, namelen + IPv4ADDR_SIZE, 90, errnop);
	if(nbytes != (ssize_t)(namelen + IPv4ADDR_SIZE)) {
		if(DEBUG) printf("size err: nbytes %ld wanted %ld\n", nbytes, namelen+IPv4ADDR_SIZE);
		if(*errnop == ETIMEDOUT) {
			ret_val = NSS_STATUS_TRYAGAIN;
			*h_errnop = TRY_AGAIN;
		}
	} else {
		if(strcmp(buf, name) != 0) {
			// some bug, data corruption or protocol mismatch
			if(DEBUG) printf("E: returned data does not match name\n");
		} else {
			buf += namelen;
			const unsigned char* addr = (const unsigned char*) buf;
			if(DEBUG) printf("Got result: %u.%u.%u.%u\n", addr[0], addr[1], addr[2], addr[3]);
			uint32_t zero = 0;
			if(memcmp(&zero, buf, sizeof(zero)) == 0) {
				// 0.0.0.0 signifies not found
				*errnop = ENOENT;
				*h_errnop = HOST_NOT_FOUND;
				ret_val = NSS_STATUS_NOTFOUND;
			} else {
				// IPv4 addr comes back right after name in return message
				result_buf->h_addr_list[0] = buf;
				result_buf->h_addr = buf;
				ret_val = NSS_STATUS_SUCCESS;
				// actually set address: just use this for testing 
				/*result_buf->h_addr[0] = 192;
				result_buf->h_addr[1] = 168;
				result_buf->h_addr[2] = 1;
				result_buf->h_addr[3] = 254;*/
			}
		}
	}
	if(ret_val == NSS_STATUS_UNAVAIL)
		*h_errnop = NO_RECOVERY;
	return ret_val;
}

// GNU extension that allows specifying address family (and so IPv6 resolution)
enum nss_status _nss_snow_gethostbyname2_r(const char *name, int af, struct hostent * result, char *buf, size_t buflen, int *errnop, int *h_errnop)
{
	// existing service only uses IPv4 NAT addresses right now
	if(af == AF_INET)
		return _nss_snow_gethostbyname_r(name, result, buf, buflen, errnop, h_errnop);
	*errnop = ENOENT;
	*h_errnop = HOST_NOT_FOUND;
	return NSS_STATUS_NOTFOUND;
}


// reverse lookups
enum nss_status _nss_snow_gethostbyaddr_r(const void *addr, socklen_t len, int af, struct hostent *result_buf, char *buf, size_t buflen, int *errnop, int *h_errnop)
{
	if(af != AF_INET || len != sizeof(struct in_addr)) {
		*errnop = ENOENT;
		*h_errnop = HOST_NOT_FOUND;
		return NSS_STATUS_NOTFOUND;
	}
	uint32_t nbo_ipaddr = ((const struct in_addr*)addr)->s_addr;
	enum nss_status ret_val = NSS_STATUS_UNAVAIL;
	// only 3 sec timeout because reverse lookups should be immediate or not there
	const unsigned timeout_secs = 3;
	ssize_t nbytes = nss_snow_get_response(&nbo_ipaddr, sizeof(nbo_ipaddr), buf, buflen, timeout_secs, errnop);
	if(nbytes <= 0) {
		// TODO: I think this might should really be EAGAIN/EWOULDBLOCK
		if(*errnop == ETIMEDOUT) {
			ret_val = NSS_STATUS_TRYAGAIN;
			*h_errnop = TRY_AGAIN;
		}
	} else {
		// see if buf was big enough
		const size_t IPv4ADDR_SIZE = 4;
		size_t namelen = strnlen(buf, nbytes) + 1/*'\0'*/;
		if(namelen == 1) {
			*errnop = ENOENT;
			*h_errnop = HOST_NOT_FOUND;
			ret_val = NSS_STATUS_NOTFOUND;
		} else {
			size_t bufneeded =
					namelen // for h_name
					+ sizeof(char*) // pointer to h_addr_list[0]
					+ sizeof(char*) // NULL terminator for h_addr_list
					+ IPv4ADDR_SIZE; // for entry of h_addr_list
			if(bufneeded > buflen) {
				if(DEBUG) printf("E: buf too small\n");
				*errnop = ERANGE;
				*h_errnop = TRY_AGAIN;
				ret_val = NSS_STATUS_TRYAGAIN; // try again with bigger buffer 
			} else {
				result_buf->h_name = buf;
				buf += namelen;
				char *addr_p = buf;
				if(memcmp(addr_p, &nbo_ipaddr, sizeof(nbo_ipaddr)) != 0) {
					if(DEBUG) printf("E: returned data does not match addr\n");
				} else {
					buf += IPv4ADDR_SIZE;
					result_buf->h_addr_list = (char**) buf;
					result_buf->h_addr = addr_p;
					result_buf->h_addr_list[0] = addr_p;
					result_buf->h_addr_list[1] = NULL;
					buf += sizeof(char*);
					result_buf->h_aliases = (char**) buf; // can reuse same NULL ptr from h_addr_list[1]
					result_buf->h_addrtype = AF_INET;
					result_buf->h_length = IPv4ADDR_SIZE;
					ret_val = NSS_STATUS_SUCCESS;
				}
			}
		}
	}
	if(ret_val == NSS_STATUS_UNAVAIL)
		*h_errnop = NO_RECOVERY;
	return ret_val;
}

#ifdef NSS_SNOW_MAIN_TEST
#include<arpa/inet.h>
int main(int argc, char** argv)
{
	if(argc < 2) { printf("Usage: %s [name.key]\n", argv[0]); return -1; }
	struct hostent he;
	char buf[5000];
	int h_errno_val, errno_val;
	if(_nss_snow_gethostbyname_r(argv[1], &he, buf, sizeof(buf), &errno_val, &h_errno_val) == NSS_STATUS_SUCCESS) {
		char addrstr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET, he.h_addr_list[0], addrstr, INET6_ADDRSTRLEN);
		printf("gethostbyname %s: %s\n", argv[1], addrstr);
		struct hostent result;
		_nss_snow_gethostbyaddr_r(he.h_addr_list[0], 4, AF_INET, &result, buf, sizeof(buf), &errno_val, &h_errno_val);
		printf("reverse lookup %s: %s\n", addrstr, result.h_name);
	} else {
		printf("_nss_snow_gethostbyname_r failed to get address for %s\n", argv[1]);
	}
	return 0;
}
#endif
