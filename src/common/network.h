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

#ifndef NETWORK_H
#define NETWORK_H
#include<list>
#include<vector>
#include<string>
#include<cstring>
#ifdef WINSOCK
#include<Winsock2.h>
#include<in6addr.h>
#include<Ws2tcpip.h>
#define in_port_t uint16_t
#else
#include<arpa/inet.h>
#include<poll.h>
#endif

const uint8_t ip4map6[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
#ifndef INET6_ADDRLEN
#define INET6_ADDRLEN 16
#endif

// actual min MTU for IPv4 is 68, which is useless and possibly dangerous (IPv6 is 1280)
// this is the minimum size datagram a peer is required to be able to handle, so we use this
#define MIN_PMTU 576

void network_init(); // call this on startup (e.g. from main())


union ip_union
{
	in6_addr ip6;
	uint32_t ip4_mapped[INET6_ADDRLEN/sizeof(uint32_t)];
	bool is_ip4map6() const;
	uint32_t ip4_addr() const { return ip4_mapped[3]; } // last four bytes of IPv4 mapped IPv6 addr is IPv4 addr
	bool is_loopback() const { return is_ip4map6() ? is_ip4_loopback() : is_ip6_loopback(); }
	bool is_ip4_loopback() const {
		return (ip4_addr() & htonl(0xff000000)) == htonl(0x7f000000); // 127.x.x.x
	}
	bool is_ip6_loopback() const {
		static const uint8_t loopback[16] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1};
		return memcmp(loopback, ip6.s6_addr, sizeof(loopback)) == 0;
	}
	bool is_rfc1918() const;
	// note: these compare without converting to host byte order, comparisons will not be consistent between architectures (but still useful for std::set/map etc.)
	bool operator<(const ip_union& ip) const {
		// compare backwards because last bits are more likely to differ (especially IPv4)
		for(unsigned i=3; i > 0; --i)
			if(ip4_mapped[i] != ip.ip4_mapped[i])
				return ip4_mapped[i] < ip.ip4_mapped[i];
		return ip4_mapped[0] < ip.ip4_mapped[0];
	}
	bool operator==(const ip_union& ip) const {
		for(unsigned i=3; i > 0; --i)
			if(ip4_mapped[i] != ip.ip4_mapped[i])
				return false;
		return ip4_mapped[0] == ip.ip4_mapped[0];
	}

	ip_union() {}
	ip_union(const uint8_t* addr) { memcpy(ip6.s6_addr, addr, INET6_ADDRLEN); }
	ip_union(const in6_addr& addr) : ip6(addr) {}
	ip_union(uint32_t ip4) { memcpy(ip4_mapped, ip4map6, sizeof(ip4map6)); ip4_mapped[3] = ip4; }
};
std::ostream &operator<<(std::ostream &out, const ip_union& ipu);

// std::hash specialization for ip_union
namespace std
{
template<>
struct hash<ip_union>
{
	size_t operator()(const ip_union& ip) const { 
		size_t rv;
		memcpy(&rv, ip.ip6.s6_addr + 16 - sizeof(rv), sizeof(rv));
		return rv;
	}
};
}


union sockaddrunion {
	sockaddr s;
	sockaddr_storage ss;
	sockaddr_in sa;
	sockaddr_in6 sa6;
	sockaddrunion() {}
	sockaddrunion(const sockaddr_in& si) { memcpy(&sa, &si, sizeof(si)); }
	sockaddrunion(const sockaddr_in6& si6) { memcpy(&sa6, &si6, sizeof(si6)); }
	in_port_t get_ip_port() const {
		return (s.sa_family == AF_INET) ? sa.sin_port : sa6.sin6_port;
	}
	void set_ip_port(in_port_t port) {
		if(s.sa_family == AF_INET)
			sa.sin_port = port;
		else
			sa6.sin6_port = port;
	}

	ip_union get_ip_union() const {
		return (s.sa_family == AF_INET) ? ip_union(sa.sin_addr.s_addr) : ip_union(sa6.sin6_addr);
	}
	// write IPv6 addr or IPv4 addr in IPv6 format
	void write_ipaddr(uint8_t* to) const {
		if(s.sa_family == AF_INET) {
			memcpy(to, ip4map6, sizeof(ip4map6));
			uint32_t ip4_addr = sa.sin_addr.s_addr; // s_addr is "long" which is the wrong size on most 64-bit architectures
			memcpy(to+sizeof(ip4map6), &ip4_addr, sizeof(ip4_addr));
		} else {
			memcpy(to, sa6.sin6_addr.s6_addr, sizeof(in6_addr::s6_addr));
		}
	}
	bool is_loopback() const { return s.sa_family == AF_INET ? is_ip4_loopback() : is_ip6_loopback(); }
	bool is_ip4_loopback() const {
		return (sa.sin_addr.s_addr & htonl(0xff000000)) == htonl(0x7f000000); // 127.x.x.x
	}
	bool is_ip6_loopback() const {
		static const uint8_t loopback[16] = {0,0,0,0, 0,0,0,0 ,0,0,0,0, 0,0,0,1};
		return memcmp(loopback, sa6.sin6_addr.s6_addr, sizeof(loopback)) == 0;
	}
	bool operator==(const sockaddrunion &su) const {
		if(s.sa_family == AF_INET)
			return memcmp(&su.sa, &sa, sizeof(sa)) == 0;
		return memcmp(&su.sa6, &sa6, sizeof(sa6)) == 0;
	}
	bool operator!=(const sockaddrunion &su) const { return !(*this == su); }
};

std::ostream &operator<<(std::ostream &out, const sockaddrunion& su);

// takes IPv6 or IPv4 addr in IPv6 format and converts to appropriate sockaddr
void write_sockaddr(const uint8_t* ip6_addr, uint16_t nbo_port, sockaddrunion* su);
sockaddrunion get_sockaddr(const in6_addr& addr, in_port_t nbo_port);

// inet_ntop/inet_pton don't exist on earlier windows and defectively take non-const second argument on later windows
#ifdef WINSOCK
inline const char *inet_ntop(int af, const void *src, char *dst, socklen_t size)
{
	sockaddrunion addr;
	DWORD sz = size;
	if(af == AF_INET) {
		addr.sa.sin_family = af;
		addr.sa.sin_port = 0;
		memcpy(&addr.sa.sin_addr.s_addr, src, 4);
		if(WSAAddressToStringA(&addr.s, sizeof(addr.sa), nullptr, dst, &sz) == SOCKET_ERROR)
			return nullptr;
	} else if(af == AF_INET6) {
		addr.sa6.sin6_family = af;
		addr.sa6.sin6_port = 0;
		memcpy(addr.sa6.sin6_addr.s6_addr, src, 16);
		if(WSAAddressToStringA(&addr.s, sizeof(addr.sa6), nullptr, dst, &sz) == SOCKET_ERROR)
			return nullptr;
	} else {
		WSASetLastError(WSAEAFNOSUPPORT);
		return nullptr;
	}
	// remove unwanted scope id
	for(size_t i=2; i < sz; ++i) {
		if(dst[i]=='%' || dst[i]==']') {
			dst[i]='\0';
			break;
		}
	}
	return dst[0]=='[' ? (dst+1) : dst;
}
inline int inet_pton(int af, const char *src, void *dst)
{
	if(af != AF_INET && af != AF_INET6) {
		WSASetLastError(WSAEAFNOSUPPORT);
		return -1;
	}
	sockaddrunion addr;
	addr.s.sa_family = af;
	int addrlen = sizeof(addr);
	// more windows stupidity: takes 'char*' instead of 'const char*' for what in any sane implementation is a read only arg (seems to be a trend)
	char addrstr[INET6_ADDRSTRLEN+1];
	strncpy(addrstr, src, INET6_ADDRSTRLEN);
	addrstr[INET6_ADDRSTRLEN] = '\0';
	if(WSAStringToAddressA(addrstr, af, nullptr, &addr.s, &addrlen) == SOCKET_ERROR) {
		if(WSAGetLastError() == WSAEINVAL)
			return 0; // (this is what POSIX does)
		return -1;
	}
	if(af == AF_INET)
		memcpy(dst, &addr.sa.sin_addr.s_addr, 4);
	else
		memcpy(dst, &addr.sa6.sin6_addr.s6_addr, 16);
	return 1;
}
#endif




// provide RAII for socket descriptors and throw exceptions instead of using return values
	// pretty thin wrapper around the subset of the C socket API used here: just add to it whenever necessary
// significant note:
	// POSIX returns '0' from recv() and friends if peer cleanly shuts connection, but returns '-1' and sets errno for EAGAIN/EWOULDBLOCK
	// in csocket the return values are unsigned, and neither of these states are worthy of an exception, so in both cases the value returned is '0'
	// and they can be distinguished by checking sock_err::get_last(), which will either be sock_err::enotconn or sock_err::eagain/ewouldblock
	// obviously this only applies to connection-oriented sockets: a connectionless socket that returns 0 should always be EAGAIN/EWOULDBLOCK
class csocket
{
public:
#ifdef WINSOCK
	// note SOCKET is an unsigned type, compare to winsock constant INVALID_SOCKET to test validity
	typedef SOCKET sock_t;
	typedef char sockopt_val_t;
#else
#define INVALID_SOCKET -1
	typedef int sock_t;
	typedef int sockopt_val_t;
#endif
protected:
	sock_t sd; // socket descriptor
public:
	static const int YES;
	static const int NO;
	csocket() : sd(INVALID_SOCKET) {}
	explicit csocket(sock_t sock) : sd(sock) {}
	csocket(int domain, int type, int proto=0); // socket() constructor
	csocket(const csocket&) = delete;
	csocket(csocket&& rval) : sd(rval.sd) { rval.sd = INVALID_SOCKET; }
	csocket& operator=(csocket&& rval) { std::swap(sd, rval.sd); return *this; }
	void setopt_keepalive();
	void setopt_reuseaddr();
	void setopt_exclusiveaddruse();
	void setopt_nonblock();
	void setopt_dontfragment();
	void setopt_ipv6only(int val); // must not call after bind()
	void bind(const sockaddrunion& su);
	void bind(in_port_t nbo_port, int domain);
	void connect(const sockaddrunion& su);
	void listen(int backlog = 10);
	csocket accept(sockaddrunion& peer_addr);
	sockaddrunion & getsockname(sockaddrunion& su) const;
	sockaddrunion & getpeername(sockaddrunion& su) const;
	size_t sendto(const void* buf, size_t len, const sockaddrunion& dest, int flags = 0);
	size_t send(const void* buf, size_t len, int flags = 0);
	size_t recvfrom(void* buf, size_t len, sockaddrunion* from, int flags= 0);
	size_t recv(void* buf, size_t len, int flags = 0);
	sock_t fd() { return sd; }
	sock_t release_fd() { sock_t rv = sd; sd = INVALID_SOCKET; return rv; }
	void close();
	~csocket();
};

std::ostream &operator<<(std::ostream &out, const csocket &sock);

// this is a csocket that borrows a file descriptor but doesn't own it, i.e. doesn't close() it on destruction
// note csocket *doesn't* have a virtual destructor, so this doesn't work if you delete it through a csocket pointer
class csocket_borrow : public csocket
{
public:
	csocket_borrow(sock_t descriptor) : csocket(descriptor) {}
	csocket_borrow(const csocket_borrow &s) : csocket(s.sd) {}
	~csocket_borrow() {
		// parent constructor doesn't close() if sd is INVALID_SOCKET
		sd = INVALID_SOCKET;
	}
	// do not close through this, if you want to close use the real csocket, if you want to close conditionally use csocket and release()
	// closing through csocket_borrow could mistakenly leave the "real" csocket with an invalid fd which it could close after it was reassigned
	void close() = delete; 
};

// wait_for_read: poll() or select() on a single socket for read with indefinite timeout
// TODO: maybe support waiting for write or with timeout, not currently needed
class wait_for_read
{
	// use select for winsock because not every windows has poll,
	// use poll everywhere else because non-winsock select is defective if value of fd is > FD_SETSIZE
#ifdef WINSOCK
	csocket::sock_t sd;
	fd_set fdset;
#else
	pollfd pfd;
#endif
public:
	wait_for_read(csocket::sock_t sock);
	int wait();
};

class sock_err
{
	int error;
	sock_err(int e) : error(e) {}
public:
#ifdef WINSOCK
	static sock_err get_last() { return sock_err(WSAGetLastError()); }
	static void set_last(sock_err e) { WSASetLastError(e.error); }
#else
	static sock_err get_last() { return sock_err(errno); }
	static void set_last(sock_err e) { errno = e.error; }
#endif
	// get_error() is platform-neutral getsockopt(sock, SOL_SOCKET, SO_ERROR)
	static sock_err get_error(csocket::sock_t sock) noexcept; // (on getsockopt() error, returns the getsockopt() error instead)
	static sock_err get_error(csocket &sock) noexcept { return get_error(sock.fd()); }
	bool operator==(sock_err se) { return error == se.error; }
	bool operator!=(sock_err se) { return error != se.error; }
	bool operator==(int e) { return error == e; }
	bool operator!=(int e) { return error != e; }
	friend std::ostream& operator<<(std::ostream&, sock_err);
	// TODO: try to make all of these constexpr (may require newer compiler than existing gcc 4.7)
	static const sock_err enoerr; // (success)
	static const sock_err enomem;
	static const sock_err ebadf;
	static const sock_err eintr;
	static const sock_err eacces;
	static const sock_err efault;
	static const sock_err einval;
	static const sock_err emfile;
	static const sock_err ewouldblock;
	static const sock_err eagain;
	static const sock_err einprogress;
	static const sock_err ealready;
	static const sock_err enotsock;
	static const sock_err edestaddrreq;
	static const sock_err emsgsize;
	static const sock_err eprototype;
	static const sock_err enoprotoopt;
	static const sock_err eprotonosupport;
	static const sock_err esocktnosupport;
	static const sock_err eopnotsupp;
	static const sock_err epfnosupport;
	static const sock_err eafnosupport;
	static const sock_err eaddrinuse;
	static const sock_err eaddrnotavail;
	static const sock_err enetdown;
	static const sock_err enetunreach;
	static const sock_err enetreset;
	static const sock_err econnaborted;
	static const sock_err econnreset;
	static const sock_err enobufs;
	static const sock_err eisconn;
	static const sock_err enotconn;
	static const sock_err eshutdown;
	static const sock_err etoomanyrefs;
	static const sock_err etimedout;
	static const sock_err econnrefused;
	static const sock_err eloop;
	static const sock_err enametoolong;
	static const sock_err ehostdown;
	static const sock_err ehostunreach;
	static const sock_err ecanceled;
};

std::ostream& operator<<(std::ostream &out, sock_err se);

inline bool sock_err_is_wouldblock(sock_err se)
{
	return(se == sock_err::ewouldblock || se == sock_err::eagain);
}

// this is similar to sockaddrunion but is more compact when not necessary to pass to BSD sockets API
struct ip_info
{
	ip_union addr;
	in_port_t port; // network byte order
	ip_info() : ip_info(ip_union(0U), 0) {}
	ip_info(uint32_t ip4_addr, in_port_t nbo_port) : addr(ip4_addr), port(nbo_port) {}
	ip_info(const in6_addr& ip, in_port_t nbo_port) : port(nbo_port) { memcpy(addr.ip6.s6_addr, ip.s6_addr, INET6_ADDRLEN);	}
	ip_info(const uint8_t* ip6, in_port_t nbo_port) : port(nbo_port) { memcpy(addr.ip6.s6_addr, ip6, INET6_ADDRLEN);	}
	ip_info(const ip_union& ip, in_port_t nbo_port) : addr(ip), port(nbo_port) {}
	explicit ip_info(const sockaddrunion& su) : addr(su.get_ip_union()), port(su.get_ip_port()) {}
	bool operator==(const ip_info& info) const { return addr == info.addr && port == info.port; }
	bool operator!=(const ip_info& info) const { return !(*this == info); }
	bool operator<(const ip_info& info) const { return addr == info.addr ? port < info.port : addr < info.addr; }
	// some convenience constructors / functions:
	ip_info(const uint8_t* raw) {
		memcpy(addr.ip6.s6_addr, raw, INET6_ADDRLEN);
		memcpy(&port, raw+INET6_ADDRLEN, sizeof(port));
	}
	void copy_to(uint8_t* dest) const {
		memcpy(dest, addr.ip6.s6_addr, INET6_ADDRLEN);
		memcpy(dest + INET6_ADDRLEN, &port, sizeof(port));
	}
	void copy_to(sockaddrunion& su) const {
		if(addr.is_ip4map6()) {
			su.sa.sin_family = AF_INET;
			su.sa.sin_addr.s_addr = addr.ip4_addr();
			su.sa.sin_port = port;
		} else {
			su.sa6.sin6_family = AF_INET6;
			memcpy(su.sa6.sin6_addr.s6_addr, addr.ip6.s6_addr, INET6_ADDRLEN);
			su.sa6.sin6_port = port;
		}
	}
	static unsigned size() { return INET6_ADDRLEN + sizeof(in_port_t); }
};
static_assert(sizeof(in6_addr::s6_addr)==INET6_ADDRLEN, "IPv6 addr has broken size");
std::ostream& operator<<(std::ostream &out, const ip_info&);

// std::hash specialization for ip_info
namespace std
{
template<>
struct hash<ip_info>
{
	size_t operator()(const ip_info& info) const { 
		size_t rv = 0;
		rv = info.addr.ip4_addr(); // (or last 32 bits of ip6 addr)
		if(sizeof(size_t) > 4)
			rv<<=16;
		rv^=info.port;
		return rv;
	}
};
}

// put NBO IP addrs to ostream
struct ss_ipaddr
{
	const uint32_t addr;
	ss_ipaddr(const uint32_t ip) : addr(ip) {}
};
std::ostream& operator<<(std::ostream&, const ss_ipaddr);

struct ss_ip6addr
{
	const uint8_t* addr;
	ss_ip6addr(const uint8_t* ip) : addr(ip) {}
};
std::ostream& operator<<(std::ostream&, const ss_ip6addr&);
		


#endif // NETWORK_H
