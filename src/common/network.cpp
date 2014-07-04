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

#include<cstdint>
#include<cstring>
#include<sys/types.h>
#ifndef WINSOCK
#include<sys/socket.h>
#include<fcntl.h>
#include<unistd.h>
#endif

#include"../common/network.h"
#include"../common/err_out.h"
#include"../common/common.h"

void network_init()
{
#ifdef WINSOCK
	dout() << "network_init: doing WSAStartup()";
	WSADATA not_interested;
	int rv = WSAStartup(MAKEWORD(2,2), &not_interested);
	if(rv != 0) {
		eout() << "WSAStartup failed: " << get_windows_errorstr(rv);
		throw e_check_sock_err("WSAStartup failed", true);
	}
#endif
}

bool ip_union::is_rfc1918() const
{
	if(is_ip4map6()) {
		uint32_t ip4 = ip4_addr();
		if((ip4 & htonl(0xff000000)) == htonl(0x0a000000)) // 10.0.0.0/8
			return true;
		if((ip4 & htonl(0xfff00000)) == htonl(0xac100000)) // 172.16.0.0/12
			return true;
		if((ip4 & htonl(0xffff0000)) == htonl(0xc0a80000)) // 192.168.0.0/16
			return true;
	}
	return false;
}

std::ostream &operator<<(std::ostream &out, const ip_union& ipu)
{
	if(ipu.is_ip4map6()) {
		out << ss_ipaddr(ipu.ip4_addr());
	} else {
		out << ss_ip6addr(ipu.ip6.s6_addr);
	}
	return out;
}

std::ostream &operator<<(std::ostream &out, const sockaddrunion& su)
{
	char buf[INET6_ADDRSTRLEN];
	if(su.s.sa_family == AF_INET) {
		if(nullptr != inet_ntop(AF_INET, &su.sa.sin_addr, buf, INET6_ADDRSTRLEN))
			out << buf << ":" << ntohs(su.sa.sin_port);
		else
			out << "[sockaddrunion: inet_ntop(AF_INET, ...): " << sock_err::get_last() << "]";
	} else if(su.s.sa_family == AF_INET6) {
		if(nullptr != inet_ntop(AF_INET6, &su.sa6.sin6_addr, buf, INET6_ADDRSTRLEN))
			out << "[" << buf << "]:" << ntohs(su.sa6.sin6_port);
		else
			out << "[sockaddrunion: inet_ntop(AF_INET6, ...): " << sock_err::get_last() << "]";
	} else if(su.s.sa_family == AF_UNSPEC) {
		out<< "[AF_UNSPEC]";
	} else {
		out << "[sockaddrunion: invalid or non-INET address family]";
		// could do AF_LOCAL?
	}
	return out;
}



csocket::csocket(int domain, int type, int proto)
{
	sd = socket(domain, type, proto);
	check_sock_err(sd, "socket()");
}

void csocket::setopt_keepalive() { check_sock_err(setsockopt(sd, SOL_SOCKET, SO_KEEPALIVE, (const sockopt_val_t*)&YES, sizeof(YES)), "setsockopt(SO_KEEPALIVE)"); }
void csocket::setopt_reuseaddr() { check_sock_err(setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (const sockopt_val_t*)&YES, sizeof(YES)), "setsockopt(SO_REUSEADDR)"); }
void csocket::setopt_exclusiveaddruse() {
#ifdef WINDOWS
	check_sock_err(setsockopt(sd, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const sockopt_val_t*)&YES, sizeof(YES)), "setsockopt(SO_EXCLUSIVEADDRUSE)");
#endif
}
void csocket::setopt_ipv6only(int val) { check_sock_err(setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, (const sockopt_val_t*)&val, sizeof(val)), "setsockopt(IPV6_V6ONLY)"); }

void csocket::setopt_dontfragment() {
#ifdef WINSOCK
	DWORD val = TRUE;
	check_sock_err(setsockopt(sd, IPPROTO_IP, IP_DONTFRAGMENT, (LPSTR)&val, sizeof(val)), "setsockopt(IP_DONTFRAGMENT)");
#elif defined(IP_PMTUDISC_DO)
	// linux
	// TODO: does this do anything unreasonable when called against IPv6 socket?
	sockopt_val_t val = IP_PMTUDISC_DO;
	check_sock_err(setsockopt(sd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val)), "setsockopt(IP_MTU_DISCOVER)");
	// IPv6 doesn't have DF bit, this option would only enable PMTU discovery:
	// int val = IPV6_PMTUDISC_DO;
	// check_sock_err(setsockopt(sd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &val, sizeof(val)), "setsockopt(IPV6_MTU_DISCOVER)");
#else
	// BSD
	check_sock_err(setsockopt(sd, IPPROTO_IP, IP_DONTFRAG, &YES, sizeof(val)), "setsockopt(IP_DONTFRAG)");
#endif
}

void csocket::setopt_nonblock() {
#ifdef WINSOCK
	DWORD imode=1;
	check_sock_err(ioctlsocket(sd, FIONBIO, &imode), "csocket::setopt_nonblock(): ioctlsocket(FIONBIO)");
#else
	check_sock_err(fcntl(sd, F_SETFL, O_NONBLOCK), "csocket::setopt_nonblock(): fnctl(F_SETFL, O_NONBLOCK)");
#endif
}
void csocket::bind(const sockaddrunion& su)
{
	check_sock_err(::bind(sd, &su.s, sizeof(sockaddrunion)), "bind()");
}
void csocket::bind(in_port_t nbo_port, int domain)
{
	sockaddrunion su;
	memset(&su, 0, sizeof(su));
	if(domain == AF_INET) {
		su.sa.sin_family = domain;
		su.sa.sin_port = nbo_port;
	} else {
		su.sa6.sin6_family = domain;
		su.sa6.sin6_port = nbo_port;
	}
	bind(su);
}
void csocket::connect(const sockaddrunion& su)
{
	if(is_sock_err(::connect(sd, &su.s, sizeof(sockaddrunion)))) {
		// EINPROGRESS just means socket is non-blocking and requires TCP handshake, not really an error
		if(sock_err::get_last() != sock_err::einprogress)
			throw e_check_sock_err("connect()", true);
	}
}
// these return the len of the sockaddr written, but this appears to be redundant information: it's implied by the address family
sockaddrunion & csocket::getsockname(sockaddrunion& su) const
{
	socklen_t addrlen = sizeof(su);
	check_sock_err(::getsockname(sd, &su.s, &addrlen), "getsockname()");
	return su;
}
sockaddrunion & csocket::getpeername(sockaddrunion& su) const
{
	socklen_t addrlen = sizeof(su);
	check_sock_err(::getpeername(sd, &su.s, &addrlen), "getpeername()");
	return su;
}
std::ostream &operator<<(std::ostream &out, const csocket &sock)
{
	try {
		sockaddrunion local, remote;
		sock.getsockname(local);
		try {
			sock.getpeername(remote);
			out << local << "<->" << remote;
		} catch(const e_check_sock_err &e) {
			// this is generally "not connected" but print whatever it is
			out << local << ": " << e;
		}
	} catch(const e_check_sock_err &e) {
		out << "[csocket: " << e << "]";
	}
	return out;
}

size_t send_rv(ssize_t bytes, const char* fn)
{
	if(is_sock_err(bytes)) {
		if(sock_err_is_wouldblock(sock_err::get_last()))
			return 0;
		else
			throw e_check_sock_err(fn, true);
	}
	return bytes;
}
size_t csocket::sendto(const void* buf, size_t len, const sockaddrunion& dest, int flags)
{
	ssize_t bytes = ::sendto(sd, static_cast<const char*>(buf), len, flags, &dest.s, sizeof(sockaddrunion));
	return send_rv(bytes, "sendto()");
}
size_t csocket::send(const void* buf, size_t len, int flags)
{
	ssize_t bytes = ::send(sd, static_cast<const char*>(buf), len, flags);
	return send_rv(bytes, "send()");
}

size_t recv_rv(ssize_t bytes, size_t len, const char* fn)
{
	if(is_sock_err(bytes)) {
		if(sock_err_is_wouldblock(sock_err::get_last()))
			return 0;
		else
			throw e_check_sock_err(fn, true);
	}
	if(bytes == 0 && len != 0)
		sock_err::set_last(sock_err::enotconn);
	return bytes;
}
size_t csocket::recvfrom(void* buf, size_t len, sockaddrunion* from, int flags)
{
	socklen_t addrlen = sizeof(sockaddrunion);
	ssize_t bytes = ::recvfrom(sd, static_cast<char*>(buf), len, flags, &from->s, &addrlen);
	return recv_rv(bytes, len, "recvfrom()");
}
size_t csocket::recv(void* buf, size_t len, int flags)
{
	ssize_t bytes = ::recv(sd, static_cast<char*>(buf), len, flags);
	return recv_rv(bytes, len, "recv()");
}

void csocket::listen(int backlog) { check_sock_err(::listen(sd, backlog), "listen()"); }

csocket csocket::accept(sockaddrunion &peer_addr)
{
	socklen_t addrlen = sizeof(peer_addr);
	int newsd = ::accept(sd, &peer_addr.s, &addrlen);
	check_sock_err(newsd, "accept()");
	return csocket(newsd);
}

csocket::~csocket() {
	try { close(); }
	catch(const e_check_sock_err &e) {
		eout() << "csocket::~csocket():" << e;
	}
}
void csocket::close() {
	if(sd != INVALID_SOCKET) {
#		ifdef WINSOCK
			check_sock_err(closesocket(sd), "closesocket()");
#		else
			while(::close(sd) < 0) {
				if(errno != EINTR) {
					eout_perr() << "csocket: error closing socket descriptor";
					break;
				}
			}
#		endif
	}
	sd = INVALID_SOCKET;
}


const int csocket::YES = 1;
const int csocket::NO = 0;

#ifdef WINSOCK
wait_for_read::wait_for_read(csocket::sock_t sock) : sd(sock) {}
#else
wait_for_read::wait_for_read(csocket::sock_t sock) : pfd{sock, POLLIN, 0} {}
#endif

int wait_for_read::wait()
{
#ifdef WINSOCK
	FD_ZERO(&fdset);
	FD_SET(sd, &fdset);
	return select(sd+1, &fdset, nullptr, nullptr, nullptr);
#else
	return poll(&pfd, 1, -1);
#endif
}

const sock_err sock_err::enoerr(0);
#ifdef WINSOCK
const sock_err sock_err::enomem(WSA_NOT_ENOUGH_MEMORY);
const sock_err sock_err::ebadf(WSAEBADF);
const sock_err sock_err::eintr(WSAEINTR);
const sock_err sock_err::eacces(WSAEACCES);
const sock_err sock_err::efault(WSAEFAULT);
const sock_err sock_err::einval(WSAEINVAL);
const sock_err sock_err::emfile(WSAEMFILE);
const sock_err sock_err::ewouldblock(WSAEWOULDBLOCK);
const sock_err sock_err::eagain(WSAEWOULDBLOCK); // no EAGAIN on windows
const sock_err sock_err::einprogress(WSAEINPROGRESS);
const sock_err sock_err::ealready(WSAEALREADY);
const sock_err sock_err::enotsock(WSAENOTSOCK);
const sock_err sock_err::edestaddrreq(WSAEDESTADDRREQ);
const sock_err sock_err::emsgsize(WSAEMSGSIZE);
const sock_err sock_err::eprototype(WSAEPROTOTYPE);
const sock_err sock_err::enoprotoopt(WSAENOPROTOOPT);
const sock_err sock_err::eprotonosupport(WSAEPROTONOSUPPORT);
const sock_err sock_err::esocktnosupport(WSAESOCKTNOSUPPORT);
const sock_err sock_err::eopnotsupp(WSAEOPNOTSUPP);
const sock_err sock_err::epfnosupport(WSAEPFNOSUPPORT);
const sock_err sock_err::eafnosupport(WSAEAFNOSUPPORT);
const sock_err sock_err::eaddrinuse(WSAEADDRINUSE);
const sock_err sock_err::eaddrnotavail(WSAEADDRNOTAVAIL);
const sock_err sock_err::enetdown(WSAENETDOWN);
const sock_err sock_err::enetunreach(WSAENETUNREACH);
const sock_err sock_err::enetreset(WSAENETRESET);
const sock_err sock_err::econnaborted(WSAECONNABORTED);
const sock_err sock_err::econnreset(WSAECONNRESET);
const sock_err sock_err::enobufs(WSAENOBUFS);
const sock_err sock_err::eisconn(WSAEISCONN);
const sock_err sock_err::enotconn(WSAENOTCONN);
const sock_err sock_err::eshutdown(WSAESHUTDOWN);
const sock_err sock_err::etoomanyrefs(WSAETOOMANYREFS);
const sock_err sock_err::etimedout(WSAETIMEDOUT);
const sock_err sock_err::econnrefused(WSAECONNREFUSED);
const sock_err sock_err::eloop(WSAELOOP);
const sock_err sock_err::enametoolong(WSAENAMETOOLONG);
const sock_err sock_err::ehostdown(WSAEHOSTDOWN);
const sock_err sock_err::ehostunreach(WSAEHOSTUNREACH);
const sock_err sock_err::ecanceled(WSAECANCELLED);
std::ostream& operator<<(std::ostream &out, sock_err se)
{
	out << get_windows_errorstr(se.error);
	return out;
}
sock_err sock_err::get_error(csocket::sock_t sock) noexcept
{
	int rv = 0;
	int len = sizeof(rv);
	if(is_sock_err(getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&rv, &len)))
		return WSAGetLastError();
	return sock_err(rv);
}
#else
const sock_err sock_err::enomem(ENOMEM);
const sock_err sock_err::ebadf(EBADF);
const sock_err sock_err::eintr(EINTR);
const sock_err sock_err::eacces(EACCES);
const sock_err sock_err::efault(EFAULT);
const sock_err sock_err::einval(EINVAL);
const sock_err sock_err::emfile(EMFILE);
const sock_err sock_err::ewouldblock(EWOULDBLOCK);
const sock_err sock_err::eagain(EAGAIN);
const sock_err sock_err::einprogress(EINPROGRESS);
const sock_err sock_err::ealready(EALREADY);
const sock_err sock_err::enotsock(ENOTSOCK);
const sock_err sock_err::edestaddrreq(EDESTADDRREQ);
const sock_err sock_err::emsgsize(EMSGSIZE);
const sock_err sock_err::eprototype(EPROTOTYPE);
const sock_err sock_err::enoprotoopt(ENOPROTOOPT);
const sock_err sock_err::eprotonosupport(EPROTONOSUPPORT);
const sock_err sock_err::esocktnosupport(ESOCKTNOSUPPORT);
const sock_err sock_err::eopnotsupp(EOPNOTSUPP);
const sock_err sock_err::epfnosupport(EPFNOSUPPORT);
const sock_err sock_err::eafnosupport(EAFNOSUPPORT);
const sock_err sock_err::eaddrinuse(EADDRINUSE);
const sock_err sock_err::eaddrnotavail(EADDRNOTAVAIL);
const sock_err sock_err::enetdown(ENETDOWN);
const sock_err sock_err::enetunreach(ENETUNREACH);
const sock_err sock_err::enetreset(ENETRESET);
const sock_err sock_err::econnaborted(ECONNABORTED);
const sock_err sock_err::econnreset(ECONNRESET);
const sock_err sock_err::enobufs(ENOBUFS);
const sock_err sock_err::eisconn(EISCONN);
const sock_err sock_err::enotconn(ENOTCONN);
const sock_err sock_err::eshutdown(ESHUTDOWN);
const sock_err sock_err::etoomanyrefs(ETOOMANYREFS);
const sock_err sock_err::etimedout(ETIMEDOUT);
const sock_err sock_err::econnrefused(ECONNREFUSED);
const sock_err sock_err::eloop(ELOOP);
const sock_err sock_err::enametoolong(ENAMETOOLONG);
const sock_err sock_err::ehostdown(EHOSTDOWN);
const sock_err sock_err::ehostunreach(EHOSTUNREACH);
const sock_err sock_err::ecanceled(ECANCELED);
std::ostream& operator<<(std::ostream &out, sock_err se)
{
	out << se.error << ": " << strerror_rp(se.error);
	return out;
}
sock_err sock_err::get_error(csocket::sock_t sock) noexcept
{
	int rv = 0;
	socklen_t len = sizeof(rv);
	// returning errno on getsockopt error may be slightly confusing,
	// but most of the errors that would actually happen make sense to return (e.g. EBADF or ENOTSOCK)
	if(is_sock_err(getsockopt(sock, SOL_SOCKET, SO_ERROR, &rv, &len)))
		return errno;
	return rv;
}
#endif


std::ostream& operator<<(std::ostream &out, const ip_info& info)
{
	out << info.addr << " port " << ntohs(info.port);
	return out;
}

bool ip_union::is_ip4map6() const {
	return memcmp(ip4map6, ip6.s6_addr, sizeof(ip4map6)) == 0;
}

void write_sockaddr(const uint8_t* ip6_addr, uint16_t nbo_port, sockaddrunion* su)
{
	if(is_equal(ip4map6, ip6_addr, sizeof(ip4map6)))
	{
		su->sa.sin_family = AF_INET;
		uint32_t ip4_addr;
		std::copy(ip6_addr+sizeof(ip4map6),ip6_addr+sizeof(in6_addr), (uint8_t*)&ip4_addr);
		su->sa.sin_addr.s_addr = ip4_addr;
		su->sa.sin_port = nbo_port;
	} else {
		su->sa6.sin6_family = AF_INET6;
		std::copy(ip6_addr, ip6_addr+sizeof(in6_addr), su->sa6.sin6_addr.s6_addr);
		su->sa6.sin6_port = nbo_port;
	}
}

sockaddrunion get_sockaddr(const in6_addr& addr, in_port_t nbo_port)
{
	sockaddrunion rv;
	write_sockaddr(addr.s6_addr, nbo_port, &rv);
	return rv;
}


std::ostream& operator<<(std::ostream& out, const ss_ipaddr ip)
{
	const uint8_t* addr = (const uint8_t*)&ip.addr;
	out << std::dec << (int)addr[0] << "." << (int)addr[1] << "." << (int)addr[2] << "." << (int)addr[3];
	return out;
}


std::ostream& operator<<(std::ostream& out, const ss_ip6addr& ip)
{
	char addrstr[INET6_ADDRSTRLEN] = {0};
	out << inet_ntop(AF_INET6, ip.addr, addrstr, INET6_ADDRSTRLEN);
	return out;
}


