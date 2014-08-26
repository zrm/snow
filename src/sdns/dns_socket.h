/*	sdns
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

#ifndef DNS_SOCKET_H
#define DNS_SOCKET_H
#include "../common/network.h"
#include "../common/common.h"
#include "../common/dbuf.h"
#include "dns_message.h"

class dns_message;
class dns_socket : public csocket
{
protected:
	dbuf sendbuf;
	// DNS must use random port to inhibit Kaminsky attack; allowing OS to choose "randomly" may not be sufficiently random
	uint16_t random_unprivileged_port() {
		static std::uniform_int_distribution<uint16_t> dist(1024, 65535);
		static std::random_device rd;
		return dist(rd);
	}
	void bind_random_port(int family);
public:
	dns_socket() {}
	dns_socket(int domain, int type) : csocket(domain, type) { bind_random_port(domain); }
	dns_socket(csocket &&sock) : csocket(std::move(sock)) {}
	dns_socket(dns_socket &&sock) : csocket(std::move(sock)) {}
	dns_socket& operator=(const dns_socket &s) = delete;
	dns_socket& operator=(dns_socket &&s) = delete;
	virtual dns_message recv_dnsmsg() = 0;
	// send_dnsmsg: returns true if entire message sent, false if buffered and calls to send() must be made to complete sending
	virtual bool send_dnsmsg(const dns_message & msg) = 0;
	virtual bool send() = 0;
	virtual void rebind(int domain) = 0; // throws e_check_sock_err
	virtual bool is_tcp() { return false; }
	virtual dns_socket* get_new() = 0; // get newly allocated dns_socket of same type as this socket
	virtual ~dns_socket() {}
};

class dns_udp_socket : public dns_socket
{
	static uint8_t udpbuf[65536]; // recv buf, static means we're not thread safe even between sockets but current implementation uses UDP sockets in only one thread
public:
	dns_udp_socket() {}
	dns_udp_socket(int domain) : dns_socket(domain, SOCK_DGRAM) {}
	dns_udp_socket& operator=(dns_udp_socket &&s) {
		std::swap(sendbuf, s.sendbuf);
		csocket::operator=(std::move(s));
		return *this;
	}
	virtual dns_message recv_dnsmsg();
	virtual bool send_dnsmsg(const dns_message & msg);
	virtual bool send();
	virtual void rebind(int domain) { *this = dns_udp_socket(domain); } // throws e_check_sock_err
	virtual dns_socket* get_new() { return static_cast<dns_socket*>(new dns_udp_socket()); }
};

class dns_tcp_socket : public dns_socket
{
	size_t sendbuf_offset;
	size_t sendbuf_len;
	dbuf tcpbuf;
	size_t msg_recvd;
public:
	dns_tcp_socket() : msg_recvd(0) {}
	dns_tcp_socket(int domain) : dns_socket(domain, SOCK_STREAM), sendbuf_offset(0), sendbuf_len(0), msg_recvd(0) {}
	dns_tcp_socket(dns_tcp_socket &&s) : dns_socket(std::move(s)), sendbuf_offset(s.sendbuf_offset), sendbuf_len(s.sendbuf_len), tcpbuf(std::move(s.tcpbuf)), msg_recvd(s.msg_recvd) {}
	dns_tcp_socket(csocket &&s) : dns_socket(std::move(s)), sendbuf_offset(0), sendbuf_len(0), msg_recvd(0) {}
	dns_tcp_socket& operator=(dns_tcp_socket &&s);
	virtual dns_message recv_dnsmsg();
	virtual bool send_dnsmsg(const dns_message & msg);
	bool send_tcpmsg(dbuf && buf, size_t msglen); // send raw DNS message which already includes two byte TCP msg size header
	virtual bool send();
	virtual void rebind(int domain) { *this = dns_tcp_socket(domain); } // throws e_check_sock_err
	virtual bool is_tcp() { return true; }
	virtual dns_socket* get_new() { return static_cast<dns_socket*>(new dns_tcp_socket()); }
};


#endif // DNS_SOCKET_H
