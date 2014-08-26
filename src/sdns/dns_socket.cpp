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

#include "dns_socket.h"

void dns_socket::bind_random_port(int family)
{
	setopt_exclusiveaddruse();
	size_t retry = 0;
	// TODO: test that this does the right thing (and on all platforms)
	// specifically that if bind() fails with addrinuse, another bind() call can be made without calling socket() again
	while(true) {
		uint16_t src_port = random_unprivileged_port();
		try {
			bind(htons(src_port), family);
			break;
		} catch(const check_err_exception &e) {
			// port already in use is not a real error, just need a different port
			// but if it fails 20 times in a row then throw the eaddrinuse
			if(sock_err::get_last() == sock_err::eaddrinuse && ++retry <= 20)
				continue; 
			throw e;
		}
	}
}

uint8_t dns_udp_socket::udpbuf[65536];

dns_message dns_udp_socket::recv_dnsmsg()
{
	size_t size = recv(udpbuf, sizeof(udpbuf));
	if(size) return dns_message(udpbuf, size);
	return dns_message();
}

bool dns_udp_socket::send_dnsmsg(const dns_message & msg)
{
	// TODO: figure out what to do if msg is ever > 65535 (currently throws EMSGSIZE which turns into SERVFAIL)
	dbuf buf(msg.maxsize());
	size_t len = msg.write(buf);
	if(csocket::send(buf, len))
		return true;
	sendbuf = std::move(buf);
	sendbuf.resize(len); // truncate to message length
	return false;
}

bool dns_udp_socket::send()
{
	if(sendbuf.size() == 0)
		return true;
	if(csocket::send(sendbuf, sendbuf.size())) {
		sendbuf.free();
		return true;
	}
	return false;
}

dns_tcp_socket& dns_tcp_socket::operator=(dns_tcp_socket &&s)
{
	std::swap(sendbuf, s.sendbuf);
	sendbuf_offset = s.sendbuf_offset;
	sendbuf_len = s.sendbuf_len;
	std::swap(tcpbuf, s.tcpbuf);
	msg_recvd = s.msg_recvd;
	csocket::operator=(std::move(s));
	return *this;
}

dns_message dns_tcp_socket::recv_dnsmsg()
{
	if(tcpbuf.size() < 512)
		tcpbuf.resize(512);
	size_t bytes = recv(tcpbuf + msg_recvd, tcpbuf.size() - msg_recvd);
	msg_recvd += bytes;
	if(msg_recvd >= sizeof(uint16_t)) {
		size_t len = (tcpbuf[0] << 8) + tcpbuf[1];
		size_t rawlen = len + sizeof(uint16_t);
		if(tcpbuf.size() < rawlen) {
			tcpbuf.resize(rawlen);
			return recv_dnsmsg();
		}
		if(msg_recvd == rawlen) {
			msg_recvd = 0;
			return dns_message(tcpbuf + sizeof(uint16_t), len);
		}
		if(msg_recvd > rawlen) {
			size_t blen = std::max<size_t>((tcpbuf[rawlen] + 1) << 8, msg_recvd - rawlen + 2);
			dbuf newbuf(std::move(tcpbuf));
			tcpbuf = dbuf(blen);
			memcpy(tcpbuf, newbuf + rawlen, msg_recvd - rawlen);
			return dns_message(newbuf + sizeof(uint16_t), len);
		}
	}
	if(bytes > 0)
		sock_err::set_last(sock_err::ewouldblock); // (if bytes==0 then last sock err is already set)
	return dns_message();
}

bool dns_tcp_socket::send_dnsmsg(const dns_message &msg)
{
	size_t newlen = sendbuf_len + msg.maxsize() + sizeof(uint16_t);
	if(sendbuf.size() < newlen) sendbuf.resize(newlen);
	size_t len = msg.write(sendbuf + sendbuf_len + sizeof(uint16_t));
	if(len > UINT16_MAX) {
		eout() << "BUG: tried to send " << len << " byte DNS message in excess of 65535 byte hard limit";
		return true;
	}
	sendbuf[sendbuf_len + 0] = len >> 8;
	sendbuf[sendbuf_len + 1] =  len & 0xff;
	sendbuf_len += len + sizeof(uint16_t);
	return send();
}
bool dns_tcp_socket::send_tcpmsg(dbuf &&buf, size_t len)
{
	if(len > UINT16_MAX + 2) {
		eout() << "BUG: tried to send " << len << " byte DNS message buffer in excess of 65535 byte hard limit";
		return true;
	}
	if(sendbuf.size() == 0) {
		size_t sent = csocket::send(buf, len);
		if(sent == len) {
			dout() << "Sent entire TCP message";
			return true;
		} else {
			sendbuf = std::move(buf);
			sendbuf_offset = sent;
			sendbuf_len = len;
		}
	} else if(sendbuf.size() - sendbuf_offset < 75000) {
		dout() << "dns_tcp_socket queued outgoing TCP dnsmsg send because exising message remains pending";
		if(sendbuf.size() < sendbuf_len + len)
			sendbuf.resize(sendbuf_len + len);
		memcpy(sendbuf + sendbuf_len, buf, len);
		sendbuf_len += len;
		return send();
	} else {
		wout() << "Discarded TCP outgoing message because existing send buffer was too large";
	}
	return false;
}

bool dns_tcp_socket::send()
{
	if(sendbuf_len <= sendbuf_offset)
		return true;
	size_t sent = csocket::send(sendbuf + sendbuf_offset, sendbuf_len - sendbuf_offset);
	dout() << "dns_tcp_socket sent " << sent << " / " << sendbuf_len << " bytes of message from offset " << sendbuf_offset;
	sendbuf_offset += sent;
	if(sendbuf_offset == sendbuf_len) {
		sendbuf.resize(0);
		sendbuf_offset = 0;
		sendbuf_len = 0;
		return true;
	}
	if(sendbuf_offset >  4000) {
		memmove(sendbuf, sendbuf + sendbuf_offset, sendbuf_len - sendbuf_offset);
		sendbuf_len -= sendbuf_offset;
		sendbuf_offset = 0;
	}
	return false;
}
