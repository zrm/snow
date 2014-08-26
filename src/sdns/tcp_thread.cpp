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

#include "../sdns/tcp_thread.h"
#include "../sdns/dns_message.h"
#include "../sdns/eventloop.h"
#include <chrono>

// TODO: the justification for having a separate TCP thread is not very strong, it may make sense to fold it back into eventloop
	// would still need special treatment for TCP (e.g. must close socket after idle timeout), but it would eliminate a lot of the duplication between eventloop and tcp_thread
tcp_thread::tcp_thread() : clients(std::bind(&tcp_thread::cleanup_connection, this, std::placeholders::_1), TCP_NONPEER::NUM_NONPEER_FDS, "tcp"), running(true)
{
	clients.emplace_back(interthread_msg_queue.getSD(), pvevent::read, std::bind(&function_tqueue::pv_execute, &interthread_msg_queue, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), nullptr);
	for(uint32_t addr : sdns::conf[sdns::BIND4_ADDRS]) {
		if(addr==0) {
			eout() << "Wildcard not supported in BIND4_ADDRS, you must specify actual bind addresses";
			abort();
		}
		try {
			csocket lsock(AF_INET, SOCK_STREAM);
			lsock.setopt_exclusiveaddruse();
			sockaddrunion su;
			write_sockaddr(addr, htons(sdns::conf[sdns::DNS_PORT]), &su);
			lsock.bind(su);
			lsock.listen();
			lsock.setopt_nonblock();
			clients.emplace_back(lsock.release_fd(), pvevent::read, std::bind(&tcp_thread::listen_socket_event, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), nullptr);
		} catch(const check_err_exception &e) {
			char buf[INET_ADDRSTRLEN];
			eout() << "Error creating TCP listen socket for " << inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN) << " port " << sdns::conf[sdns::DNS_PORT] << ": " << e;
			abort();
		}
	}
	for(in6_addr addr : sdns::conf[sdns::BIND6_ADDRS]) {
		const uint8_t zero[16] = {0};
		if(memcmp(addr.s6_addr, zero, 16) == 0) {
			eout() << "Wildcard not supported in BIND6_ADDRS, you must specify actual bind addresses";
			abort();
		}
		try {
			csocket lsock6(AF_INET6, SOCK_STREAM);
			lsock6.setopt_exclusiveaddruse();
			lsock6.setopt_ipv6only(csocket::YES);
			sockaddrunion su;
			write_sockaddr(addr.s6_addr, htons(sdns::conf[sdns::DNS_PORT]), &su);
			lsock6.bind(su);
			lsock6.listen();
			lsock6.setopt_nonblock();
			clients.emplace_back(lsock6.release_fd(), pvevent::read, std::bind(&tcp_thread::listen_socket_event, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), nullptr);
		} catch(const check_err_exception &e) {
			char buf[INET6_ADDRSTRLEN];
			eout() << "Error creating TCP listen socket for " << inet_ntop(AF_INET6, addr.s6_addr, buf, INET6_ADDRSTRLEN) << " port " << sdns::conf[sdns::DNS_PORT] << ": " << e;
			abort();
		}
	}
	query_socket_event_function = std::bind(&tcp_thread::query_socket_event, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
}

// thread entrypoint
void tcp_thread::operator()()
{
	timers.add(15, std::bind(&tcp_thread::cleanup_idle, this));
	while(running) {
		try {
			int next_timer = timers.exec();
			clients.event_exec_wait(next_timer);
		} catch(const e_exception &e) {
			eout() << "Failure in TCP event loop: " << e;
			abort();
		}
	}
}

void tcp_thread::listen_socket_event(size_t index, pvevent event, sock_err err)
{
	if(event == pvevent::read) {
		dout() << "ready to read event on TCP listen fd at " << index;
		try {
			csocket_borrow lfd(clients.get_fd(index));
			sockaddrunion peer;
			csocket client = lfd.accept(&peer);
			client.setopt_nonblock();
			csocket::sock_t fd = client.fd();
			if(clients.size() < sdns::conf[sdns::MAX_TCP_CLIENTS])
				clients.emplace_back(fd, pvevent::read, query_socket_event_function, std::make_shared<tcp_peer>(dns_tcp_socket(std::move(client)), clients.size()));
			else
				dout() << "Rejected TCP client because there are already " << sdns::conf[sdns::MAX_TCP_CLIENTS] << " TCP clients";
		} catch(const check_err_exception &e) {
			eout() << "Error accepting TCP client connection:" << e;
		}
	} else {
		eout() << "error on TCP thread listen socket descriptor: " << err;
	}
}

void tcp_thread::query_socket_event(size_t i, pvevent event, sock_err err)
{
	if(event & pvevent::write)
		send_data(i);
	if(event & pvevent::read)
		recv_data(i);
	if(event & pvevent::error)
		dout() << "error in dnsd TCP thread at idx " << i << ": " << err;
}


void tcp_thread::send_msg(dbuf &msg, size_t len, std::weak_ptr<tcp_peer>& peerp)
{
	if(peerp.expired())
		return;
	std::shared_ptr<tcp_peer> peer(peerp);
	if(peer->index == SIZE_MAX)
		return;
	dout() << "tcp_thread::send_msg";
	try {
		if(!peer->sock.send_tcpmsg(std::move(msg), len))
			clients.add_events(peer->index, pvevent::write);
	} catch(const check_err_exception &e) {
		eout() << "TCP thread could not send to peer: " << e;
		clients.mark_defunct(peer->index);
	}
}

void tcp_thread::send_data(size_t idx)
{
	dout() << "tcp_thread::send_data";
	tcp_peer &peer = *clients[idx];
	peer.last_access = std::chrono::steady_clock::now();
	try {
		if(peer.sock.send())
			clients.clear_events(peer.index, pvevent::write);
	} catch(const check_err_exception &e) {
		eout() << "Could not send data to TCP client: " << e;
		clients.mark_defunct(idx);
	}
}

void tcp_thread::recv_data(size_t idx)
{
	dout() << "tcp_thread::recv_data";
	tcp_peer &peer = *clients[idx];
	peer.last_access = std::chrono::steady_clock::now();

	try {
		dns_message msg = peer.sock.recv_dnsmsg();
		if(msg.question().size() > 0) {
			sockaddrunion fromaddr;
			dout() << "process_query() from TCP client " << clients[idx]->sock.getpeername(fromaddr) << ": " << msg;
			// TCP messages should never be truncated, discard any that are
			if(!msg.header().tc)
				el->client_msg(std::move(msg), std::weak_ptr<tcp_peer>(clients[idx]));
			else
				wout() << "Discarded invalid truncated DNS response from TCP connection";
		} else if(sock_err::get_last() == sock_err::enotconn) {
			dout() << "client closed TCP connection at idx " << idx;
			clients.mark_defunct(idx);
		} // (else message not complete and ewouldblock, keep waiting for rest of message)
	} catch (const e_check_sock_err & e) {
		eout() << "Could not receive message from TCP client:" << e;
		clients.mark_defunct(idx);
	} catch(const e_exception &e) {
		eout() << "Failed to parse DNS message from TCP client: " << e;
		clients.mark_defunct(idx);
	}
}

void tcp_thread::cleanup_idle()
{
	std::chrono::time_point<std::chrono::steady_clock> idle = std::chrono::steady_clock::now() - std::chrono::seconds(15);
	for(size_t i=TCP_NONPEER::NUM_NONPEER_FDS; i < clients.size(); ++i) {
		if(clients[i] != nullptr && clients[i]->last_access < idle) {
			dout() << "Evicting idle TCP client connection at " << i;
			clients.mark_defunct(i);
		}
	}
	timers.add(15, std::bind(&tcp_thread::cleanup_idle, this));
}

void tcp_thread::send_client_response_message_tcp(dns_message &&msg, std::weak_ptr<tcp_peer> &peer, const edns_options &/*not required here*/)
{
	dbuf sendbuf(msg.maxsize() + sizeof(uint16_t));
	size_t len = msg.write(sendbuf + sizeof(uint16_t));
	sendbuf[0] = (len >> 8);
	sendbuf[1] = (len & 0xff);
	interthread_msg_queue.put(std::bind(&tcp_thread::send_msg, this, std::move(sendbuf), len + sizeof(uint16_t), peer));
}

void tcp_thread::cleanup_connection(size_t remove_index)
{
	if(clients.back() != nullptr)
		clients.back()->index = remove_index; // back() becomes remove_index
	if(clients[remove_index] != nullptr)
		clients[remove_index]->index = SIZE_MAX;
	clients.set_fd(remove_index, INVALID_SOCKET); // dns_tcp_socket will close, pollvector should not
}
