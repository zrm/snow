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

#include<random>
#include<algorithm>
#include "eventloop.h"
#include "tcp_thread.h"
#include "dns_query.h"
#include "../common/err_out.h"

eventloop::eventloop(tcp_thread *tcpp)
	: queries(std::bind(&dns_query_init::cleanup_query, &qinit, std::placeholders::_1), eventloop::EVENTLOOP_NONPEER::NUM_NONPEER_FDS, "main loop"),
	  running(true), qinit(queries, timers, &eventloop::query_socket_event, this)
{
	tcp = tcpp;
	queries.emplace_back(interthread_msg_queue.getSD(), pvevent::read, std::bind(&function_tqueue::pv_execute, &interthread_msg_queue, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), nullptr);
	queries.emplace_back(qinit.snow_sock_fd(), pvevent::read, std::bind(&eventloop::snow_query_socket_event, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), nullptr);

	// TODO: wildcard bind support
		// DNS requires the reply to come from the same address as the request was sent to and for multihomed hosts the default outgoing address may not be the correct one
		// so it is not possible to just bind the wildcard on one socket and use that
		// the correct thing to do here is if BIND_ADDRS contains the wildcard address then enumerate the interfaces and bind a socket for each address
		// (and if snow is configured, exclude the snow virtual interface address, e.g. by resolving local.key, unless it is explicitly included in BIND4_ADDRS)
		// this means sdns would have to be restarted to bind a new address if one is added after dropping privileges
			// (or implement some ugly hack to allow partial retention of privilges, and a way on each platform to detect that a new address has been added)
	
	for(uint32_t addr : sdns::conf[sdns::BIND4_ADDRS]) {
		if(addr==0) {
			eout() << "Wildcard not supported in BIND4_ADDRS, you must specify actual bind addresses";
			abort();
		}
		try {
			csocket lsock(AF_INET, SOCK_DGRAM);
			lsock.setopt_exclusiveaddruse();
			sockaddrunion su;
			write_sockaddr(addr, htons(sdns::conf[sdns::DNS_PORT]), &su);
			lsock.bind(su);
			lsock.setopt_nonblock();
			csocket::sock_t sd = lsock.release_fd();
			queries.emplace_back(sd, pvevent::read, std::bind(&eventloop::listen_socket_event, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::make_shared<csocket::sock_t>(sd)), nullptr);
		} catch(const check_err_exception &e) {
			char buf[INET_ADDRSTRLEN];
			eout() << "Error creating UDP socket for " << inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN) << " port " << sdns::conf[sdns::DNS_PORT] << ": " << e;
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
			csocket lsock6(AF_INET6, SOCK_DGRAM);
			lsock6.setopt_exclusiveaddruse();
			lsock6.setopt_ipv6only(csocket::YES);
			sockaddrunion su;
			write_sockaddr(addr.s6_addr, htons(sdns::conf[sdns::DNS_PORT]), &su);
			lsock6.bind(su);
			lsock6.setopt_nonblock();
			csocket::sock_t sd = lsock6.release_fd();
			queries.emplace_back(sd, pvevent::read, std::bind(&eventloop::listen_socket_event, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::make_shared<csocket::sock_t>(sd)), nullptr);
		} catch(const check_err_exception &e) {
			char buf[INET6_ADDRSTRLEN];
			eout() << "Error creating UDP socket for " << inet_ntop(AF_INET6, addr.s6_addr, buf, INET6_ADDRSTRLEN) << " port " << sdns::conf[sdns::DNS_PORT] << ": " << e;
			abort();
		}
	}

}

void eventloop::operator()()
{
	qinit.ipv6_test();
	while(running) {
		try {
			int next_timer = timers.exec();
			queries.event_exec_wait(next_timer);
		} catch(const e_exception &e) {
			eout() << "Failure in main event loop: " << e;
			abort();
		}
	}
}

void eventloop::listen_socket_event(size_t i, pvevent event, sock_err err, std::shared_ptr<csocket::sock_t>& sd)
{
	if(queries.get_fd(i) != *sd) {
		dout() << "BUG: listen_socket_event socket " << queries.get_fd(i) << " did not match expected socket " << *sd << " at index " << i;
		return;
	}
	sockaddrunion fromaddr;
	// as of EDNS0 UDP msg can be up to 64KiB, even for query as OPT RR can be arbitrarily large
	uint8_t buf[65535]; 
	if(event != pvevent::read) {
		dout() << "error on client query listen socket: " << err;
		return;
	}		
	try {
		csocket_borrow lsock(queries.get_fd(i));
		size_t bytes = lsock.recvfrom(buf, sizeof(buf), &fromaddr);
		try {
			dns_message msg(buf, bytes);
			dout() << "process_query() from UDP client " << fromaddr << ": " << msg;
			qinit.process_query(msg, std::bind(&eventloop::send_client_response_message_udp, this, std::placeholders::_1, fromaddr, std::weak_ptr<csocket::sock_t>(sd), std::placeholders::_2));
		} catch(const e_exception &e) {
			// in theory should send back FORMAT_ERROR, but:
			// RFC6891 Sec. 7 states that an EDNS0 FORMAT_ERROR response MUST contain a header, question section and OPT record in additional section
			// the trouble is that the message doesn't parse: either some field was truncated or there was an invalid character in the qname etc.
				// a primary cause of this is somebody sending garbage to the name resolver (e.g. wrong protocol), in which case a response is not useful
			// and sending a response would seem to require attempting to interpret garbage to extract a question section / qname
				// and then putting this garbage into the response, which could cause peer misbehavior (especially if the query was sent from a spoofed IP addr)
			// so it seems the best thing to do with a message this defective is to just ignore it and not even send a response
			wout() << "Could not parse DNS query from " << fromaddr << ": " << e << " (query was defective so it had to be discarded)";
		}
	} catch(const e_check_sock_err &e) {
		if(sock_err::get_last() != sock_err::econnreset) {
			eout() << "Network error receiving query from " << fromaddr << ": " << e;
			// anything to be done here? can't do much for a query not received
		} else {
			// some OS (notably windows) give connection reset on UDP recv()/recvfrom() if a previous sendto() got ICMP error
			// annoyingly, there are two plausible causes of this: either DNS amplification DoS attack, or the client just gave up waiting for a legit but slow query
			wout() << "Client at " << fromaddr << " did not want DNS query response";
		}
	}
}

void eventloop::snow_query_socket_event(size_t /*index*/, pvevent event, sock_err err)
{
	if(event & pvevent::error) {
		eout() << "Error event on snow query socket: " << err;
		iout() << "Please check that the snow daemon is running. If you are not using snow you should add the line \"SNOW=FALSE\" to " << sdns::conf[sdns::CONFIG_FILE];
		qinit.snow_socket_error();
	} else {
		qinit.snow_socket_event();
	}
}

void eventloop::query_socket_event(size_t i, pvevent event, sock_err err)
{
	sockaddrunion fromaddr;
	if(event & pvevent::write)
		write_sendbuf(i);
	if(event & pvevent::read) {
		try {
			queries[i]->getpeername(fromaddr);
			dns_message msg = queries[i]->recv_dnsmsg();
			if(msg.question().size() > 0) {
				qinit.process_response(msg, fromaddr, *queries[i]);
			} else if(sock_err::get_last() == sock_err::enotconn) {
				queries[i]->send_query(); // (TCP) try again with next ns if any
			}
		} catch(const e_check_sock_err &e) {
			dout() << "Network error receiving query response: " << e;
			queries[i]->retry_query(); // try again but don't discard existing yet, maybe sock error was non-fatal
		} catch(const e_exception &e) {
			dout() << "Error parsing DNS message from " << fromaddr << ": " << e;
			queries[i]->send_query(); // try again with next ns if any
		}
	}
	if(event & pvevent::error) {
		dout() << "Got poll error in dnsd main eventloop at idx " << i << ": " << err;
		queries[i]->retry_query(); // try again but don't discard existing yet, maybe error was non-fatal
	}
}

void eventloop::write_sendbuf(size_t index)
{
	try {
		if(queries[index]->send_buffered())
			queries.set_events(index, pvevent::read);
	} catch(const e_check_sock_err &e) {
		dout() << "write_sendbuf got exception: " << e;
		queries[index]->retry_query();
	}
}

void eventloop::send_client_response_message_udp(dns_message &&answer, const sockaddrunion &client, const std::weak_ptr<csocket::sock_t> &sd, const edns_options &client_options)
{
	if(std::shared_ptr<csocket::sock_t> sdptr = sd.lock()) {
		dout() << "Sending to client at " << client << ": " << answer;
		dbuf sendbuf(answer.maxsize());
		size_t len = answer.write(sendbuf);
		size_t max_buf = std::min<size_t>(client_options.get_udp_bufsize(), sdns::conf[sdns::MAX_CLIENT_UDP_RESPONSE]);
		// (never exceed MAX_CLIENT_UDP_RESPONSE to reduce damage done by attacker spoofing query source address; TODO: possibly ignore this in case of localhost)
		if(len > max_buf) {
			answer.truncate();
			sendbuf.resize(answer.maxsize()); // probably unnecessary
			len = answer.write(sendbuf);
			dout() << "Excessive message size, truncating: " << answer;
			if(len > max_buf) {
				dout() << "Message size (" << len << ") was still excessive (>" << max_buf << ") after truncation (this should not happen), message dropped";
				return;
			}
		}
		try {
			csocket_borrow sock(*sdptr);
			size_t bytes = sock.sendto(sendbuf, len, client);
			dout() << "Wrote " << bytes << " bytes to client socket";
		} catch(const check_err_exception &e) {
			eout() << "Could not write to client socket:" << e;
		}
	} else {
		dout() << "Failed to send_client_response_message_udp to " << client << " because UDP socket no longer exists";
	}
}

void eventloop::recvmsg(dns_message &msg, std::weak_ptr<tcp_peer> &peer)
{
	// messages from TCP thread are always queries
	qinit.process_query(msg, std::bind(&tcp_thread::send_client_response_message_tcp, tcp, std::placeholders::_1, peer, std::placeholders::_2));
}


void eventloop::client_msg(dns_message &&msg, std::weak_ptr<tcp_peer> &&peer)
{
	interthread_msg_queue.put(std::bind(&eventloop::recvmsg, this, std::move(msg), std::move(peer)));
}
