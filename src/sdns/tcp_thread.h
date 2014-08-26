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

#ifndef TCP_THREAD_H
#define TCP_THREAD_H
#include<memory>
#include"../common/network.h"
#include"../common/common.h"
#include"../common/pollvector.h"
#include"dns_socket.h"


// this is only for TCP clients, dns_tcp_socket handles TCP connections to servers directly in eventloop
struct tcp_peer
{
	dns_tcp_socket sock;
	size_t index;
	std::chrono::time_point<std::chrono::steady_clock> last_access;
	tcp_peer(dns_tcp_socket &&s, size_t i) : sock(std::move(s)), index(i), last_access(std::chrono::steady_clock::now()) {}
};

// TCP listen socket accepts new client connections
// for each existing client connection, if the connection hasn't been used in e.g. 60 seconds, close and remove it
// then, if we have a send buffer for a client, poll for write and write so much as can be written until buffer is empty
// and for each connection, poll for read and construct completed messages to be forwarded to main event loop
// when we get a message, send the message and the weak_ptr to the event loop
	// when event loop has response, it sends response and weak_ptr back here for write
	// message is written so long as weak_ptr points to non-expired tcp_peer with valid index (closed peers have SIZE_MAX index)
// if we get message and existing message is already present, new sendbuf is allocated and remainder of existing message + new message is copied into it
	// unless total size would exceed threshold, in which case new message is dropped

// TCP thread is only used for TCP clients, TCP connections to servers are handled in main eventloop
class eventloop;
class dns_message;
class edns_options;
class tcp_thread
{
	timer_queue timers;
	function_tqueue interthread_msg_queue; 
	pollvector< std::shared_ptr<tcp_peer> > clients;
	std::function<void(size_t,pvevent,sock_err)> query_socket_event_function;
	eventloop *el;
	bool running;
	enum TCP_NONPEER { INTERTHREAD_FD, NUM_NONPEER_FDS };
	void listen_socket_event(size_t index, pvevent event, sock_err err);
	void query_socket_event(size_t index, pvevent event, sock_err err);
	void send_msg(dbuf &msg, size_t len, std::weak_ptr<tcp_peer>& peer);
	void send_data(size_t idx);
	void recv_data(size_t idx);
	void cleanup_idle();
public:
	tcp_thread();
	void operator()(); // thread entrypoint
	void set_pointers(eventloop *p) { el = p; }
	void send_client_response_message_tcp(dns_message &&msg, std::weak_ptr<tcp_peer> &peer, const edns_options &);
	void cleanup_connection(size_t remove_index);
	void stop() { interthread_msg_queue.put( [this](){running = false;} ); };
};

#endif // TCP_THREAD_H
