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

#ifndef EVENTLOOP_H
#define EVENTLOOP_H
#include<functional>
#include<memory>
#include "../common/pollvector.h"
#include "../common/common.h"
#include "dns_query_init.h"

class dns_query;
class dns_response;
class dns_message;
class edns_options;
class tcp_thread;
class tcp_peer;
class eventloop
{
	timer_queue timers;
	function_tqueue interthread_msg_queue;
	tcp_thread *tcp;
	pollvector< std::shared_ptr<dns_query> > queries;
	bool running;
	dns_query_init qinit;
	
	void listen_socket_event(size_t index, pvevent event, sock_err err, std::shared_ptr<csocket::sock_t>&);
	void query_socket_event(size_t index, pvevent event, sock_err err);
	void snow_query_socket_event(size_t index, pvevent event, sock_err err);
	void write_sendbuf(size_t index);
	void send_client_response_message_udp(dns_message &&answer, const sockaddrunion &client, const std::weak_ptr<csocket::sock_t> &sd, const edns_options &options);
	void recvmsg(dns_message &msg, std::weak_ptr<tcp_peer> &peer);
public:
	enum EVENTLOOP_NONPEER { INTERTHREAD_FD,	/*this is not an actual FD:*/ NUM_NONPEER_FDS};
	eventloop(tcp_thread *p);
	void operator()(); // thread entrypoint
	void stop() { interthread_msg_queue.put( [this](){running = false;} ); };
	void client_msg(dns_message &&msg, std::weak_ptr<tcp_peer> &&peer);
	void reread_static_records() {
		interthread_msg_queue.put(std::bind(&dns_query_init::reread_static_records, &qinit));
	}
	template<class...Args> void add_timer(Args&&... args) { timers.add(std::forward<Args>(args)...); }
};

#endif // EVENTLOOP_H

