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

#include"nameserv.h"
#include"dht.h"
#include"dtls_dispatch.h"


void nameserv::do_lookup(size_t /*index, always QUERY_FD*/, pvevent event, sock_err err)
{
	if(event != pvevent::read) {
		eout() << "Error on nameserv query socket: " << err;
		return;
	}
	// TODO: support queries that contain peer IP and DTLS port hint to allow connect without DHT lookup (but then set remote request flag in pinit)
	sockaddrunion peer_addr;
	const unsigned BUFSIZE = 2048;  // arbitrary
	char buf[BUFSIZE];
	try {
		size_t len = nameserv_sock.recvfrom(buf, BUFSIZE, &peer_addr);
		if(len == 4/*IPv4 addr size*/) {
			do_reverse_lookup(buf, peer_addr);
		} else if(len > 0 && strnlen(buf, len) + 1 == static_cast<size_t>(len)) {
			do_forward_lookup(buf, len, peer_addr);
		} else {
			eout() << "nameserv recvfrom() returned " << len << "bytes, data indicated " << strnlen(buf,len);
		}
	} catch(const check_err_exception &e) {
		if(sock_err_is_wouldblock(sock_err::get_last())) {
			dout() << "nameserv tried to receive lookup but nothing was there";
			// (do nothing, no query to process)
		} else {
			eout() << "nameserv failed to recvfrom socket:" << e;
		}
	}
}
void nameserv::do_reverse_lookup(const char* buf, const sockaddrunion& peer_addr)
{
	uint32_t nbo_lookup_addr;
	memcpy(&nbo_lookup_addr, buf, sizeof(nbo_lookup_addr));
	dout() << "Got reverse query for " << ss_ipaddr(nbo_lookup_addr);
	try {
		send_response(lookup_cache.get(nbo_lookup_addr).key_string(), nbo_lookup_addr, peer_addr);
	} catch(const e_not_found &) {
		dout() << "reverse query response was: not found";
		send_response("", nbo_lookup_addr, peer_addr);
	}
}
void nameserv::do_forward_lookup(const char* buf, size_t len, const sockaddrunion& peer_addr)
{
	if((local_keystring.size() == len || local_keystring.size() == len-1) && memcmp(local_keystring.c_str(), buf, len-1)==0) {
		dout() << "Got forward query for local keystring, sending response";
		send_response(buf, len, nbo_local_interface_addr, peer_addr);
	} else {
		dout() << "Got forward query for " << buf;
		hashkey key(buf);
		if(key.initialized()) {
			try {
				uint32_t lu_addr = lookup_cache.get(key);
				dout() << "Sending nameserv query response";
				send_response(buf, len, lu_addr, peer_addr);
				// have vnet touch the idle count when this happens to preserve expectations about continued connection lifetime
				dispatch->touch_connection(key);
			} catch(const e_not_found &) {
				pending_lookups[key].emplace(peer_addr, buf);
				timers.add(snow::conf[snow::NAMESERV_TIMEOUT_SECS]+1, [this, key]() {
					auto pending_it = pending_lookups.find(key);
					if(pending_it != pending_lookups.end()) {
						auto timeout = std::chrono::steady_clock::now() - std::chrono::seconds(snow::conf[snow::NAMESERV_TIMEOUT_SECS]);
						std::queue<pending_lookup> &pending = pending_it->second;
						while(pending.size() > 0 && pending.front().timestamp < timeout) {
							send_response(pending.front().name, 0, pending.front().addr); // respond with zero (0.0.0.0) signifying NXDOMAIN
							pending.pop();
						}
						if(pending.size() == 0)
							pending_lookups.erase(pending_it);
					}
				});
				dht_thread->initiate_connection(key);
			}
		} else {
			send_response(buf, len, 0, peer_addr);
		}
	}
}

void nameserv::send_response(const char* lu, size_t lu_size, uint32_t nbo_ipaddr, const sockaddrunion& dest)
{
	uint8_t buf[lu_size + sizeof(nbo_ipaddr)];
	memcpy(buf, lu, lu_size);
	memcpy(buf+lu_size, &nbo_ipaddr, sizeof(nbo_ipaddr));
	try {
		// if sendto returns 0 or -1 it could be EWOULDBLOCK or some error, but client can try again in that case
		size_t sent = nameserv_sock.sendto(buf, lu_size + sizeof(nbo_ipaddr), dest);
		dout() << "nameserv send_response sent " << sent << " byte response with " << lu_size << " byte lookup";
	} catch(const check_err_exception &e) {
		eout() << "Failed to send response to nameserv query: " << e;
	}
}

void nameserv::lookup_response(const hashkey& lu, uint32_t nbo_ipaddr)
{
	if(nbo_ipaddr != 0) {
		dout() << "nameserv thread: got lookup response: " << lu << ", ip " << ss_ipaddr(nbo_ipaddr);
		auto it = pending_lookups.find(lu);
		if(it != pending_lookups.end()) {
			std::queue<pending_lookup>& respond = it->second;
			while(respond.size() > 0) {
				send_response(respond.front().name, nbo_ipaddr, respond.front().addr);
				respond.pop();
			}
			pending_lookups.erase(it);
		}
		lookup_cache.insert(lu, nbo_ipaddr);
	} else {
		// zero signifies that cache entry is no longer valid
		dout() << "nameserv thread: removing lookup cache entry for: " << lu;
		lookup_cache.erase(lu);
	}
}



void nameserv::operator()()
{
	pollvector<int/*not used*/> waitsd([](size_t){/*nop*/}, 0, "nameserv");
	for(size_t i=0; i < NAMESERV_FDS::NUM_FDS; ++i)
		waitsd.emplace_back(INVALID_SOCKET, pvevent::read, nullptr, 0);
	waitsd.set_fd(NAMESERV_FDS::INTERTHREAD_FD, interthread_msg_queue.getSD());
	waitsd.set_event_function(NAMESERV_FDS::INTERTHREAD_FD, [&](size_t,pvevent,sock_err) { interthread_msg_queue.execute(); });
	waitsd.set_fd(NAMESERV_FDS::QUERY_FD, nameserv_sock.fd());
	waitsd.set_event_function(NAMESERV_FDS::QUERY_FD, std::bind(&nameserv::do_lookup, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
	while(running)
	{
		ssize_t next = timers.exec();
		waitsd.event_exec_wait(next);
	}
}
