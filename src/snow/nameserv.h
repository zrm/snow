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

#ifndef NAMESERV_H
#define NAMESERV_H
#include<string>
#include<unordered_map>
#include"../common/err_out.h"
#include"crypto.h"
#include"../common/common.h"
#include"configuration.h"
#include"../common/network.h"


//TODO: implement some various interesting metadata that could be made available through the name resolver
	// e.g. ask for a particular name (or type? or class? -> class + class-specific types could be interesting)
	// and then we can serve up things we know about the peer, like PMTU or public IP address etc.


/*
nameserv thread:
	Request comes in, nameserv checks internal tables, if found, respond. If not found, dht_thread->lookup(key).
	DHT will process request and pass ultimately to dispatch thread, dispatch thread will call nameserv->lookup_complete(hashkey, nat_ipaddr)
		If nat_ipaddr is nonzero, nameserv caches response and responds with NAT IP. If zero, responds with NXDOMAIN.
	When a peer is disconnected, dispatch will send nameserv another lookup_complete, but with zero as NAT IP. This tells nameserv to remove hashkey/IP from its cache.
*/

class nameserv_lookup_cache
{
	std::unordered_map<hashkey, uint32_t> forward;
	std::unordered_map<uint32_t, hashkey> reverse;
public:
	void insert(const hashkey& key, uint32_t addr) {
		forward[key] = addr;
		reverse[addr] = key;
	}
	void erase(const hashkey& key) {
		auto it = forward.find(key);
		if(it != forward.end()) {
			reverse.erase(it->second);
			forward.erase(it);
		}
	}
	uint32_t get(const hashkey& key) {
		auto it = forward.find(key);
		if(it == forward.end())
			throw e_not_found("nameserv_lookup_cache::get(key)");
		return it->second;
	}
	const hashkey& get(uint32_t addr) {
		auto it = reverse.find(addr);
		if(it == reverse.end())
			throw e_not_found("nameserv_lookup_cache::get(addr)");
		return it->second;
	}
};

class dht;
class dtls_dispatch_thread;
class nameserv
{
private:
	timer_queue timers;
	dht* dht_thread;
	dtls_dispatch_thread* dispatch;
	function_tqueue interthread_msg_queue;
	csocket nameserv_sock;
	nameserv_lookup_cache lookup_cache;
	uint32_t nbo_local_interface_addr; // IP address on the tuntap interface
	bool running;
	const std::string local_keystring; // always "local.key."
	struct pending_lookup
	{
		sockaddrunion addr;
		std::string name;
		std::chrono::time_point<std::chrono::steady_clock> timestamp;
		pending_lookup(const sockaddrunion& su, const char* n) : addr(su), name(n), timestamp(std::chrono::steady_clock::now()) {}
		pending_lookup(const pending_lookup& pl) : addr(pl.addr), name(pl.name), timestamp(pl.timestamp) {}
	};
	std::unordered_map< hashkey, std::queue<pending_lookup> > pending_lookups; 
	enum NAMESERV_FDS { QUERY_FD, INTERTHREAD_FD,			/*this is not an actual FD:*/ NUM_FDS};
	void do_lookup(size_t index, pvevent event, sock_err err);
	void do_reverse_lookup(const char* buf, const sockaddrunion& peer_addr);
	void do_forward_lookup(const char* buf, size_t len, const sockaddrunion& peer_addr);
	void send_response(const std::string& lu, uint32_t ipaddr, const sockaddrunion& dest) { send_response(lu.c_str(), lu.size()+1, ipaddr, dest); }
	void send_response(const char *lu, size_t lu_size, uint32_t ipaddr, const sockaddrunion& dest);
	void lookup_response(const hashkey& hk, uint32_t nat_addr);
public:
	nameserv(csocket&& sock, dht* dht, dtls_dispatch_thread* dd) : dht_thread(dht), dispatch(dd), nameserv_sock(std::move(sock)), running(true), local_keystring("local.key.") {}
	void lookup_complete(const hashkey& key, uint32_t nat_addr) { interthread_msg_queue.put(std::bind(&nameserv::lookup_response, this, key, nat_addr)); }
	void set_local_addr(const hashkey& key, uint32_t nbo_interface_addr) {
		nbo_local_interface_addr = nbo_interface_addr; // TODO: this may need to be an atomic write, or go in the other thread
		interthread_msg_queue.put(std::bind(&nameserv::lookup_response, this, key, nbo_interface_addr));
	}
	void shutdown_thread() { interthread_msg_queue.put([this]() { running = false; }); }
	void operator()(); // thread entrypoint
};

#endif // NAMESERV_H
