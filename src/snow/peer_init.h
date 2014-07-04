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

#ifndef PEER_INIT_H
#define PEER_INIT_H
#include"tls.h"
#include"../common/common.h"
#include"../common/pollvector.h"
#include"configuration.h"
#include"../common/err_out.h"
#include"handshake.h"
#include<map>
#include<unordered_map>
#include<unordered_set>
#include<list>
#include<bitset>


struct dht_connect_retry
{
	enum RETRY_TYPE { NORMAL_ROUTE, // trackback _forward_ using route map
					  TRACKBACK, // follow trackback route using trackback_route_id
					  FIRST_HOP, // route to peer with first_hop hashkey if it is connected (e.g. connect after CHECK_ROUTE failure: want same route as original CHECK_ROUTE)
					  BOOTSTRAP }; // original was DHT bootstrap connection, so don't retry this peer, retry a different known peer
	RETRY_TYPE retry_type;
	hashkey first_hop;
	uint64_t trackback_route_id;
	std::vector<ip_info> holepunch_addrs; // this is empty until swapped for dht_connect_info's IP addrs (used to send holepunch for retry)
	in_port_t holepunch_port; // peer's outgoing port, to send holepunch before sending CONNECT
	enum RETRY_FLAGS { NO_RETRY, NUM_FLAGS };
	std::bitset<RETRY_FLAGS::NUM_FLAGS> flags;
	dht_connect_retry(RETRY_TYPE rtyp, in_port_t hp_port, bool no_retry) : dht_connect_retry(rtyp, hp_port, no_retry, 0, hashkey()) {}
	dht_connect_retry(RETRY_TYPE rtyp, in_port_t hp_port, bool no_retry, const hashkey& hop) : dht_connect_retry(rtyp, hp_port, no_retry, 0, hop) {}
	dht_connect_retry(RETRY_TYPE rtyp, in_port_t hp_port, bool no_retry, uint64_t trackback_id) : dht_connect_retry(rtyp, hp_port, no_retry, trackback_id, hashkey()) {}
	dht_connect_retry(RETRY_TYPE rtyp, in_port_t hp_port, bool no_retry, uint64_t trackback_id, const hashkey& hop)
		: retry_type(rtyp), first_hop(hop), trackback_route_id(trackback_id), holepunch_port(hp_port) {
		if(no_retry) flags[NO_RETRY] = true;
	}
	bool operator==(const dht_connect_retry& dcr) const {
		return retry_type == dcr.retry_type && first_hop==dcr.first_hop && trackback_route_id == dcr.trackback_route_id
				&& holepunch_addrs == dcr.holepunch_addrs && flags == dcr.flags;
	}
};

struct dht_connect_info
{
	hashkey peer;
	std::vector<ip_info> ip_addrs;
	std::shared_ptr<dht_connect_retry> connect_retry;
	enum CONNECT_FLAGS {
		REMOTE_REQUEST=1 }; // indicates that connect request came from DHT and is to be treated with additional suspicion
	uint32_t flags;
	bool get_flag(CONNECT_FLAGS flag) { return flags & flag; }
	dht_connect_info(hashkey&& peer_hk, std::vector<ip_info>&& addrs, bool remote_req, std::shared_ptr<dht_connect_retry>&& retry) 
		: peer(std::move(peer_hk)), ip_addrs(std::move(addrs)), connect_retry(std::move(retry)) {
		if(remote_req)
			flags|=REMOTE_REQUEST;
	}
};


class dup_map
{
	typedef std::list< std::weak_ptr<snow_handshake_conn> > duplist;
	std::unordered_map<hashkey, duplist> duplicates;
public:
	// try to activate peer, register as duplicate if active peer already exists; returns true if entry did not already exist
	bool activate_peer(const snow_handshake_conn& conn) {
		auto entry = duplicates.emplace(conn.get_pubkey().get_hashkey(md_hash::SHA2, 32), duplist());
		if(entry.second == false)
			{ entry.first->second.push_back(conn.get_wptr()); } // entry exists, add as duplicate
		return entry.second;
	}
	void remove_duplicate(const snow_handshake_conn& conn) {
		auto it = duplicates.find(conn.get_pubkey().get_hashkey(md_hash::SHA2, 32));
		if(it != duplicates.end()) {
			for(duplist::iterator dup = it->second.begin(); dup != it->second.end(); ++dup) {
				// equality compare for weak_ptr:
				if(!dup->owner_before(conn.get_wptr()) && !conn.get_wptr().owner_before(*dup)) {
					it->second.erase(dup);
					break;
				}
			}
		}
	}
	// activate_duplicate returns a duplicate to activate if possible, removes the connection entry and returns nullptr if not
	std::shared_ptr<snow_handshake_conn> activate_duplicate(const der_pubkey& pubkey) {
		hashkey pkhk = pubkey.get_hashkey(md_hash::SHA2, 32);
		duplist& lst = duplicates[pkhk];
		duplist::iterator dup = lst.end();
		for(duplist::iterator dup_it = lst.begin(); dup_it != lst.end(); ++dup_it) {
			if(std::shared_ptr<snow_handshake_conn> dup_ptr = dup_it->lock()) {
				if(dup_ptr->is_duplicate()) {
					dup = dup_it;
					// if verified stop, otherwise prefer to keep looking for a verified dup
					if(dup_ptr->is_verified())
						{ break; } 
				}
			}
		}
		std::shared_ptr<snow_handshake_conn> rv = nullptr;
		if(dup == lst.end()) {
			// no dup found, erase entry
			duplicates.erase(pkhk);
		} else {
			rv = dup->lock();
			lst.erase(dup);
		}
		return std::move(rv);
	}
};

class connected_peer_set
{
	// keep quantity because defunct existing conn may come back from vnet after secondary sends replacement
	std::map<hashkey, size_t> connected_peers;
public:
	void register_hashkey(const hashkey& hk) {
		connected_peers.insert(std::pair<hashkey, size_t>(hk, 0)).first->second++;
	}
	bool unregister_hashkey(const hashkey& hk) {
		auto it = connected_peers.find(hk);
		if(it != connected_peers.end()){
			it->second--;
			if(it->second == 0) {
				connected_peers.erase(it);
				return true;
			}
		}
		return false;
	}
	bool exists(const hashkey& hk) { return connected_peers.count(hk) > 0; }
};

class dht;
class vnet;

// peer handshake and connection teardown
class peer_init
{
public:
	enum TLS_NONPEER { TLS_SERVER_FD, INTERTHREAD_FD,			/*not an actual FD:*/ NUM_NONPEER_FDS};
private:
	timer_queue& timers;
	function_tqueue interthread_msg_queue;
	dtls_dispatch* dispatch;
	vnet* vn;
	dht* dht_thread;
	worker_thread* io;
	tls_server tls_listen;

	// peers in handshake
	std::unordered_set< std::shared_ptr<snow_handshake_conn> > handshake_peers;
	// map of pubkeys to zero or more snow_handshake_conn duplicate candidates (entry exists with zero elements if connected but no dups)
	dup_map duplicates;
	// set of hashkeys of active connections in vnet
	connected_peer_set connected_peers; 
	// map hashkeys to would-be connection attempts waiting to be initiated if active connection fails
	std::map< hashkey, std::unordered_set<dht_connect_info*> > attempt_info_map;
	
	std::shared_ptr<snow_handshake_conn> new_connection(dtls_ptr&& newconn, bool remote_request) {
		std::shared_ptr<snow_handshake_conn> newpeer = std::make_shared<snow_handshake_conn>(std::move(newconn), remote_request, false);
		newpeer->set_self(newpeer);
		handshake_peers.emplace(newpeer);
		// simulate event once here (timeout is not set until after the first call to dtls_handshake(), and otherwise could wait forever)
		newpeer->socket_pretend_event();
		return std::move(newpeer);
	}
public:
	peer_init(dtls_dispatch* d, vnet* v, worker_thread* io_t, timer_queue& tq, buffer_list* bl) 
		: timers(tq), dispatch(d), vn(v), io(io_t)
	{
		snow_handshake_conn::set_pointers(d, this, &timers, vn);
		snow_handshake_conn::set_buflist(bl);
		iout() << "Your key is " << tls_listen.get_hashkey().key_string();
	}
	void set_pointers(dht* d) { dht_thread = d; }

	const hashkey& local_hashkey() { return tls_listen.get_hashkey(); }
	const der_pubkey& local_pubkey() { return tls_listen.get_pubkey(); }
	std::shared_ptr<dtls_peer> new_peer_socket_event(const sockaddrunion& local_su, const sockaddrunion& remote_su, uint8_t* buf, size_t readlen, csocket::sock_t sd);
	bool register_connection(snow_handshake_conn& conn) { return duplicates.activate_peer(conn); }
	void register_hashkey(const hashkey &hk) { connected_peers.register_hashkey(hk); }
	void new_connect_info(dht_connect_info& info);
	void attempt_new_connection(const hashkey& hk, const ip_info& ip, std::shared_ptr<dht_connect_retry>& retry, bool remote_request);
	bool connection_exists(const hashkey &hk) { return connected_peers.exists(hk); }
	void exec_retry(std::shared_ptr<dht_connect_retry>& retry, const hashkey &hk);
	void shutdown_connection(dtls_ptr, std::vector<ip_info>&& peer_addrs, in_port_t holepunch_port);
	void cleanup_peer(snow_handshake_conn& remove);
	void cleanup_active(const dtls_ptr& conn, bool active);
	void reconnect_after_failure(hashkey peer, std::vector<ip_info> addrs, in_port_t holepunch_port);
	void shutdown_thread_pending() {
		for(auto& peer : handshake_peers)
			peer->mark_disconnecting();
	}
	void dtls_timeout_occurred(snow_handshake_conn& conn) {
		dout() << "peer_init: dtls timeout occurred for " << conn.get_peer() << " " << conn.get_hashkey();
		dispatch->cleanup_peer(conn.get_wptr());
	}
	size_t peer_count() { return handshake_peers.size(); }
};

#endif // PEER_INIT_H
