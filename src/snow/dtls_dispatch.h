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

#ifndef DTLS_DISPATCH_H
#define DTLS_DISPATCH_H
#include "../common/pollvector.h"
#include "../common/common.h"
#include "../common/network.h"
#include "../common/dbuf.h"
#include<vector>
#include<queue>
#include<unordered_map>
#include<set>

class dtls_peer;
struct dtls_socket
{
	std::unordered_map< ip_info, std::shared_ptr<dtls_peer> > peers;
	csocket sock;
	sockaddrunion local_addr;
	enum SOCKET_FLAGS {
		PERSISTENT = 1 // socket is used for incoming connections, do not close/remove even if no peers, unless error occurs
	};
	uint32_t flags;
	dtls_socket(csocket&& s, const sockaddrunion& local, uint32_t flgs=0) : sock(std::move(s)), local_addr(local), flags(flgs) {}
};

struct port_detect_nonce
{
	uint64_t nonce0;
	uint64_t nonce1;
	port_detect_nonce() : nonce0(getrand<uint64_t>()), nonce1(getrand<uint64_t>()) {}
	port_detect_nonce(const uint8_t* data) { memcpy(this, data, sizeof(port_detect_nonce)); }
	port_detect_nonce(const port_detect_nonce&) = default;
	port_detect_nonce& operator=(const port_detect_nonce&) = default;
	bool operator==(const port_detect_nonce& pdn) const { return nonce0 == pdn.nonce0 && nonce1 == pdn.nonce1; }
	const uint8_t* bytes() { return reinterpret_cast<uint8_t*>(this); }
};
static_assert(sizeof(port_detect_nonce)==16, "unexpected padding in port_detect_nonce");
// std::hash specialization for port_detect_nonce
namespace std
{
template<>
struct hash<port_detect_nonce>
{
	size_t operator()(const port_detect_nonce& pdn) const { 
		return pdn.nonce0 ^ pdn.nonce1;
	}
};
}


class vnet;
class peer_init;
class snow_hello;
class tls_conn;
class packet_buf;
class vnet_peer;
class snow_port_detect;
class hashkey;
class nameserv;
class dht;
class dht_connect_info;
class worker_thread;
class dtls_dispatch
{
	pollvector<dtls_socket> sockets;
	function_tqueue interthread_msg_queue;
	timer_queue timers;
	buffer_list buflist;
	std::unique_ptr<vnet> vn;
	std::unique_ptr<peer_init> pinit;
	dht* dht_thread;
	nameserv* nameserv_thread;
	uint16_t nbo_dhtport;
	std::unordered_map<ip_info, size_t> socket_map; // maps ip info to socket index
	std::unordered_map< port_detect_nonce, std::weak_ptr<dtls_peer> > port_nonce_map;
	std::queue< std::weak_ptr<dtls_peer> > cleanup_queue;
	std::function<void(size_t,pvevent,sock_err)> peer_socket_event_function;
	enum RUN_STATE { RUNNING, SHUTDOWN_PENDING, SHUTDOWN };
	RUN_STATE run_state;
	uint32_t natpmp_addr; // NBO IPv4 public addr if natpmp/upnp has provided one, zero otherwise
	uint16_t natpmp_port; // port mapped from natpmp_addr via natpmp/upnp
	std::unordered_map<ip_info, size_t> peer_visible_addrs; // what peers see as this node's IP address, maps to # peers seeing that address
	std::vector<ip_union> local_interface_addrs; // local interface addresses with sockets bound to them
	// IP addresses thought to belong to this node, to validate whether peer is seeing the right address / detect MITM, and provide addrs for DHT CONNECT
	std::vector<ip_info> local_advertised_addrs; // (may include natpmp addr or peer visible addrs)
	std::vector<sockaddrunion> detect_local_addrs(uint32_t nbo_tun_addr);
	void update_dht_local_ipaddrs();
	void set_icmp_pmtu(const ip_info& local, const ip_info& remote, uint16_t mtu);
	void icmp_unreachable(const ip_info& local, const ip_info& remote);
	void do_shutdown_thread_pending();
	void do_shutdown_thread();
	void create_socket(const sockaddrunion& su, uint32_t flags = 0); // throws check_err_exception
	void send_holepunch(const sockaddrunion& local, const sockaddrunion& remote);

	void peer_socket_event(size_t index, pvevent event, sock_err err);
	void icmp_socket_event(size_t index, pvevent event, sock_err err);
	void icmp6_socket_event(size_t index, pvevent event, sock_err err);
	void cleanup_socket(size_t index);
	void query_natpmpupnp();
	void natpmpupnp_results(uint32_t addr, uint16_t port) {
		interthread_msg_queue.put(std::bind(&dtls_dispatch::process_natpmpupnp_results, this, addr, port));
	}
	void process_natpmpupnp_results(uint32_t addr, uint16_t port);
public:
	enum DISPATCH_NONPEER { TUNTAP_FD, INTERTHREAD_FD, ICMP4_FD, ICMP6_FD,		/* not an actual fd: */ NUM_NONPEER_FDS };
	dtls_dispatch(worker_thread* io);
	~dtls_dispatch();
	dtls_socket& get_socket(const sockaddrunion& ip, in_port_t local_port); // creates if necessary, throws e_check_sock_err
	const std::vector<ip_info>& get_advertised_ipaddrs() { return local_advertised_addrs; } // this produces the addresses to be used by peers to reach this node
	bool is_running() { return run_state == RUNNING; }
	void add_peer_visible_ipaddr(const ip_info& visible_ipaddr);
	void holepunch_request(std::vector<ip_info>&& addrs) { interthread_msg_queue.put(std::bind(&dtls_dispatch::do_holepunch, this, std::move(addrs), 0)); }
	void do_holepunch(const std::vector<ip_info>& addrs, in_port_t port);
	void decrement_peer_visible_ipaddr(const ip_info& visible_ipaddr);
	void send_port_detect_nonce(std::shared_ptr<vnet_peer>& peer);
	void snow_port_detect_packet(snow_port_detect* packet, vnet_peer& frompeer);
	bool check_port_detect_nonce(const uint8_t* nonce_data, const sockaddrunion& fromaddr);
	void update_peer(const ip_info& local, const ip_info& remote, std::shared_ptr<dtls_peer> newpeer);
	void remove_peer(const ip_info& local, const ip_info& remote);
	void cleanup_peer(const std::weak_ptr<dtls_peer>& peer) { cleanup_queue.emplace(peer); }
	// cleanup_peers may cause destruction of dtls_peer objects
	bool cleanup_peers(); // returns true if any peers were cleaned up

	
	void operator()(); // thread entrypoint
	void set_dhtport(uint16_t dhtport) { nbo_dhtport = dhtport; }
	uint16_t get_dhtport() { return nbo_dhtport; }
	void set_pointers(dht* d, nameserv* ns);
	// shutdown pending: stop accepting new connections
	void shutdown_thread_pending() {
		interthread_msg_queue.put(std::bind(&dtls_dispatch::do_shutdown_thread_pending, this));
	}
	// shutdown: orderly exit thread
	void shutdown_thread() {
		interthread_msg_queue.put(std::bind(&dtls_dispatch::do_shutdown_thread, this));
	}
	void check_connection(const hashkey& fingerprint);
	void check_all_connections();
	void touch_connection(const hashkey& fingerprint);
	void add_peer(dht_connect_info&& info);
	const hashkey& get_hashkey();
	uint32_t virtual_interface_ipaddr();
};

// wrap dtls_dispatch, exposing only functions callable by other threads
class dtls_dispatch_thread
{
	dtls_dispatch dispatch;
public:
	// for main():
	dtls_dispatch_thread( worker_thread* io) : dispatch(io) {}
	void operator()() { dispatch(); } // thread entrypoint	
	void set_pointers(dht* d, nameserv* ns) { dispatch.set_pointers(d, ns); } // call before starting thread
	void set_dhtport(uint16_t nbo_dhtport) { dispatch.set_dhtport(nbo_dhtport) ;} // call before starting thread
	void shutdown_thread_pending() { dispatch.shutdown_thread_pending(); }
	void shutdown_thread() { dispatch.shutdown_thread(); }
	// for other threads:
	void check_connection(const hashkey& fingerprint) { dispatch.check_connection(fingerprint); }
	void check_all_connections() { dispatch.check_all_connections(); }
	void touch_connection(const hashkey& fingerprint) { dispatch.touch_connection(fingerprint); }
	void add_peer(dht_connect_info&& info) { dispatch.add_peer(std::move(info)); }
	void holepunch_request(std::vector<ip_info>&& addrs) { dispatch.holepunch_request(std::move(addrs)); }
	const hashkey& get_hashkey() { return dispatch.get_hashkey(); }
	uint32_t virtual_interface_ipaddr() { return dispatch.virtual_interface_ipaddr(); }	
};

#endif // DTLS_DISPATCH_H
