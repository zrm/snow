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

#ifndef DHT_H
#define DHT_H
#include<cstring>
#include<string>
#include<sstream>
#include<set>
#include<map>
#include<bitset>
#include<memory>
#include"../common/common.h"
#include"../common/err_out.h"
#include"../common/pollvector.h"
#include"../common/network.h"
#include"../common/dbuf.h"
#include"crypto.h"
#include"configuration.h"

	

/*
Simple distributed hash table
1) Nodes are given a hash value, the hash value of their public key (hashkey, AKA public key fingerprint)
2) Each node must connect to the node with the next highest hash value (by asking to retreive it each time a new connection is made, then connecting to the final destination)
	(this ensures at least one path to node with the hash value closest to that of data being inserted)
3) Messages are routed by sending it to the connected peer with hash value nearest to that of the data until the message reaches the destination
*/

/*
DHT operation: there are three things that cause interaction with the DHT:
	1) a lookup has to be sent [and then a timer set to retry it with a different path if it doesn't return]
	2) a lookup response has been returned and has to be processed (i.e. connect to new node, perform another lookup, notify other interested threads, etc.)
	3) a TLS connection has been successfully made (for one reason or another, incoming or outgoing) and the DHT thread needs to connect to the new peer
*/


struct dht_newconn
{
	csocket sock;
	uint32_t nat_addr;
};


class dht;



/*
Failure resistence: whenever a node receives a message to be cached with no closer destination to forward it,
	it nonetheless forwards it to the connected node that would have been closest if this node were to fail.
	That way that node will contain all data required to be held by this node, in case this node were to fail.
Also: Let's make each node connect not only to its closest node, but maybe also the second closest (and third?)
	so that, again, a node removal doesn't as easily result in breakage. 
	(This goes along with the general idea of: Each node connects to log(n) [or e.g. 20] peers:
		one half way across the address space, one a quarter, one an eighth, etc. down to 1/2**20th )
*/


// a name for type checking and clarity, really just a wrapper around a raw message ptr :
struct dhtmsg
{
	const uint8_t* msg;
	dhtmsg(const uint8_t* m) : msg(m) {}
	dhtmsg& operator=(const dhtmsg& m) { msg = m.msg; return *this; }
};


// TODO: maybe messages should have TTL?


class dht_peer_bufs
{
	dbuf read_buf;
	dbuf write_buf;
	size_t write_bytes;
	size_t write_offset;
	// (read buffers are only for partial reads of individual messages, so read "offset" is always zero and read_bytes==read buffer size)
public:
	dht_peer_bufs() : write_bytes(0), write_offset(0) {}
	void buffer_read_data(const uint8_t* buf, size_t size) {
		read_buf = dbuf(buf, size);
	}
	void read_buffered_data(uint8_t* dest) {
		memcpy(dest, read_buf, read_buf.size());
		read_buf = dbuf();
	}
	size_t read_bytes_available() { return read_buf.size(); }
	size_t write_bytes_buffered() { return write_bytes; }
	bool write_buf_empty() { return write_buf.size() == 0; }
	void buffer_write_data(const uint8_t* buf, size_t size) {
		if(write_buf.size() == 0) {
			write_offset = 0;
			write_bytes = 0; // add below
			write_buf = dbuf((size > 8192) ? size : 8192);
		} else {
			if(write_buf.size() < write_offset + write_bytes + size) {
				if(write_buf.size() < write_bytes + size) {
					write_buf.resize((write_bytes + size) * 2);
				} else {
					// existing buf is large enough but needs to have offset zeroed
					memmove(write_buf, write_buf+write_offset, write_bytes);
					write_offset = 0;
				}
			}
		}
		memcpy(write_buf+write_offset+write_bytes, buf, size);
		write_bytes += size;
	}
	size_t write_buffered_data(csocket_borrow sock) { // throws e_check_sock_err
		size_t bytes = sock.send(write_buf + write_offset, write_bytes);
		if(bytes == write_bytes) {
			write_buf = dbuf();
		} else {
			write_bytes -= bytes;
			write_offset += bytes;
		}
		return bytes;
	}
};

struct dht_peer
{
	dht_peer_bufs bufs;
	hashkey fingerprint;
	uint64_t bytes_sent; // total bytes sent to this peer, not including bytes in 'bufs' but not yet transferred
	size_t index;
	std::chrono::time_point<std::chrono::steady_clock> connection_timestamp;
	uint32_t reconnect_delay; 
	std::vector<ip_info> native_addrs; // peer's native IP addrs and DTLS listen ports
	uint16_t dhtport; // NBO (for reconnect attempts on fail)
	uint16_t dtls_srcport; // NBO (for congestion connects?)
	uint32_t nat_ipaddr; // network byte order
	enum DHT_PEER_FLAGS { PRIMARY,	// primary makes first attempt at initiating DHT connection
						  RECEIVED_HELLO, // received HELLO from peer
						  DISCONNECT_CHECK_ROUTE, // removing this node may break DHT routing, after disconnect send CHECK_ROUTE to new antecedent
						  NO_RECONNECT, // no reconnection should be attempted even if shutdown was unclean
						  CLEAN_SHUTDOWN, // peer was clean disconnected with DHT GOODBYE
						  PENDING_PROGRESS_CHECK, // already have a timer checking that peer write buf is making progress, don't set another
						  NUM_FLAGS }; // (not a flag)
	std::bitset<DHT_PEER_FLAGS::NUM_FLAGS> flags;
	dht_peer(const hashkey& f, const std::vector<ip_info>& native, uint16_t dhtprt, uint16_t srcprt, uint32_t nbo_nat_ipaddr, bool pr)
		: fingerprint(f), bytes_sent(0), reconnect_delay(pr ? 0 : 10), native_addrs(native), dhtport(dhtprt), dtls_srcport(srcprt), nat_ipaddr(nbo_nat_ipaddr) {
		flags[DHT_PEER_FLAGS::PRIMARY] = pr;
		connection_timestamp = std::chrono::steady_clock::now();
	}
	dht_peer(dht_peer&& ) = default;
	dht_peer& operator=(dht_peer&& dp) = default;
};


struct dht_connection_timestamp
{
	dht_peer* peer;
	dht_connection_timestamp(dht_peer& p) : peer(&p) {}
	bool operator<(const dht_connection_timestamp& ct) const { return peer->connection_timestamp < ct.peer->connection_timestamp; }
};

class dht_route_map
{
	std::map< hashkey, std::shared_ptr<dht_peer> > route_map;
	std::shared_ptr<dht_peer> antecedent_ptr;
	std::shared_ptr<dht_peer> successor_ptr;
	bool lower_is_closer(const hashkey& hklow, const hashkey& hkhigh, const hashkey& hktarget, int diff = 0)
	{
		// FAIL: what about hashkeys with different lengths but same first n bits
		// also, possible issue: attacker generates keys just above and below target, then connects to everybody near target in the network
			// attacker is closest peer to target, so for all nodes not directly connected to target will route messages to peer through attacker, allowing DoS (or observation etc)
		const uint8_t *low = hklow.get_raw(), *high = hkhigh.get_raw(), *target = hktarget.get_raw();
		size_t min = std::min({hklow.size(), hkhigh.size(), hktarget.size()});
		for(size_t i=0; i < min; ++i) {
			diff += high[i] + low[i] - target[i] - target[i];
			if(diff > 1)
				return true;
			if(diff < -1)
				return false;
			diff <<= 8;
		}
		return diff > 0;
	}
public:
	dht_route_map() {}
	dht_route_map(std::shared_ptr<dht_peer>& local_ptr) : antecedent_ptr(local_ptr), successor_ptr(local_ptr) {
		route_map.insert(std::make_pair(local_ptr->fingerprint, local_ptr));
	}
	const std::shared_ptr<dht_peer>& antecedent() { return antecedent_ptr; }
	const std::shared_ptr<dht_peer>& successor() { return successor_ptr; }
	void insert(std::shared_ptr<dht_peer>& ptr);
	void remove(std::shared_ptr<dht_peer>& ptr);
	dht_peer& nearest_peer(const hashkey& fingerprint) {
		auto it = route_map.lower_bound(fingerprint);
		if(it == route_map.end()) {
			--it; // target is above last peer, put first peer above ceiling
			if(lower_is_closer(it->first, route_map.begin()->first, fingerprint, (1<<8)))
				return *it->second;
			return *route_map.begin()->second;
		}
		if(it == route_map.begin()) {
			auto prev_it = --route_map.end(); // target is at or below first peer, put last peer below floor
			if(lower_is_closer(prev_it->first, it->first, fingerprint, (-1<<8)))
				return *prev_it->second;
			return *it->second;
		}
		auto prev_it = std::prev(it);
		if(lower_is_closer(prev_it->first, it->first, fingerprint))
			return *prev_it->second;
		return *it->second;
	}
	// lower_bound finds the largest peer <= fingerprint
	dht_peer& lower_bound(const hashkey& fingerprint) {
		auto it = route_map.lower_bound(fingerprint);
		if(it == route_map.end())
			it = route_map.begin(); // wrap around
		return *it->second;
	}
	// upper_bound finds the smallest peer > fingerprint
	dht_peer& upper_bound(const hashkey& fingerprint) {
		auto it = route_map.upper_bound(fingerprint);
		if(it == route_map.end())
			--it; // wrap around
		return *it->second;
	}
	/*size_t antecedent(const hashkey& fingerprint) {
		auto it = route_map.lower_bound(fingerprint);
		if(it == route_map.begin())
			it = --route_map.end();
		else
			--it;
		return it->second->index;
	}*/

	bool contains(const hashkey& fingerprint) { return route_map.count(fingerprint) != 0; }
	size_t size() { return route_map.size(); }
};


struct trackback_route
{
	// TODO: why do we use peer hashkey instead of weak_ptr to dht_peer?
	hashkey peer;
	uint64_t route_id;
	trackback_route(const hashkey& hk, uint64_t id) : peer(hk), route_id(id) {}
	trackback_route() {}
};

// TODO : handle peers with dynamic IP addrs (don't want peer with 10,000 IP addrs in the known_peers file when 9999 don't work)
	// at this point this pretty much just involves removing ipaddrs with zero recency (which isn't yet implemented)
struct node_info
{
	friend std::ostream& operator<<(std::ostream& out, const node_info& ni);
	enum { DEFAULT_PEER_RECENCY = 4096, DEFAULT_ADDR_RECENCY = 256 };
	struct ninfo_recency
	{
		uint32_t recency;
		ninfo_recency(uint32_t rec = DEFAULT_ADDR_RECENCY) : recency(rec) {}
	};
	std::map<ip_info, ninfo_recency> addrs;
	// peer recency field is decremented each time a connection attempt fails, reset at each success; peer is removal candidate at zero
	uint32_t recency;
	uint16_t dtls_source_port;
	node_info()	: recency(DEFAULT_PEER_RECENCY) {}
	node_info(const std::vector<std::string>& fields); // fields from known_peers file line, fields[0] (hashkey) is ignored
	node_info(const std::vector<ip_info> &infos, uint16_t dtls_source);
	std::vector<ip_info> get_addrs() {
		std::vector<ip_info> rv;
		rv.reserve(addrs.size());
		for(auto& addr : addrs)
			rv.emplace_back(addr.first);
		return std::move(rv);
	}
};
std::ostream& operator<<(std::ostream& out, const node_info& ni);

struct node_hkinfo
{
	hashkey fingerprint;
	std::vector<ip_info> addrs;
	uint16_t dtls_source_port;
	node_hkinfo(const hashkey& fp, std::vector<ip_info> ips, uint16_t source)
		: fingerprint(fp), addrs(std::move(ips)), dtls_source_port(source) {}
};

class known_peer_set
{
	std::map<hashkey, node_info> known_peers;
	hashkey last_bootstrap;
	uint32_t recency_threshold;
	uint32_t next_recency_threshold;
	size_t active_serial;
	size_t written_serial;
	// mutex rules: DHT thread may read at any time without locking; it is the only thread that may write/modify and will lock to do so,
	// any other thread must lock for any read/access
	// serial variables may be read/written by any thread so any thread including DHT must lock for any access
	mutable std::mutex mtx;
	std::chrono::time_point<std::chrono::steady_clock> too_soon;
	std::vector<std::string> splitstring(const std::string& line);
	void save_modified_data(worker_thread* io); // lock mutex before calling this
	void save_to_disk();
public:
	known_peer_set();
	node_hkinfo get_next_bootstrap();
	void add_peer(const hashkey& fingerprint, uint16_t dtls_srcprt, const std::vector<ip_info>& addrs, worker_thread* io, bool is_client);
	// note: only call mark_fail for bootstrap failures or attacker could reduce rank of target bootstrap peers by sending DHT CONNECT with false parameters
	void mark_fail(const hashkey& target, worker_thread* io); 
	const node_info* get_node_info(const hashkey& hk) { auto it = known_peers.find(hk); if(it != known_peers.end()) return &it->second; return nullptr; }
};

/*
 *	TODO: problem: DHT antecedent or successor and this node are both firewalled and holepunch fails to get them connected for some reason
 *		some mechanism is going to be necessary so that where this happens, both peers connect to a third node and communicate DHT msgs through it
 *		alternative possibility is for successor to connect to antecedent's antecedent and antecedent to connect to successor's successor
 *			that would sort out routing for everybody else and only break messages sent directly to the firewalled nodes
 *			then the firewalled nodes would simply need to know the hashkey of the unreachable node and any node it *is* connected to (e.g. antecedent's antecedent) and send messages specifically to that hashkey through there
 *			[make sure to check that any hashkey this is enabled for is between this node's hashkey and its currently connected antecedent or successor, and is not equal to local hashkey]
*/

class dht_signature;
class dht_hash;
class dht_forward_payload;
class dht_connect_retry;
class dtls_dispatch_thread;
class nameserv;
class dht
{
public:
	dht(dtls_dispatch_thread* dd, worker_thread* io);
	void set_pointers(nameserv* nst) { nameserv_thread = nst; }
	void operator()(); // thread entrypoint
	void listen_socket_event(size_t index, pvevent event, sock_err err);
	void peer_socket_event(size_t index, pvevent event, sock_err err);
	void initiate_connection(const hashkey& h) { interthread_msg_queue.put(std::bind(&dht::do_initiate_connection, this, h)); }
	void newTLS_notify(std::shared_ptr<dht_peer> dntls, bool is_client)
		{ interthread_msg_queue.put(std::bind(&dht::newtls, this, std::move(dntls), is_client)); }
	void notify_disconnect(const hashkey& fp, uint32_t nbo_nat_addr) { interthread_msg_queue.put(std::bind(&dht::dtls_disconnect, this, fp, nbo_nat_addr)); }
	void set_local_ipaddrs(const std::vector<ip_info>& ips) { interthread_msg_queue.put(std::bind(&dht::set_local_ips, this, ips)); }
	void connection_retry(const hashkey& target, std::shared_ptr<dht_connect_retry>& retry);
	void shutdown_thread() { interthread_msg_queue.put(std::bind(&dht::do_shutdown_thread, this)); }

	static const uint16_t DHTMSG_ROUTED_START = 0;
	static const uint16_t DHTMSG_DIRECT_START = 32768;
	enum class DHTMSG : std::uint16_t {
					CONNECT = DHTMSG_ROUTED_START, HOLEPUNCH_ADDRS, MISMATCH_DETECTED, CHECK_ROUTE, TRACKBACK_FORWARD, FORWARD,
																		/*this is not an actual message:*/MAX_ROUTED_DHT_MESSAGE,
					NOP = DHTMSG_DIRECT_START, HELLO, CHECK_ROUTE_OK, TRACKBACK_ROUTE, GOODBYE_REQUEST, GOODBYE_CONFIRM,
																		/*this is not an actual message:*/MAX_DIRECT_DHT_MESSAGE
	};
	template<DHTMSG type> struct msg_enum {/*specialization will contain FIELDS enum*/};
	enum CONNECT_FLAGS { NO_RETRY, TRACKBACK, REQUEST_HP_ADDRS, UNUSED3, UNUSED4, UNUSED5, UNUSED6, UNUSED7,
						 UNUSED8, UNUSED9, UNUSED10, UNUSED11, UNUSED12, UNUSED13, UNUSED14, UNUSED15 };
private:
	timer_queue timers;
	function_tqueue interthread_msg_queue;
	std::function<void(size_t,pvevent,sock_err)> peer_socket_event_function;
	enum DHT_NONPEER { DHTLISTEN_FD,	INTERTHREAD_FD,		/*this is not an actual FD:*/ NUM_NONPEER_FDS};
	static const unsigned bufsize = 65536; // large enough to hold maximum individual message size
	uint8_t buf[bufsize];
	csocket dht_incoming;
	in_port_t dhtport;

	worker_thread* io_thread;
	dtls_dispatch_thread* dispatch_thread;
	nameserv* nameserv_thread;
	uint32_t nbo_virtual_interface_addr;
	bool running;

	known_peer_set known_peers;

	pollvector< std::shared_ptr<dht_peer> > connections;
	std::map< uint32_t, std::weak_ptr<dht_peer> > dht_pending_map; // expected incoming DHT connections, waiting for peer DHT to connect (key is assigned NAT IP addr)
	std::map< uint32_t, std::shared_ptr<dht_peer> > connected_peers; // maps NAT IP addrs to active DHT connections (for duplicate elimination)
	
	struct dhtconnect_opts
	{
		in_port_t holepunch_port; // will be inserted into CONNECT for peer to use as src port for UDP holepunch on retry, network byte order
		enum FLAGS { REQUEST_HP_ADDRS=1, // set REQUEST_HP_ADDRS flag so that peer will send HOLEPUNCH_ADDRS back
					 NO_RETRY=2, // set NO_RETRY flag specifying that this is the final attempt, peer should give up rather than sending counter-CONNECT
					 BROADCAST_RETRY=4 }; // if set, broadcast CONNECT to all peers if still not connected after timeout
		unsigned flags;
		dhtconnect_opts(in_port_t hp_port = 0, bool req_hp_addrs = false, bool no_retry = false, bool broadcast_retry = true) : holepunch_port(hp_port) {
			if(holepunch_port==0) holepunch_port = htons(snow::conf[snow::DTLS_OUTGOING_PORT]);
			flags |= req_hp_addrs ? REQUEST_HP_ADDRS : 0;
			flags |= no_retry ? NO_RETRY : 0;
			flags |= broadcast_retry ? BROADCAST_RETRY : 0;
		}
	};
	std::map<hashkey, dhtconnect_opts> dht_connect_pending; // hashkeys for which a DHT CONNECT has been sent and is not yet connected (to track retries and avoid sending duplicates)

	// peer_map: all DTLS connected peers, even if not DHT connected (e.g. either waiting for incoming DHT connect or already did DHT clean disconnect)
		// also contains local node
	struct map_peer {
		std::shared_ptr<dht_peer> peer;
		bool dht_connected; // note: dht_connected may be true even though peer is not [yet] in route_map
		map_peer(std::shared_ptr<dht_peer>& p, bool dht) : peer(p), dht_connected(dht) {}
		map_peer() : dht_connected(false) {}
	};
	std::map<hashkey, map_peer> peer_map;
	dht_route_map route_map; // "routing table" for DHT message routing to directly connected peers
	std::map< uint64_t, std::weak_ptr<dht_peer> > nonce_map; // for CHECK_ROUTE
	std::map<uint64_t, trackback_route> trackback_route_map; // trackback routing (to help fix routing failures)
	
	uint64_t add_trackback_route(uint64_t route_id, dht_peer& peer);
	template<class DHTMSG_T>
	void trackback_forward(DHTMSG_T& msg, dht_peer& frompeer, bool route_message = true);
	template<class DHTMSG_T>
	bool trackback_follow(DHTMSG_T& msg, dht_peer& frompeer); // returns whether msg was successfully forwarded

	std::default_random_engine random_engine;
	std::uniform_int_distribution<uint64_t> random_distribution64;
	std::vector<ip_info> local_ipaddrs;

	/* dht messages: some are routable, some aren't. Routable ones have a size and a destination always in the same position (route header).
	 *	This allows routing to be independent of message type (and allows routing of unknown messages / protocol extensions).
	 */
	static const size_t LOCAL_INDEX = 0;
	static const uint16_t DHT_VERSION = 0;

	template<uint16_t I> struct init_dhtmsg_pointers;
	
	dht_newconn get_client();
	void do_shutdown_thread();
	void initiate_disconnect(dht_peer& peer);
	void dht_startup();
	void check_dht_peer_count();
	void send_hello(dht_peer& peer);
	void check_route_timeout(uint64_t nonce, bool sent_connect, bool sent_retry);
	void newtls(std::shared_ptr<dht_peer> dntls, bool is_client);
	void schedule_reconnect(std::shared_ptr<dht_peer>&);
	void pending_connect_timeout(uint32_t nbo_nat_addr); // really any timeout that causes a DHT reconnect attempt
	void dtls_disconnect(const hashkey& fingerprint, uint32_t nbo_nat_addr);
	void dht_connect(std::shared_ptr<dht_peer> dntls);
	void add_peer(std::shared_ptr<dht_peer>&& ptr, csocket::sock_t);
	void process_dht_incoming();
	void connect_known_peer();
	void forward_payload(const dht_forward_payload& fwd, dht_peer& frompeer);
	void handle_retry(const hashkey& target, std::shared_ptr<dht_connect_retry>& retry);
	void do_initiate_connection(hashkey);
	void set_local_ips(std::vector<ip_info>& ips) {
		if(snow::conf[snow::DHT_RFC1918_ADDRESSES]) {
			std::swap(local_ipaddrs, ips);
		} else {
			local_ipaddrs.clear();
			for(const ip_info& ip : ips) {
				if(!ip.addr.is_rfc1918()) {
					local_ipaddrs.emplace_back(ip);
				}
			}
		}
	}

	/* send_connect():
	 * dest: hashkey of node CONNECT is to be sent to
	 * opts: options and flags, see dhtconnect_opts
	 * follow_trackback: if true, route_id is a trackback route to follow; if false, route_id is the connections index of the next hop (or LOCAL_INDEX to use process_msg)
	 * route_id: see follow_trackback
	*/
	void send_connect(const dht_hash& dest, const dhtconnect_opts& opts = dhtconnect_opts(), bool follow_trackback = false, uint64_t route_id = LOCAL_INDEX);
	void send_broadcast_connect(const hashkey& dest_hk); // send broadcast connect with opts from dht_connect_pending (e.g. after timeout), if one has not already been sent
	// TODO: check if there exist any curious C++ implementations where epoch is not 00:00:00 UTC 1 January 1970 and adjust for that somehow
	static time_t get_time() { return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count(); }
	void remove_routing(dht_peer& peer);
	void mark_defunct(dht_peer& peer);
	void cleanup_connection(size_t remove_index);
	void process_msg(dhtmsg msg, dht_peer& frompeer);
	void route_msg(dhtmsg msg, dht_peer& frompeer);
	void route_msg(dhtmsg msg, dht_peer& frompeer, const hashkey& dest);
	void route_msg(dhtmsg msg, dht_peer& frompeer, dht_peer& topeer);
	void read_peer(dht_peer& peer); // try to read a message and process it (this may cause writes to other peers)
	void write_peer(dht_peer& peer); // try to write whatever is in write_buf
	void write_peer(dhtmsg buf, dht_peer& peer, dht_peer& frompeer); // try to write *buf (or put it at the end of write_buf)
	void handle_excessive_write_buffer(dhtmsg dmsg, dht_peer& peer, dht_peer& frompeer);
	

	
	template<DHTMSG type> void process_msgtype(dhtmsg msg, dht_peer& frompeer);
	template<DHTMSG type> void process_msgtype_final(dhtmsg msg, dht_peer& frompeer);
	template<DHTMSG type> void reroute_msg(dhtmsg msg, dht_peer& frompeer);

	struct dht_fptr
	{
		void (dht::*process)(dhtmsg, dht_peer&);
		void (dht::*process_final)(dhtmsg, dht_peer&);
		void (dht::*reroute)(dhtmsg, dht_peer&);
		bool (*validate)(dhtmsg);
		dht_fptr() {}
		dht_fptr(void (dht::*p)(dhtmsg, dht_peer&), void (dht::*pf)(dhtmsg, dht_peer&), void (dht::*rr)(dhtmsg, dht_peer&), bool (*v)(dhtmsg))
			: process(p), process_final(pf), reroute(rr), validate(v) {}
		inline void process_msg(dht* d, dhtmsg msg, dht_peer& frompeer) {
			if( (*validate)(msg) )
				(d->*process)(msg, frompeer);
			else
				wout() << "dhtmsg failed validation";
		}
		inline void process_msg_final(dht* d, dhtmsg msg, dht_peer& frompeer) {
			(d->*process_final)(msg, frompeer);
		}
		inline void reroute_msg(dht* d, dhtmsg msg, dht_peer& frompeer) {
			(d->*reroute)(msg, frompeer);
		}
	};
	dht_fptr process_routed_msgtype[(unsigned)DHTMSG::MAX_ROUTED_DHT_MESSAGE - DHTMSG_ROUTED_START];
	dht_fptr process_direct_msgtype[(unsigned)DHTMSG::MAX_DIRECT_DHT_MESSAGE - DHTMSG_DIRECT_START];
};

#endif // DHT_H
