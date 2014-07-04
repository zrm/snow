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

#ifndef SNOW_HANDSHAKE_H
#define SNOW_HANDSHAKE_H
#include<set>
#include"../common/dbuf.h"
#include"../common/network.h"
#include"../common/pollvector.h"
#include"crypto.h"
#include"tls.h"
#include"dtls_dispatch.h"
#include"natpmp.h"

struct packet_buf
{
	dbuf buf;
	size_t bytes;
	packet_buf(dbuf&& data, size_t sz) : buf(std::move(data)), bytes(sz) {}
};


class snow_hello
{
	// all fields in network byte order
	struct hello_fields
	{
		uint8_t packet_type; // first nibble PACKET_TYPE::SNOW_HELLO_PACKET, second nibble SNOW_PACKET_TYPE::SNOW_HELLO_PACKET
		uint8_t ipaddrs; // number of 16-byte IP addresses that follow fixed hello fields and hashkey (IPv6 or IPv6-encoded IPv4)
		uint8_t peer_ip[16]; // IP of receiving peer as seen by sending peer: IPv6 addr or IPv4 addr encoded as IPv6 addr
		// TODO: any use in providing source port as well?
		uint16_t peer_ip_port; // DTLS port of receiving peer as seen by sending peer
			// this is less useful for verification because of NAPT prevalence, although clients verifying listen ports could be productive
		uint16_t flags;
		uint16_t protocol_version; // currently ignored (and set to zero)
		uint16_t mtu; // sending peer's OTT MTU; receiving peer must never send a packet larger than this to this peer (minimum 576)
		uint16_t heartbeat_seconds;
		uint16_t nbo_hashalgo; // sending node's hashalgo
		uint16_t nbo_hashlen; // sending node's hashlen
		uint16_t nbo_dhtport; // sending node's DHT port
		uint16_t nbo_dtls_srcport; // sending node's default outgoing DTLS source port (for future holepunch)
		uint16_t peer_hashalgo; // expected peer hashkey algorithm, zero if none expected
		uint16_t peer_hashlen; // expected peer hashkey len, zero if none expected
	};
	static_assert(sizeof(hello_fields)==40, "oops: padding in hello_fields structure");
	struct connect_addr
	{
		uint8_t ipaddr[16];
		uint16_t nbo_port;
		uint8_t* raw() { return ipaddr; }
		const uint8_t* raw() const { return ipaddr; }
	};
	static_assert(sizeof(connect_addr)==18, "oops: padding in connect_addr structure");
	// hfields and addrs point to bytes within "data"
	// "data" is the raw data sent/recvd over the network
	hello_fields* hfields;
	connect_addr* addrs;
	dbuf data; // note: data.size() may be larger than hello_size() (remaining data if any is unused/ignored)
	static unsigned hello_size(size_t num_ipaddrs) {
		return sizeof(hello_fields) + sizeof(connect_addr)*num_ipaddrs; 
	}
public:
	const uint8_t* hello_buf() { return data.data(); }
	unsigned hello_size() { return hello_size(hfields->ipaddrs); }
	/*
	 * DUP: primary has identified this connection as a duplicate; connection will be disconnected if currently active connection is verified good
	 * REQUEST_RETRANSMIT: sending peer requests retransmission, e.g. because it was not timely received, or not received by secondary w/o DUP flag set
	 * EXTERNAL_CONNECT_REQUEST: initiating [sending] peer has initiated connection in response to external request (e.g. DHT, not e.g. local DNS lookup);
	 *		requires peer_ip to match one of those sent by listening peer in outgoing DHT CONNECTs or the connection is dropped (to inhibit traffic analysis MITM)
	 * STRICT_ADDRESS_VERIFY: sending peer's visible address must match a provided address or connection is disconnected, for peers with finite known fixed address(es)
	 *		this is the inverse of EXTERNAL_CONNECT_REQUEST: verify that my address matches what you see rather than verify that your address matches what I see
	*/
	enum SNOW_HELLO_FLAGS { DUP = 1, REQUEST_RETRANSMIT = 2, EXTERNAL_CONNECT_REQUEST = 4, STRICT_ADDRESS_VERIFY = 8, TRANSIENT_KEY = 16 };
	// TODO: TRANSIENT_KEY means peer generates new key on every restart; to implement:
		// a) add config option to enable transient key, generate new key and DH params on startup (or new key and use SKIP params)
		// b) set TRANSIENT_KEY flag in outgoing snow hello when config option is set
		// c) peer that receives hello with TRANSIENT_KEY flag does not add to known_peers because key will change
	const hello_fields& fields() const { return *hfields; }
	void set_flag(SNOW_HELLO_FLAGS flag) { hfields->flags |= htons(flag); }
	void clear_flag(SNOW_HELLO_FLAGS flag) { hfields->flags &= htons(~flag); }
	bool get_flag(SNOW_HELLO_FLAGS flag) const { return hfields->flags & htons(flag); }
	snow_hello(dbuf&& buf, size_t read_len); // throws e_invalid_input
	snow_hello(const hashkey& local_hashkey, const dtls_ptr& peer_conn, const std::vector<ip_info>& local_ipaddrs, uint16_t mtu, uint16_t dhtport);
	snow_hello(const snow_hello&) = delete;
	snow_hello(snow_hello&& sh) : hfields(sh.hfields), addrs(sh.addrs), data(std::move(sh.data)) { sh.hfields = nullptr; sh.addrs = nullptr;}
	snow_hello& operator=(const snow_hello&) = delete;
	snow_hello& operator=(snow_hello&& sh) {
		hfields = sh.hfields;
		sh.hfields = nullptr;
		addrs = sh.addrs;
		sh.addrs = nullptr;
		data = std::move(sh.data);
		return *this;
	}
	// destroy() releases internal dbuf; subsequent access to snow_hello will yield nullptr dereference
	// (generally called immediately before destruction to reclaim buffer)
	dbuf destroy() {
		hfields = nullptr;
		addrs = nullptr;
		return std::move(data);
	}

	bool address_exists(const uint8_t* addr, uint16_t nbo_port) const {
		for(unsigned i=0; i < hfields->ipaddrs; ++i) {
			if(memcmp(addr, addrs[i].ipaddr, 16) == 0 && (nbo_port == addrs[i].nbo_port || nbo_port == 0))
				{ return true; }
			dout() << "snow_hello::address_exists: actual addr " << ss_ip6addr(addr) << ":" << ntohs(nbo_port) << " did not match hello addr " << ss_ip6addr(addrs[i].ipaddr) << ":" << ntohs(addrs[i].nbo_port);
		}
		return false;
	}
	std::vector<ip_info> get_addrs() {
		std::vector<ip_info> rv;
		rv.reserve(hfields->ipaddrs);
		for(unsigned i=0; i < hfields->ipaddrs; ++i) {
			rv.emplace_back(addrs[i].raw());
		}
		return std::move(rv);
	}
	bool hashkey_ok(const snow_hello& peer) const {
		if(hfields->peer_hashalgo == 0 && hfields->peer_hashlen == 0) {
			dout() << "hashkey_ok -> accepting hashkey because no specific hashkey expected";
			return true;
		}
		if(hfields->peer_hashlen != peer.hfields->nbo_hashlen || hfields->peer_hashalgo != peer.hfields->nbo_hashalgo) {
			dout() << "hashkey_ok -> FAILED, hashkey length or algorithm did not match";
			return false;
		}
		dout() << "hashkey_ok -> hashkey params were known and matched";
		return true;
	}
};


class dht_connect_retry;
class peer_init;
class vnet;
class snow_handshake_conn;
typedef std::weak_ptr<snow_handshake_conn> handshake_hint_t;
class snow_handshake_conn : public dtls_peer
{
	enum HANDSHAKE_STATUS { DTLS_HANDSHAKE, SNOW_HELLO, MAKE_LIVE, HANDSHAKE_ERROR, DISCONNECTING };
	void dtls_handshake(uint8_t* read_buf, size_t read_len);
	void recv_snow_hello(uint8_t* read_buf, size_t read_len);
	bool snow_hello_check(snow_hello& hello_recv);
	bool snow_hello_check_static(const snow_hello& primary_hello, const snow_hello& secondary_hello, bool primary_is_client);
	void buffer_packet(dbuf&& buf, size_t size) {
		if(packets.size() <= MAX_PACKETS)
			{ packets.emplace_back(std::move(buf), size); }
	}
	void send_hello();
	static void retransmit_hello_static(std::weak_ptr<snow_handshake_conn>& wptr) {
		if(auto ptr = wptr.lock())
			{ ptr->retransmit_hello(true); }
		// (else connection is gone, either succeeded and moved to vnet or failed and disconnected)
	}
	void retransmit_hello(bool request_retransmit = false);
	// check_status: returns true if status was a success-indicating tls_conn return value,
	// marks for removal if status was serious error (may return false w/o removal, e.g. EWOULDBLOCK)
	bool check_status(ssize_t status); 
	void set_duplicate(bool dup) {
		duplicate = dup;
		if(dup) {
			hello_send.set_flag(snow_hello::DUP);
			if(primary == false) {
				// secondary waits a little longer to time out for duplicates
				retransmit_max = DUP_COUNT;
				retransmit_msecs = DUP_MSECS;
			}
		} else {
			hello_send.clear_flag(snow_hello::DUP);
		}
	}
	dtls_ptr conn;
	snow_hello hello_send;
	std::vector<packet_buf> packets; // set of IP packet buffers that go to vnet when this peer is verified
	enum { DEFAULT_COUNT = 15, DEFAULT_MSECS = 125, DUP_COUNT = 60, DUP_MSECS = 2000, MAX_PACKETS = 50, DEFAULT_WRITE_MSECS = 125, MAX_WRITE_MSECS = 1000 };
	unsigned retransmit_counter; 
	unsigned retransmit_max;
	unsigned retransmit_msecs;
	unsigned write_retry_msecs;
	HANDSHAKE_STATUS handshake_status;
	std::weak_ptr<snow_handshake_conn> self;
	ip_info visible_ipaddr; // this node's IP address as seen by peer
	std::vector<ip_info> peer_addrs;
	unsigned peer_mtu;
	uint16_t peer_dht_port; // NBO
	uint16_t peer_dtls_srcport; // NBO
	bool primary;
	bool duplicate; // there is already a connected peer with this pubkey; this connection is listed in the dup set
	bool verified_peer; // true if snow hello was received and verified (even if dup)
	bool active; // set when this conn represents the active conn in connected_peers and is about to go to vnet (or has come back from vnet), requires cleanup on failure
		// generally coincides with MAKE_ACTIVE handshake status, but is not modified by errors like status (so that if it errors out it is known that activating a dup or reconnect is necessary)
	std::vector< std::shared_ptr<dht_connect_retry> > retries;

	static dtls_dispatch* dispatch;
	static peer_init* pinit;
	static vnet* vn;
	static timer_queue *timers;
	static buffer_list* buflist;
public:
	snow_handshake_conn(dtls_ptr&& dtls, bool remote_request, bool activ);
	snow_handshake_conn(dtls_ptr&& dtls, std::vector<ip_info>&& addrs, in_port_t holepunch_port, bool remote_request, bool activ)
		: snow_handshake_conn(std::move(dtls), remote_request, activ) { peer_addrs = std::move(addrs); peer_dtls_srcport = holepunch_port; }
	~snow_handshake_conn() { buflist->recover(hello_send.destroy()); }
	static void set_pointers(dtls_dispatch* dd, peer_init* p, timer_queue *q, vnet* v)
		{ dispatch = dd; pinit = p; timers = q; vn=v; }
	static void set_buflist(buffer_list* bl) { buflist = bl; }
	void add_retry(std::shared_ptr<dht_connect_retry>& retry);
	void exec_retries();
	void mark_disconnecting() {
		handshake_status = snow_handshake_conn::HANDSHAKE_STATUS::DISCONNECTING;
		std::weak_ptr<snow_handshake_conn> timeout_conn = self;
		timers->add(30, [this, timeout_conn]() {
			if(auto ptr = timeout_conn.lock())
			   ptr->mark_handshake_error();
		});
		// do this once to get started
		socket_pretend_event();
	}
	void mark_handshake_error() {
		handshake_status = HANDSHAKE_ERROR;
		dispatch->cleanup_peer(self);
	}
	void mark_live();
	void activate_duplicate() {
		// (only called for primary)
		active = true;
		duplicate = false;
		hello_send.clear_flag(snow_hello::DUP);
		if(verified_peer) {
			send_hello();
			mark_live();
		} else {
			hello_send.set_flag(snow_hello::REQUEST_RETRANSMIT);
			retransmit_hello();
		}
	}
	void dtls_shutdown(uint8_t* read_buf, size_t read_len)
	{
		dout() << "handshake doing DTLS shutdown";
		ssize_t rv = conn->do_shutdown(read_buf, read_len);
		if(check_status(rv)) {
			dout() << "Completed clean shutdown of DTLS connection, removing peer";
			dispatch->cleanup_peer(self);
		}
	}
	void set_self(std::shared_ptr<snow_handshake_conn>& slf) { self = slf; conn->set_self(timers, slf); } // this fn only exists because weak_ptr to self cannot be passed to constructor
	const std::weak_ptr<snow_handshake_conn>& get_wptr() const { return self; }
	const sockaddrunion& get_peer() const { return conn->get_peer(); }
	in_port_t get_local_port() const { return conn->get_local_port(); }
	const hashkey& get_hashkey() const { return conn->get_hashkey(); }
	const der_pubkey& get_pubkey() const { return conn->get_pubkey(); }
	bool is_duplicate() const { return duplicate; }
	bool is_verified() const { return verified_peer; }
	
	void socket_pretend_event() { dbuf empty; socket_read_event(empty, 0); } // proceed with no data, e.g. to attempt a write operation
	PEER_TYPE peer_type() { return dtls_peer::HANDSHAKE; }
	void socket_read_event(dbuf& buf, size_t read_len);
	void socket_error_occurred() { exec_retries(); } // error could be minor or forged but do retries immediately in case it isn't
	tls_conn& get_conn() { return *conn; }
	void dtls_timeout_occurred();
	void set_icmp_mtu(uint16_t /*mtu*/) {} // TODO: maybe separately store pmtu and vmtu and send both to vnet?
	void cleanup();
};


#endif // SNOW_HANDSHAKE_H
