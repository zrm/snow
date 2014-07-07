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

#ifndef VNET_H
#define VNET_H
#include "../common/common.h"
#include "../common/err_out.h"
#include "netpool.h"
#include "tls.h"
#include "tuntap.h"
#include "handshake.h"
#include "configuration.h"
#include "natpmp.h"
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <map>


class tls_conn;

struct ethernet_mac
{
	uint16_t addr[3]; // network byte order
	bool operator<(const ethernet_mac& a) const { return memcmp(this, &a, sizeof(ethernet_mac)) < 0; }
	bool operator!=(const ethernet_mac& a) const { return memcmp(this, &a, sizeof(ethernet_mac)) != 0; }
	bool operator==(const ethernet_mac& a) const { return memcmp(this, &a, sizeof(ethernet_mac)) == 0; }
	struct hashfn { size_t operator()(const ethernet_mac& mac) const {
			return static_cast<size_t>(mac.addr[0]) 
				+ ((static_cast<size_t>(mac.addr[1])) << (sizeof(size_t) << 1))
				+ ((static_cast<size_t>(mac.addr[2])) << (sizeof(size_t) << 2));
	}};
	bool is_unicast() {
		// unicast if least significant bit of most significant octet is zero
		return (ntohs(addr[0]) & 0x0100) == 0;
	}
};
std::ostream& operator<<(std::ostream&, const ethernet_mac&);

struct pmtu_data
{
	uint16_t pmtu; // path MTU estimate to this peer, drop or fragment if packet exceeds this
	uint16_t amtu; // path MTU acknowledged by peer
	uint16_t vmtu; // min(local, peer) tun mtu
	pmtu_data(uint16_t mtu) : pmtu(mtu), amtu(MIN_PMTU), vmtu(mtu) {}
};

class vnet;
struct vnet_peer : public dtls_peer
{
	dtls_ptr conn;
	std::weak_ptr<vnet_peer> self;
	pmtu_data mtu; 
	uint32_t nat_addr; // network byte order
	ip_info visible_ipaddr; // underlying transport IP address peer sees as ours
	std::vector<ip_info> peer_addrs; // peer's DTLS listen addrs, for reconnect attempt on failure
	uint16_t dhtport; // peer's NBO DHT port
	uint16_t dtls_srcport; // peer's NBO DTLS default source port
	unsigned idle_count; // how many heartbeat periods have occurred without any real activity
	std::chrono::time_point<std::chrono::steady_clock> last_heartbeat_sent;
	std::chrono::time_point<std::chrono::steady_clock> last_heartbeat_received;
	snow_hello hello; // sometimes this has to be re-sent from here (generally because peer lost the packet)
	vnet_peer(dtls_ptr&& c, uint16_t pmtu, uint32_t nat, std::vector<ip_info>&& addrs, uint16_t dhtprt, uint16_t srcprt, const ip_info& visible_ip, snow_hello&& h)
		: conn(std::move(c)), mtu(pmtu), nat_addr(nat), visible_ipaddr(visible_ip), peer_addrs(std::move(addrs)), dhtport(dhtprt), dtls_srcport(srcprt),
		  idle_count(0), last_heartbeat_sent(std::chrono::steady_clock::now()), last_heartbeat_received(last_heartbeat_sent), hello(std::move(h)) {
		hello.clear_flag(snow_hello::REQUEST_RETRANSMIT); // should never request retransmit of peer hello from vnet
	}
	static vnet* vn;
	dtls_peer::PEER_TYPE peer_type() { return dtls_peer::VNET; }
	void socket_read_event(dbuf& buf, size_t read_len);
	void socket_error_occurred();
	tls_conn& get_conn() { return *conn; }
	void dtls_timeout_occurred();
	void set_icmp_mtu(uint16_t imtu);
	void cleanup();
};


struct ipv4_header;
union snow_packet;
class dht;
class nameserv;
class vnet
{
private:
	std::unordered_set< std::shared_ptr<vnet_peer> > peers;
	tuntap tun;
	timer_queue& timers;
	uint32_t natpool_network, natpool_netmask;
	address_assignment_map address_assignments;
	buffer_list& buflist;

	uint32_t local_ip; // IPv4 address on tap interface (network byte order)
	std::unordered_map< uint32_t, std::shared_ptr<vnet_peer> > nat_map;
	dht* dht_thread;
	nameserv* nameserv_thread;
	peer_init* pinit;
	dtls_dispatch* dispatch;
	void handle_dtls_error(vnet_peer &peer, ssize_t status);
	void mark_remove(vnet_peer &remove) { dispatch->cleanup_peer(remove.self); }
	void cleanup_address_assignments();
	void send_dtls_heartbeats();
	void heartbeat_timeout(std::weak_ptr<vnet_peer>& peer, size_t retries);
	
	void snow_hello_packet(vnet_peer &peer, dbuf &buf, size_t packetsize);
	void snow_control_packet(vnet_peer &peer, dbuf &buf, size_t packetsize);
	void snow_echo_packet(vnet_peer &peer, dbuf &buf, size_t packetsize);
	void snow_port_detect_packet(vnet_peer &peer, dbuf &buf, size_t packetsize);
	void pmtu_discover_timeout(std::weak_ptr<vnet_peer>& peer, uint16_t mtu);
	void fragment_packet(const uint8_t *buf, const size_t size, vnet_peer* peer, const size_t pmtu);
	void send_icmp(const snow_packet *inner, unsigned inner_size, uint32_t peer_ip, vnet_peer *peer, uint8_t icmp_type, uint8_t code, uint32_t icmp_data = 0);
	void send_peer(vnet_peer &peer, const uint8_t *buf, size_t size);
	void local_NAT(ipv4_header* packet, size_t len);
	void peer_NAT(ipv4_header* packet, uint32_t nat_addr, uint32_t local_addr, size_t len);
	void local_packet(dbuf &buf, snow_packet* packet, size_t packetsize);
	void peer_packet(vnet_peer &peer, dbuf &buf, snow_packet* packet, size_t packetsize);
public:
	void set_pointers(dht* d, peer_init* p, nameserv* nst) { dht_thread = d; pinit = p; nameserv_thread = nst; }
	void peer_read_event(vnet_peer& peer, dbuf& udp_buf, size_t udp_len);
	void tuntap_socket_event(size_t index, pvevent event, sock_err err);
	void add_peer(dtls_ptr&& conn, snow_hello&& hello, std::vector<packet_buf>& packets, std::vector<ip_info>&& peer_addrs, uint16_t dhtprt, uint16_t srcprt, const ip_info& visible_ip, unsigned peer_mtu, bool primary);
	void cleanup(vnet_peer &remove);
	void test_pmtu(vnet_peer &peer);
	void send_heartbeat(const hashkey& fingerprint);
	void send_heartbeat(vnet_peer &peer, size_t retries = snow::conf[snow::HEARTBEAT_RETRIES], bool is_retry = false);
	void check_connection(const hashkey& fingerprint) { send_heartbeat(fingerprint) ; }
	void send_heartbeat_all();
	void check_all_connections() { send_heartbeat_all(); }
	void reset_idle_count(const hashkey& fingerprint);
	vnet(dtls_dispatch* dd, worker_thread* io, timer_queue& tq, buffer_list& bl);
	void shutdown_thread() {
		for(auto& peer : peers)
			mark_remove(*peer);
	}
	void dtls_timeout_occurred(vnet_peer& peer) {
		dout() << "vnet: dtls timeout occurred for " << peer.conn->get_hashkey();
		peer.conn->set_error(); // this is the handshake timeout rather than the idle timeout, set error flag to induce retry
		mark_remove(peer);
	}

	uint32_t get_tun_ipaddr() { return local_ip; }
	unsigned get_tun_mtu() { return tun.get_mtu(); } // reentrant
	tuntap& get_tun() { return tun; }
	bool natpool_contains_addr(uint32_t addr) { return (addr & natpool_netmask) == natpool_network; }
	size_t peer_count() { return peers.size(); }
};

#endif // VNET_H
