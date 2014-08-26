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

#include"vnet.h"
#include"peer_init.h"
#include"handshake.h"
#include"nameserv.h"
#include"configuration.h"
#include"dht.h"
#include"ip_packet.h"
#include"netpool.h"
#include<cstring>
#include<unistd.h>
#include<cerrno>
#include<cstdint>
#include<iostream>
#include<fstream>

vnet* vnet_peer::vn;

void vnet_peer::set_icmp_mtu(uint16_t imtu) {
	imtu += conn->dtls_overhead_length();
	if(imtu < MIN_PMTU)
		imtu = MIN_PMTU;
	if(mtu.pmtu > imtu) {
		mtu.pmtu = imtu;
		if(mtu.amtu > imtu)
			mtu.amtu = MIN_PMTU;
		vn->test_pmtu(*this);
	}
}

void vnet_peer::socket_read_event(dbuf &buf, size_t read_len) { vn->peer_read_event(*this, buf, read_len); }
// TODO: if socket error occurs then do multiple heartbeats at short intervals (e.g. 250ms)
	// if the third occurs before the first returns, initiate reconnect (but don't disconnect yet)
	// note however that this will require bypassing the existing check against making new connections to already connected peers
	// if after e.g. 3s no heartbeat has been received, and there is by now a verified "duplicate", switch to the duplicate
void vnet_peer::socket_error_occurred() { vn->send_heartbeat(*this); }
void vnet_peer::dtls_timeout_occurred() { vn->dtls_timeout_occurred(*this); }
void vnet_peer::cleanup() { vn->cleanup(*this); }

vnet::vnet(dtls_dispatch* dd, worker_thread* io, timer_queue& tq, buffer_list& bl) 
	: timers(tq), address_assignments(io), buflist(bl), dispatch(dd)
{
	vnet_peer::vn = this;
	try {
		auto ifinfo = tun.get_if_info();
		local_ip = ifinfo.if_addr;
		natpool_netmask = ifinfo.netmask;
		natpool_network = local_ip & natpool_netmask;
	} catch(const check_err_exception &e) {
		eout() << "Failed to configure tun/tap interface: " << e;
		throw;
	}
	buflist.set_bufsize(tun.get_mtu());
	dout() << "Local virtual interface IP: " << ss_ipaddr(local_ip)
		<< ", NAT network: " << ss_ipaddr(natpool_network)
		<< ", NAT netmask: " << ss_ipaddr(natpool_netmask);	
	address_pool natpool(natpool_network, natpool_netmask);
	natpool.remove_address(local_ip);
	address_assignments.set_natpool(std::move(natpool), natpool_network, natpool_netmask);
	// these self-reschedule, so get them started:
	send_dtls_heartbeats();
	cleanup_address_assignments();
}


void ipv4_checksum(snow_packet* packet)
{
	packet->header.header_checksum = 0;
	uint32_t checksum = 0xffff;
	unsigned words = packet->header.ihl()/2;
	for(unsigned i=0; i < words; ++i)
		checksum += packet->raw16[i];
	// (ipv4 ihl is always even, no need to deal with stray byte)
	while(checksum > 0xffff)
		checksum = (checksum & 0xffff) + (checksum >> 16); // fold carries
	packet->header.header_checksum = ~checksum;
}

void icmp_checksum(snow_packet *packet)
{
	unsigned len = ntohs(packet->header.total_length) - packet->header.ihl();
	ip_transport_header* th = &packet->header.transport_header();
	th->icmp.checksum = 0;
	uint32_t checksum = 0xffff;
	for(unsigned i=0; i+i<len; ++i)
		checksum += th->raw16[i];
	if(len & 0x01)
		checksum += th->raw[len-1] << 8;
	while(checksum > 0xffff)
		checksum = (checksum & 0xffff) + (checksum >> 16); // fold carries
	th->icmp.checksum = ~checksum;
}

inline uint32_t adjust_checksum(uint32_t src, uint32_t dst)
{
	return (src & 0xffff) + (src >> 16) + (dst & 0xffff) + (dst >> 16);
}
inline uint16_t ip_checksum_subtract(uint32_t checksum, uint32_t checksum_adjust)
{
	checksum ^= 0xffff; // '~checksum' (but don't touch the high bits)
	 while(checksum_adjust > checksum)
		checksum += 0xffff; // undo folding of carries
	checksum -= checksum_adjust;
	return ~checksum;
}
void vnet::local_NAT(ipv4_header* ip, size_t len)
{
	// subtract out IP addrs being NAT'd so other side can just add back in whatever they're translated to
	uint32_t checksum_adjust = adjust_checksum(ip->src_addr, ip->dst_addr);
	// adjust TCP/UDP/ICMP checksum if applicable
	if((ip->flags_fragmentoffset & htons(0x1fff)/*frag offset mask*/) == 0) {
		unsigned ihl = ip->ihl();
		ip_transport_header& transport = ip->transport_header();
		if(ip->protocol == 0x06/*TCP*/ && len >= ihl + sizeof(tcp_header)) {
			transport.tcp.checksum = ip_checksum_subtract(transport.tcp.checksum, checksum_adjust);
		} else if(ip->protocol == 0x11/*UDP*/ && len >= ihl + sizeof(udp_header)) {
			transport.udp.checksum = ip_checksum_subtract(transport.udp.checksum, checksum_adjust);
		} else if(ip->protocol == 0x01/*ICMP*/ && len >= ihl + sizeof(icmp_header) + sizeof(ipv4_header) && transport.icmp.contains_inner_packet()) {
			// ICMP checksum covers the inner packet but not the outer IP header, so only need to subtract addrs for inner packet for it
			ipv4_header& inner_ip = transport.icmp.payload()->header;
			transport.icmp.checksum = ip_checksum_subtract(transport.icmp.checksum, adjust_checksum(inner_ip.src_addr, inner_ip.dst_addr));
			// have to NAT the inner message in ICMP (RFC5508)
			local_NAT(&inner_ip, len - ihl - sizeof(icmp_header));
		}
	}
	ip->dst_addr = 0x00000000;
	ip->src_addr = 0x00000000;
	ip->header_checksum = ip_checksum_subtract(ip->header_checksum, checksum_adjust);
}

inline uint16_t ip_checksum_add(uint32_t checksum, uint32_t checksum_adjust)
{
	checksum ^= 0xffff; // '~checksum' (but don't touch the high bits)
	checksum += checksum_adjust;
	while(checksum > 0xffff)
		checksum = (checksum & 0xffff) + (checksum >> 16); // fold carries
	return ~checksum;
}
void vnet::peer_NAT(ipv4_header* ip, uint32_t src_addr, uint32_t dst_addr, size_t len)
{
	uint32_t checksum_adjust = adjust_checksum(src_addr, dst_addr);
	ip->dst_addr = dst_addr; // (typically local interface IP)
	ip->src_addr = src_addr; // (typically remote/NAT IP)
	ip->header_checksum = ip_checksum_add(ip->header_checksum, checksum_adjust);
	// adjust TCP/UDP/ICMP checksum if applicable
	if((ip->flags_fragmentoffset & htons(0x1fff)/*frag offset mask*/) == 0) {
		unsigned ihl = ip->ihl();
		ip_transport_header& transport = ip->transport_header();
		if(ip->protocol == 0x06/*TCP*/ && len >= ihl + sizeof(tcp_header)) {
			transport.tcp.checksum = ip_checksum_add(transport.tcp.checksum, checksum_adjust);
		} else if(ip->protocol == 0x11/*UDP*/ && len >= ihl + sizeof(udp_header)) {
			transport.udp.checksum = ip_checksum_add(transport.udp.checksum, checksum_adjust);
		} else if(ip->protocol == 0x01/*ICMP*/ && len >= ihl + sizeof(icmp_header) + sizeof(ipv4_header) && transport.icmp.contains_inner_packet()) {
			// ICMP checksum covers the inner packet but not the outer IP header, so only need to add addrs for inner packet
			ipv4_header& inner_ip = transport.icmp.payload()->header;
			transport.icmp.checksum = ip_checksum_add(transport.icmp.checksum, adjust_checksum(inner_ip.src_addr, inner_ip.dst_addr));
			// have to NAT the inner message in ICMP (RFC5508)
			peer_NAT(&inner_ip, dst_addr, src_addr, len - ihl - sizeof(icmp_header)); // src and dst addrs reversed in inner packet
		}
	}
}


void vnet::local_packet(dbuf &buf, snow_packet* packet, size_t packetsize)
{
	if(packet->version_header.version() != 4/*IPv4*/) {
		dout() << "Dropped " << packetsize << " byte non-IPv4 packet from tun";
		return;
	}
	if(validate_packet4_length(packet, packetsize) == false) {
		dout() << "Local packet of size " << packetsize << " failed length validation";
		return;
	}
	dout() << packetsize << " bytes from tun, proto " << (unsigned)packet->header.protocol;
	if(packet->header.protocol == 0x01/*ICMP*/ && packet->header.transport_header().icmp.contains_inner_packet()) {
		snow_packet* inner_packet = packet->header.transport_header().icmp.payload();
		if(inner_packet->header.src_addr != packet->header.dst_addr || inner_packet->header.dst_addr != packet->header.src_addr) {
			dout() << "Dropped ICMP packet because inner packet src/dst was missing or did not match outer packet";
			return;
		}
	}
	
	auto it = nat_map.find(packet->header.dst_addr);
	if(it != nat_map.end()) {
		vnet_peer& peer = *it->second;
		if(packet->header.src_addr == local_ip) {
			local_NAT(&packet->header, packetsize);
			send_peer(peer, buf, packetsize);
		} else {
			iout() << "Dropped packet with source address not on local virtual interface " << *packet;
			send_icmp(packet, packetsize, packet->header.dst_addr, nullptr, icmp_header::DEST_UNREACHABLE, icmp_header::COMM_ADMIN_PROHIBITED);
		}
	} else {
		try {
			dht_thread->initiate_connection(address_assignments.get_defunct_assignment(packet->header.dst_addr));
			dout() << "Got packet for defunct address assignment, attempting reconnect";
			// TODO: it may make sense to buffer these for a few seconds and retransmit on reconnect
				// or send ICMP unreachable if reconnect hasn't succeeded within a few seconds
		} catch(const e_not_found &) {
			dout() << "Dropped packet for address not in NAT table " << *packet;
			send_icmp(packet, packetsize, packet->header.dst_addr, nullptr, icmp_header::DEST_UNREACHABLE, icmp_header::DEST_HOST_UNKNOWN);
		}
		// TODO: what should be done with broadcast packets? user option to actually broadcast?
	}
}

void vnet::peer_packet(vnet_peer &peer, dbuf &buf, snow_packet* packet, size_t packetsize)
{
	dout() << packetsize << " byte packet from peer";
	if(packet->version_header.version() != 4/*IPv4*/) {
		if((buf.data()[0] & 0xf0) == PACKET_TYPE::SNOW_PACKET) {
			switch(buf.data()[0] & 0x0f) {
			case SNOW_PACKET_TYPE::SNOW_HELLO_PACKET:
				snow_hello_packet(peer, buf, packetsize);
				break;
			case SNOW_PACKET_TYPE::SNOW_CONTROL_PACKET:
				snow_control_packet(peer, buf, packetsize);
				break;
			default:
				dout() << "Dropped snow packet of unknown subtype " << ((int)(buf.data()[0]&0x0f));
				break;
			}
		} else {
			dout() << "Dropped packet from peer with unsupported IP version " << packet->version_header.version();
		}
		return;
	}
	if(validate_packet4_length(packet, packetsize) == false) {
		dout() << "Peer packet failed length validation";
		return;
	}
	if(packet->header.protocol == 0x01/*ICMP*/ && packet->header.transport_header().icmp.contains_inner_packet()) {
		snow_packet* inner_packet = packet->header.transport_header().icmp.payload();
		if(inner_packet->header.src_addr != packet->header.dst_addr || inner_packet->header.dst_addr != packet->header.src_addr) {
			dout() << "Dropped ICMP packet because inner packet src/dst was missing or did not match outer packet";
			return;
		}
	}

	if(packet->header.src_addr == 0 && packet->header.dst_addr == 0)
	{
		peer_NAT(&packet->header, peer.nat_addr, local_ip, packetsize);
		try {
			if(tun.send_packet(buf, packetsize) == false)
				dout() << "Write to tuntap would block, packet dropped";
		} catch(const e_exception &e) {
			eout() << "tuntap interface write error: " << e;
			dout() << "error packet was " << *packet;
			// TODO: maybe some mitigation here, e.g. reconfigure tun
			// (obviously the current packet is to be dropped) [maybe send ICMP?]
		}
	} else {
		wout() << "Dropped invalid packet to address " << ss_ipaddr(packet->header.dst_addr) 
								 << " from peer with real IP " << peer.conn->get_peer()
								 << " and assigned NAT pool address " << ss_ipaddr(peer.nat_addr);
		dout out; out << "Raw crazy packet looked like this:";
		for(size_t i=0; i < packetsize; ++i)
			out << std::hex << std::setw(2) << std::setfill('0') << (int)buf[i];
		out << std::dec;
	}
}

void vnet::snow_hello_packet(vnet_peer &peer, dbuf &buf, size_t packetsize)
{
	try {
		snow_hello hello(std::move(buf), packetsize);
		if(hello.get_flag(snow_hello::REQUEST_RETRANSMIT))
			send_peer(peer, peer.hello.hello_buf(), peer.hello.hello_size());
		buf = hello.destroy();
	} catch(const e_invalid_input& e) {
		wout() << "Got snow_hello from peer in vnet which did not parse: " << e;
	}
}

void vnet::snow_control_packet(vnet_peer &peer, dbuf &buf, size_t packetsize)
{
	// snow control packet format: [1:control packet (0x01)][1:(reserved/flags)][2:subtype]
	uint16_t subtype;
	if(packetsize >= 2+sizeof(subtype)) {
		memcpy(&subtype, buf.data()+2, sizeof(subtype));
		subtype=ntohs(subtype);
		switch(subtype) {
		case SNOW_CONTROL_SUBTYPE::SNOW_CONTROL_ECHO:
			snow_echo_packet(peer, buf, packetsize);
			break;
		case SNOW_CONTROL_SUBTYPE::SNOW_CONTROL_PORT_DETECT:
			snow_port_detect_packet(peer, buf, packetsize);
			break;
		default:
			dout() << "Dropped snow control packet with unknown subtype " << subtype;
			break;
		}
	} else {
		wout() << "Dropped snow control packet lacking subtype field";
	}
}

void vnet::snow_echo_packet(vnet_peer &peer, dbuf &buf, size_t packetsize)
{
	if(packetsize >= sizeof(snow_echo)) {
		snow_echo* packet = reinterpret_cast<snow_echo*>(buf.data());
		if(packet->ack == 0) {
			dout() << "Acknowledging snow echo packet of size " << packetsize << " from " << peer.conn->get_hashkey();
			snow_echo ack(packetsize);
			send_peer(peer, reinterpret_cast<const uint8_t*>(&ack), sizeof(ack));
		} else {
			uint16_t pmtu_ack = ntohs(packet->ack);
			dout() << "Got echo ack from " << peer.conn->get_hashkey() << " with pmtu of " << pmtu_ack;
			if(pmtu_ack > peer.mtu.amtu) {
				peer.mtu.amtu = std::min(pmtu_ack, peer.mtu.vmtu);
			}
		}
		peer.last_heartbeat_received = std::chrono::steady_clock::now();
	} else {
		wout() << "Dropped snow echo packet with truncated header";
	}
}
void vnet::snow_port_detect_packet(vnet_peer &peer, dbuf &buf, size_t packetsize)
{
	if(packetsize >= sizeof(snow_port_detect)) {
		snow_port_detect* packet = reinterpret_cast<snow_port_detect*>(buf.data());
		dispatch->snow_port_detect_packet(packet, peer);
	} else {
		wout() << "Dropped truncated snow_port_detect packet";
	}
}

// TODO: periodically reset pmtu and amtu of peer and call test_pmtu again to recheck pmtu discovery for any peer that pmtu not equal to vmtu
void vnet::test_pmtu(vnet_peer &peer)
{
	dbuf buf(buflist.get());
	uint16_t mtu = peer.mtu.pmtu;
	if(buf.size() < mtu) {
		eout() << "BUG: peer has pmtu in excess of mtu buffer size";
		mark_remove(peer);
		return;
	}
	dout() << "Testing PMTU of " << mtu;
	new(buf.data()) snow_echo(0); // placement new
	memset(buf.data()+sizeof(snow_echo), 0, mtu-sizeof(snow_echo));
	send_peer(peer, buf.data(), mtu);
	timers.add(1, std::bind(&vnet::pmtu_discover_timeout, this, peer.self, mtu));
}

void vnet::pmtu_discover_timeout(std::weak_ptr<vnet_peer>& wptr, uint16_t mtu)
{
	// need some MTUs to try if ICMP is broken
	static const uint16_t common_mtus[] = { 32000, 17840, 8042, 4278, 1920, 1400, 930, 552 };
	auto peer = wptr.lock();
	if(peer) {
		if(peer->mtu.pmtu == mtu && peer->mtu.amtu < mtu) {
			// mtu test neither got ICMP nor was ack'd by peer, try lowering mtu estimate
			uint16_t next_mtu = mtu;
			for(unsigned i=0; i < sizeof(common_mtus)/sizeof(uint16_t); ++i) {
				if(common_mtus[i] < next_mtu) {
					next_mtu = common_mtus[i];
					break;
				}
			}
			if(next_mtu != mtu) {
				peer->mtu.pmtu = next_mtu;
				test_pmtu(*peer);
			} else {
				send_heartbeat(*peer);
			}
		}
	}
}

// buf: packet to be fragmented
// size: size of packet in dbuf
// index: index of peer to send fragments to, or TAP_FD to send to tap
// pmtu: path mtu, maximum size of fragments
void vnet::fragment_packet(const uint8_t *buf, const size_t size, vnet_peer* peer, const size_t pmtu)
{
	// nullptr peer means send to tuntap
	const ipv4_header* packet = reinterpret_cast<const ipv4_header*>(buf);
	if(packet->ihl() == sizeof(ipv4_header)) {
		dout() << "Fragmenting packet of size " << size << " for PMTU " << pmtu;
		uint16_t base_checksum = ip_checksum_subtract(packet->header_checksum, packet->total_length + packet->flags_fragmentoffset);
		// fragment increment: remainder of PMTU after IHL, truncated to nearest 8-octet boundary
		unsigned fragment_increment = (pmtu - sizeof(ipv4_header)) & 0xfff8;
		unsigned remaining = size - sizeof(ipv4_header);
		dbuf fragment_buf = buflist.get();
		ipv4_header *fragment_header = reinterpret_cast<ipv4_header*>(fragment_buf.data());
		for(size_t data_offset = sizeof(ipv4_header); data_offset < size; data_offset += fragment_increment) {
			unsigned dsize = std::min(fragment_increment, remaining);
			remaining -= dsize;
			memcpy(fragment_buf, buf, sizeof(ipv4_header));
			memcpy(fragment_buf+sizeof(ipv4_header), buf + data_offset, dsize);
			fragment_header->total_length = htons(sizeof(ipv4_header) + dsize);
			fragment_header->flags_fragmentoffset = htons( (data_offset - sizeof(ipv4_header)) / 8 );
			fragment_header->flags_fragmentoffset |= remaining ? htons(0x2000) : ((htons(0x2000) & packet->flags_fragmentoffset)); // more fragments flag
			fragment_header->header_checksum = ip_checksum_add(base_checksum, fragment_header->total_length + fragment_header->flags_fragmentoffset);
			if(peer == nullptr)
				tun.send_packet(fragment_buf, sizeof(ipv4_header) + dsize);
			else
				send_peer(*peer, fragment_buf, sizeof(ipv4_header) + dsize);
		}
		buflist.recover(std::move(fragment_buf));
	} else {
		wout() << "Received packet with IPv4 options that required fragmentation; fragmentation of IPv4 options not implemented; packet dropped";
		// TODO: actually implement this someday (even though it's a pain and hardly anybody uses it)
	}
}

void vnet::send_icmp(const snow_packet *inner, unsigned inner_packet_size, uint32_t peer_ip, vnet_peer* peer, uint8_t icmp_type, uint8_t code, uint32_t icmp_data)
{
	// passing nullptr peer to this means send ICMP to tuntap
	if(inner_packet_size > inner->header.ihl() + 8)
		inner_packet_size = inner->header.ihl() + 8; // RFC792
	const unsigned packet_size = sizeof(ipv4_header) + sizeof(icmp_header) + inner_packet_size;
	dbuf buf(buflist.get());
	snow_packet* icmp_packet = reinterpret_cast<snow_packet*>(buf.data());
	uint32_t ipaddr = (peer == nullptr) ? local_ip : 0; 
	icmp_packet->header = ipv4_header(packet_size, 0/*flags,frag*/, 64/*ttl*/, ipv4_header::ICMP, ipaddr, ipaddr);
	icmp_header& icmp = icmp_packet->header.transport_header().icmp;
	icmp = icmp_header(icmp_type, code, icmp_data);
	if(icmp.contains_inner_packet()) {
		memcpy(icmp.payload(), inner, inner_packet_size);
		if(inner_packet_size > sizeof(ipv4_header)) {
			if(peer != nullptr && inner->header.src_addr != 0 && inner->header.dst_addr != 0) {
				local_NAT(&icmp.payload()->header, inner_packet_size);
			} else if(peer == nullptr && inner->header.src_addr == 0 && inner->header.dst_addr == 0) {
				peer_NAT(&icmp.payload()->header, local_ip, peer_ip, inner_packet_size);
			}
		}
	}
	ipv4_checksum(icmp_packet);
	icmp_checksum(icmp_packet);
	// TODO: catch possible exception from tun
	if(peer == nullptr)
		tun.send_packet(buf, packet_size);
	else
		send_peer(*peer, buf, packet_size);
	buflist.recover(std::move(buf));
}

void vnet::send_peer(vnet_peer &peer, const uint8_t *buf, size_t size)
{
	peer.idle_count = 0;
	if(size <= peer.mtu.pmtu) {
		ssize_t nwritten = peer.conn->send(buf, size);
		if(nwritten < 0)
			handle_dtls_error(peer, nwritten);
	} else if((buf[0] & 0xF0) == PACKET_TYPE::IPV4_PACKET) {
		const snow_packet* packet = reinterpret_cast<const snow_packet*>(buf);
		if(packet->header.flags_fragmentoffset & htons(0x4000/*don't fragment bit*/)) {
			dout() << "Got packet for peer larger than PMTU but DF bit set, packet dropped";
			send_icmp(packet, size, peer.nat_addr, nullptr, icmp_header::DEST_UNREACHABLE, icmp_header::PACKET_TOO_BIG, htonl(peer.mtu.pmtu));
		} else {
			fragment_packet(buf, size, &peer, peer.mtu.pmtu);
		}
	} else {
		dout() << "Dropped packet of size " << size << " because it was larger than PMTU " << peer.mtu.pmtu << " and could not be fragmented as it was not an IPv4 packet"; 
		// TODO: send ICMPv6 if packet is IPv6 (once IPv6 is implemented)
	}
}

void vnet::add_peer(dtls_ptr&& conn, snow_hello&& hello, std::vector<packet_buf>& packets, std::vector<ip_info>&& peer_addrs, uint16_t dhtprt, uint16_t srcprt, const ip_info& visible_ip, unsigned peer_mtu, bool primary)
{
	conn->update_thread_tracker();
	const hashkey &fingerprint = conn->get_hashkey();
	dout() << "vnet got new DTLS peer " << fingerprint;
	uint32_t nbo_nat_ip = address_assignments[fingerprint];
	if(nbo_nat_ip != 0) {
		// existing peer may be present (or addr may just be in grace period), if so this peer will replace it, shutdown existing if any
		auto it = nat_map.find(nbo_nat_ip);
		if(it != nat_map.end()) {
			it->second->nat_addr = 0;
			dispatch->cleanup_peer(it->second);
		}
	}
	try {
		nbo_nat_ip = address_assignments.assign_address(fingerprint);
	} catch(const e_resource_exhaustion &) {
		eout() << "NAT pool address exhaustion, new peer at " << fingerprint << " will be disconnected. Consider a wider subnet mask on the snow virtual network interface.";
		pinit->shutdown_connection(std::move(conn), std::move(peer_addrs), srcprt);
		return;
	}
	dispatch->add_peer_visible_ipaddr(visible_ip);
	std::shared_ptr<vnet_peer> newpeer = *peers.emplace(std::make_shared<vnet_peer>(std::move(conn), std::min(peer_mtu, tun.get_mtu()), nbo_nat_ip, std::move(peer_addrs), dhtprt, srcprt, visible_ip, std::move(hello))).first;
	newpeer->self = newpeer;
	vnet_peer& peer = *newpeer;
	peer.conn->set_self(&timers, newpeer);
	nat_map[nbo_nat_ip] = newpeer;
	if(newpeer->conn->is_client() == false)
		dispatch->send_port_detect_nonce(newpeer);
	dispatch->update_peer(ip_info(peer.conn->get_local()), ip_info(peer.conn->get_peer()), std::move(newpeer));
	dout() << "Added peer with NAT IP " << ss_ipaddr(nbo_nat_ip);
	// notify DHT to do DHT connect (and add to DHT known peers file if this was a successful outgoing connection)
	dht_thread->newTLS_notify(std::make_shared<dht_peer>(fingerprint, peer.peer_addrs, dhtprt, srcprt, peer.nat_addr, primary), peer.conn->is_client());
	nameserv_thread->lookup_complete(fingerprint, peer.nat_addr);
	test_pmtu(peer);
	for(auto& packet : packets) // process buffered packets if any
		{ peer_packet(peer, packet.buf, reinterpret_cast<snow_packet*>(packet.buf.data()), packet.bytes); }
}


/*
TODO: man SSL_write says the following:

"When an SSL_write() operation has to be repeated because of SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE, it must be repeated with the same arguments."

We're currently violating that systematically, but it may be that the warning only applies to SSL/TLS and not DTLS (which shouldn't do partial writes). Verify this.
*/

/*
eager allocation of NAT IP addrs:
	right now when nameserv gets request for unconnected peer, actual connection is entirely made before allocating IP and sending response
	possible alternative is to have vnet assign IP addr immediately and do immediate response
	advantage:
		nameserv response time is reduced; no timeouts if connection takes a long time to become established
	disadvantage:
		easier for attacker to exhaust NAT address pool
			but simple mitigation for this is to fall back to the first method if more than half of the addresses are exhausted
	more disadvantage:
		responding to userspace before connection is established will often result in first packets being dropped, causing possible user program timeouts etc.
			but how about this: give connection until nameserv timeout to become established, then respond
			result will be to eliminate NXDOMAIN from possible nameserv responses, but if no connection comes or conn is slow, user packets go nowhere (as intended?)
		could also just buffer packets for a few seconds
*/

/*
TODO: implement threads for DTLS peers
threading problem: OpenSSL does not allow simultaneous read and write to same TLS connection, so can't put tuntap read in one thread and TLS read in another on same conn
possible solution: one tuntap read thread + thread pool where threads are assigned TLS connections
	main thread does all read operations on tuntap and on datagram sockets (could also make this two threads or more)
	data read is sent to thread pool thread which corresponds to associated connection, to do encryption operation and then write to socket or tuntap
		[I think simultaneous read/write to tuntap is allowed, verify this]
	main thread maintains NAT table associating peer addrs with peers, mapping socket reads to TLS using recvfrom addr and tuntap reads using IP header destination
	thread pool does some basic load balancing, e.g. # active connections on one thread is more than one greater than # active connections on another, move one
alt solution of having one tuntap read thread and a dedicated thread for each DTLS connection makes little sense when using shared UDP sockets
possible interesting solution:
	main thread holds connections which are known idle; when data arrives the connection it's for is assigned to a thread and it goes to write data
f	as more data arrives it is put on the queue for the same thread (ideally using some kind of lockless queue) and the thread continues processing it
	when all data is processed the thread blocks with e.g. 1s timeout on the queue descriptor waiting for additional data
	if data arrives it is processed and another wait occurs, if no data arrives the peer connection ownership is returned to the main thread
	if data arrives for a different connection and all other threads are busy, the main thread sends a new connection w/ new data to replace existing

	
TODO: OpenSSL ERR_remove_state has to be done at the end of each thread, if threads that ever actually terminate are implemented
maybe the way to do this is write a wrapper around pthread_exit [or c++11 equiv] that calls this and then pthread_exit)
	or just call it before thread exit
ERR_remove_state(0); //free OpenSLL auto-created error queue for this thread
Similarly, don't forget about the tls_conn pointer allocated in thread tracker
	(this will all be much easier when compiler support for thread local storage improves.)
*/

// TODO: PMTU reverse path hints: if fw is blocking ICMP, peer can do PMTU discovery from the other end and notify of what PMTU appears to be
	// this could be wrong because the path could be different the other way, but useful as a hint for this peer to try
	// might be possible to do this implicitly: when peer sends echo req if it's bigger than current PMTU then try it in the other direction
	// if it gets ack'd then we have new PMTU (assuming no multipath etc, but ICMP blackhole + multipath with different MTUs = perfect storm)
		// not clear if anything even could be done in that case: is it even possible to distinguish it from random packet loss?


void vnet::tuntap_socket_event(size_t, pvevent event, sock_err err)
{
	if(event == pvevent::read)
	{
		dbuf buf(buflist.get());
		try {
			// nread is size of packet read from tuntap; packet data is written to bytes 4 through nread+4 to leave space for snow header
			size_t nread = tun.recv_packet(buf);
			if(nread > 0)
				local_packet(buf, reinterpret_cast<snow_packet*>(buf.data()), nread);
			// (else EWOULDBLOCK, do nothing)
		} catch(const e_exception &e) {
			eout_perr() << "FATAL: tuntap read error: " << e << ": ";
			abort();
			// TODO: maybe consider re-issuing tuntap fcntl/ioctl in case error was user reconfiguration of interface
				// but that's going to require some work: if natpool changes (and doesn't contain the old one) then reassign all new nat addrs to connections, etc.
		}
		buflist.recover(std::move(buf));
	} else {
		// some pollvector error event occurred on tun/tap device, fail
		eout() << "FATAL: error event on tun/tap interface device descriptor: " << err;
		// TODO: try some mitigation if this ever happens
		abort();
	}
	dispatch->cleanup_peers();
}

void vnet::peer_read_event(vnet_peer& peer, dbuf& udp_buf, size_t udp_len)
{
	dbuf buf(buflist.get());
	ssize_t nread = peer.conn->recv(udp_buf, udp_len, buf, buf.size());
	if(nread > 0) {
		snow_packet *packet = reinterpret_cast<snow_packet*>(buf.data());
		peer.idle_count = 0;
		peer_packet(peer, buf, packet, nread);
	} else if(nread == tls_conn::TLS_WANT_READ) {
		// this can happen if peer disconnects and reconnects using the same ports: existing conn gets the handshake request, discards it and says WANT_READ
		// so do heartbeat to make sure this peer is still alive, so that it can be killed quickly if it isn't and handshake packets can go to pinit
		send_heartbeat(peer);
	} else {
		handle_dtls_error(peer, nread);
	}
	buflist.recover(std::move(buf));
}

void vnet::reset_idle_count(const hashkey &fingerprint)
{
	auto it = nat_map.find(address_assignments[fingerprint]);
	if(it != nat_map.end())
		it->second->idle_count = 0;
	else if(fingerprint != pinit->local_hashkey())
		dht_thread->initiate_connection(fingerprint);
}

void vnet::send_heartbeat(const hashkey &fingerprint)
{
	auto it = nat_map.find(address_assignments[fingerprint]);
	if(it != nat_map.end())
		send_heartbeat(*it->second);
	else
		// (this could happen if peer just disconnected, ignore)
		dout() << "Could not find peer requested to send heartbeat to with fingerprint " << fingerprint;
}
void vnet::send_heartbeat(vnet_peer& peer, size_t retries, bool is_retry)
{
	// do heartbeat if previous heartbeat response was received more than two seconds ago
	if((peer.last_heartbeat_received >= peer.last_heartbeat_sent || is_retry) && peer.last_heartbeat_received + std::chrono::seconds(2) < std::chrono::steady_clock::now()) {
		dout() << "Sending heartbeat to " << peer.conn->get_hashkey() << " (" << retries << " retries remain)";
		peer.last_heartbeat_sent = std::chrono::steady_clock::now();
		snow_echo heartbeat(0);
		send_peer(peer, reinterpret_cast<const uint8_t*>(&heartbeat), sizeof(heartbeat));
		timers.add(1, std::bind(&vnet::heartbeat_timeout, this, peer.self, retries));
	} else {
		dout() << "Not sending heartbeat to " << peer.conn->get_hashkey() << " because one is pending or not enough time has elapsed since the last one";
	}
}
void vnet::heartbeat_timeout(std::weak_ptr<vnet_peer>& peer, size_t retries)
{
	auto ptr = peer.lock();
	if(ptr && ptr->last_heartbeat_received < ptr->last_heartbeat_sent) {
		// ruh roh, didn't get heartbeat response
		if(retries) {
			send_heartbeat(*ptr, retries-1, true);
		} else {
			dout() << "HEARTBEAT TIMEOUT for " << ptr->conn->get_hashkey();
			ptr->conn->set_error();
			mark_remove(*ptr);
		}
	}
}

void vnet::send_heartbeat_all()
{
	for(const std::shared_ptr<vnet_peer>& peer : peers)
		send_heartbeat(*peer);
}


void vnet::send_dtls_heartbeats()
{
	// TODO: separate idle disconnects from heartbeat
	size_t heartbeat_secs = snow::conf[snow::HEARTBEAT_SECONDS];
	size_t timeout_secs = snow::conf[snow::DTLS_IDLE_TIMEOUT_SECS];
	size_t idle_threshold = (timeout_secs / heartbeat_secs) + (timeout_secs % heartbeat_secs) ? 1 : 0; // round up
	// TODO: consider making heartbeat per-connection instead of doing them all at once: is the timer overhead worth it? conversely, is latency of doing maybe thousands at once problematic?
		// if there are a lot of connections doing all at once like this could cause EWOULDBLOCK -> thundering hurd retries -> mass disconnects
		// on the other hand, sending all the heartbeats at once is better for mobile connection radios
	// TODO: it doesn't really make sense to have both peers send heartbeats on timers, it just causes twice as much traffic
		// it would make more sense to put the heartbeat duration in the snow hello and then only have the primary do it, using min(local, peer) duration
		// then secondary doesn't actually send heartbeat but keeps track of the last one it received from primary and checks periodically whether to disconnect because it was too long ago
		// also, when one device is cellular and the other one isn't, regardless of who the primary is, the mobile device sends the heartbeat (if both mobile then same rule as both not)
	for(const std::shared_ptr<vnet_peer>& peer : peers) {
		if(peer->idle_count++ > idle_threshold) {
			dout() << "vnet: peer at NAT IP " << ss_ipaddr(peer->nat_addr) << " disconnected as idle too long";
			mark_remove(*peer);
		} else {
			dout() << "dtls connection idle " << peer->idle_count << " threshold " << idle_threshold << ", doing heartbeat";
			// send heartbeat every few seconds: for large numbers of connections this could be slow, is there any better way to accomplish this?
			send_heartbeat(*peer);
		}
	}
	timers.add(heartbeat_secs, std::bind(&vnet::send_dtls_heartbeats, this));
}


void vnet::cleanup_address_assignments()
{
	// this runs once every grace period, so if address is marked defunct right after an iteration it may not be removed for up to double the grace period
	// advantage is that if a peer reconnects and then disconnects again during the grace period,
	// the address will not be removed until the grace period expires again
	// TODO: change this so that addresses are not removed until they become scarce
		// possible sensible way to go is to keep the address list in a mmapped binary file which is in address order and has fixed length field for hashkey
		// then keep timestamp for last access and discard assignments on the basis of recency, e.g. once 99% of all addrs are used parse file in separate thread and discard 1% LRU assignments and put in free list
		// possible problem is how to determine existing mapping every time a peer connects w/o having to parse file with a million entries
		// possible solution is to purge addrs not used in e.g. a week even if pool not empty, preventing accumulation of mappings over time on low-resource nodes
	address_assignments.cleanup();
	timers.add(snow::conf[snow::NAT_IP_GRACE_PERIOD_SECONDS], std::bind(&vnet::cleanup_address_assignments, this));
}

void vnet::handle_dtls_error(vnet_peer& peer, ssize_t status)
{
	switch(status)
	{
	case tls_conn::TLS_OK:
		break;
	case tls_conn::TLS_WANT_READ:
		dout() << "vnet: tls_conn gave TLS_WANT_READ";
		// (dispatch always polls for read)
		break;
	case tls_conn::TLS_WANT_WRITE:
		dout() << "vnet: tls_conn gave TLS_WANT_WRITE";
		// (never poll for write, will attempt write again next time there is data or heartbeat)
		break;
	case tls_conn::TLS_SOCKET_ERROR:
		dout() << "vnet: socket error from DTLS connection, ignored";
		// this can happen for writes, but error could be attacker sending icmp
		// TODO: maybe do heartbeat? but careful now: don't want send() -> error -> heartbeat -> send() <-<-
			// maybe OK if heartbeat sets last_heartbeat_sent before calling send() because then next call w/o is_retry will do nothing
		break;
	case tls_conn::TLS_CONNECTION_SHUTDOWN:
		// other side sent shutdown msg, send back to tls_newconn for shutdown/cleanup
		dout() << "vnet got TLS_CONNECTION_SHUTDOWN, disconnecting";
		mark_remove(peer);
		break;
	default:
		eout() << "vnet thread: DTLS error";
		mark_remove(peer);
		break;
	}
}



void vnet::cleanup(vnet_peer &remove)
{
	const hashkey &remove_fingerprint = remove.conn->get_hashkey();
	dout() << "vnet removing peer " << remove_fingerprint << " at " << ss_ipaddr(remove.nat_addr);
	uint32_t nbo_nat_addr = remove.nat_addr;
	if(nbo_nat_addr != 0) {
		// TODO: address is still in grace period here, maybe let nameserv keep responding with it and just initiate reconnect if there is a query?
		nameserv_thread->lookup_complete(remove_fingerprint, 0); // zero NAT IP notifies nameserv that this is no longer there
		dht_thread->notify_disconnect(remove_fingerprint, nbo_nat_addr);
		address_assignments.unassign_address(remove_fingerprint);
		nat_map.erase(nbo_nat_addr);
	}
	// send connection back to peer init so it can do clean shutdown (if possible) and update connected peers list etc.
	pinit->shutdown_connection(std::move(remove.conn), std::move(remove.peer_addrs), remove.dtls_srcport);
	dispatch->decrement_peer_visible_ipaddr(remove.visible_ipaddr);
	peers.erase(remove.self.lock());
}


