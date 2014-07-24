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

#include"dtls_dispatch.h"
#include"vnet.h"
#include"peer_init.h"
#include"dht.h"
#include"nameserv.h"
#include"../common/err_out.h"
#ifdef WINDOWS
#include"../common/dbuf.h"
#include<Winsock2.h>
#include<Iphlpapi.h>
#else
#include<ifaddrs.h>
#endif
#include"ip_packet.h"
#include"natpmp.h"

// TODO: if there is a verified dup then do heartbeat differently
	// this requires supporting snow control echo packets in pinit/handshake, but:
	// when primary gets duplicate, it sends heartbeat/echo to existing and also to dup
	// if dup responds and active hasn't within e.g. 100ms (ACTIVE_DUP_DELAY_MSECS ?) after that, fail active and activate dup
	// if active responds, keep active
	// if neither respond, send another echo to each until one does or timeout
	// this allows fast fail detection: the problem with short timeouts is the network could be slow or losing packets
	// which could cause repeated replacement of active with duplicates (and then more handshakes/dups if peer thinks disconnect was unclean)
	// so instead we require that duplicate be faster than active in order to replace it
		// and if it happens to be faster because it's using a better path rather than because active is dead, that's fine too
	// this also allows the heartbeat timeout to be extended a bit when there is no duplicate available, which will improve behavior on slow networks

void add_addr(std::vector<sockaddrunion>& addrs, const sockaddrunion* su, uint32_t nbo_tun_addr)
{
	if(su == nullptr) {
		dout() << "Ignoring null ifaddr";
		return;
	}
	if(su->s.sa_family == AF_INET) {
		if(su->is_ip4_loopback()) {
			dout() << "Ignoring IPv4 loopback address";
		} else if(su->is_ip4_link_local()) {
			dout() << "Ignoring IPv4 link-local address";
		} else if(su->sa.sin_addr.s_addr == nbo_tun_addr) {
			dout() << "Ignoring tun interface IP address " << *su;
		} else {
			addrs.emplace_back(su->sa);
			dout() << "Got IPv4 interface ipaddr: " << addrs.back();
		}
	} else if(su->s.sa_family == AF_INET6) {
		if(su->is_ip6_loopback()) {
			dout() << "Ignoring IPv6 loopback address";
		} else if(su->is_ip6_link_local()) {
			dout() << "Ignoring IPv6 link-local address";
		} else {
			addrs.emplace_back(su->sa6);
			dout() << "Got IPv6 interface ipaddr: " << addrs.back();
		}
	} else {
		dout() << "Ignoring ifaddr with non-INET address family " << static_cast<int>(su->s.sa_family);
	}
}

std::vector<sockaddrunion> dtls_dispatch::detect_local_addrs(uint32_t nbo_tun_addr)
{
	dout() << "detect_local_addrs()";
	std::vector<sockaddrunion> addrs;
#ifdef WINDOWS
	dbuf buf(15000); // per MSFT docs
	ULONG size = buf.size();
	IP_ADAPTER_ADDRESSES* adapter_addresses = (IP_ADAPTER_ADDRESSES*)(buf.data());
	// GAA_FLAG_INCLUDE_GATEWAYS would provide gateways, may be useful for NAT-PCP implementation
		// (but FirstGateway address was only added to structure in Vista, so may be an issue for XP/2003)
	if(GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME, nullptr, adapter_addresses, &size) != NO_ERROR) {
		dout() << "GetAdaptersAddresses returned error";
		return addrs;
	}
	for(IP_ADAPTER_ADDRESSES* adapter = adapter_addresses; adapter != nullptr; adapter = adapter->Next) {
		for(IP_ADAPTER_UNICAST_ADDRESS* addr = adapter->FirstUnicastAddress; addr != nullptr; addr = addr->Next) {
			add_addr(addrs, reinterpret_cast<const sockaddrunion*>(addr->Address.lpSockaddr), nbo_tun_addr);
		}
	}
#else
	ifaddrs* ifad;
	if(getifaddrs(&ifad) == -1) {
		wout_perr() << "getifaddrs could not get local IP addrs";
		return addrs;
	}
	// TODO: link local addrs: what to do?
		// should bind them just to keep anything else from doing so
		// not sure whether to keep them; in theory they're addresses and could be used 
		// and sometimes you may even want to: suppose you can't find any DHT peers (e.g. LAN party with no internet)
		// so you send out a broadcast msg to the snow port asking for some
		// a local peer responds and supplies its link local addr and hashkey and you're up and running completely zeroconf
		// that would give you the ability to just plug machines into a switch or create an ad hoc 802.11 network and be done
		// and sending them to DHT peers is probably harmless (minor overhead): they'll just try to connect and fail, unless they succeed
		// on the other hand, something that can be expected to fail 99% of the time may not be worth doing
	for(ifaddrs* ifa = ifad; ifa != nullptr; ifa = ifa->ifa_next) {
		add_addr(addrs, reinterpret_cast<sockaddrunion*>(ifa->ifa_addr), nbo_tun_addr);
	}
	freeifaddrs(ifad);
#endif
	iout out;
	out << "Detected the following local addrs: ";
	for(auto& addr : addrs)
		out << addr.get_ip_union() << " ";
	return std::move(addrs);
}




dtls_dispatch::dtls_dispatch(worker_thread* io)
	: sockets(std::bind(&dtls_dispatch::cleanup_socket, this, std::placeholders::_1), DISPATCH_NONPEER::NUM_NONPEER_FDS, "dispatch"), buflist(-1),
	  vn(new vnet(this, io, timers, buflist)), pinit(new peer_init(this, vn.get(), timers, &buflist)),
	  run_state(RUNNING), natpmp_addr(0)
{
	buflist.set_bufsize(vn->get_tun_mtu()+200); // tun MTU plus [over-]estimate of DTLS overhead
	sockets.emplace_back(INVALID_SOCKET, pvevent::read, std::bind(&vnet::tuntap_socket_event, vn.get(), std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), dtls_socket(csocket(), sockaddrunion()));
#ifdef WINDOWS
	// set_read_ready_cb must be called after sockets.emplace_back above so that TUNTAP_FD is a valid index, as the callback may be called immediately if data is available
	vn->get_tun().set_read_ready_cb(std::bind(&decltype(sockets)::indicate_read, &sockets, TUNTAP_FD), vn->get_tun_mtu());
#else
	sockets.set_fd(TUNTAP_FD, vn->get_tun().get_fd());
#endif
	sockets.emplace_back(interthread_msg_queue.getSD(), pvevent::read, std::bind(&function_tqueue::pv_execute, &interthread_msg_queue, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), dtls_socket(csocket(), sockaddrunion()));
	csocket icmp4, icmp6;
	try {
		icmp4 = csocket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		icmp6 = csocket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	} catch(const check_err_exception& e) {
		eout() << "Failed to configure ICMP socket: " << e;
	}
	int icmp4_sd = icmp4.fd(), icmp6_sd = icmp6.fd();
	sockets.emplace_back(icmp4_sd, pvevent::read, std::bind(&dtls_dispatch::icmp_socket_event, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), dtls_socket(std::move(icmp4), sockaddrunion()));
	sockets.emplace_back(icmp6_sd, pvevent::read, std::bind(&dtls_dispatch::icmp6_socket_event, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), dtls_socket(std::move(icmp6), sockaddrunion()));
	// that's it for the nonpeers, now grab sockets for all the local ipaddrs
	peer_socket_event_function = std::bind(&dtls_dispatch::peer_socket_event, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
	std::vector<sockaddrunion> local_addrs(detect_local_addrs(vn->get_tun_ipaddr()));
	// TODO: this concept of always using the same incoming and outgoing local ports for all connections theoretically makes the NAT traversal stuff work pretty well
		// and it means we can use a finite number of sockets for arbitrarily many peers
		// but there are probably going to be some circumstances where binding a new socket on a different port will be in order
	// one example of this is when a connection fails (e.g. hard restart of the daemon or device) and the client tries to reconnect using the same ports, which the peer already has associated with the dead connection
		// the current implementation probably does the right thing eventually (maybe bad packet causes peer to do heartbeat and then fail the dead connection?)
		// and if not then the client will send DHT CONNECT which should do the same (induce peer to do heartbeat and fail dead connection)
		// but that's a lot of timeouts and maybes for something that could be avoided by binding a new socket on a random port
			// so could do that for the pre-DHT connection for reconnect-after-failure or reconnects during grace period
	// there are also likely to be situations where the NAT misbehaves in various ways, especially if two nodes behind the same NAT choose the same ports
		// although in that case the NAPT detection should mostly sort it out in theory (at least for incoming port; still needs to be implemented for outgoing port)
	// TODO: figure out what to do if we can't bind the appropriate port on one or more addrs
		// part of the problem is that this sometimes happens normally, e.g. OS (especially stupid Windows) gives useless addrs that don't work but the real addrs are fine
		// but this could also happen if some other program has the port on one or more addrs, or the port is privileged and we don't have privs, etc.
	for(sockaddrunion& su : local_addrs) {
		su.set_ip_port(htons(snow::conf[snow::DTLS_OUTGOING_PORT]));
		try {
			create_socket(su, dtls_socket::PERSISTENT);
		} catch(const e_check_sock_err &e) {
			eout() << "Could not create create UDP socket: " << e;
		}
		if(su.s.sa_family == AF_INET)
			su.set_ip_port(htons(snow::conf[snow::DTLS_BIND_PORT]));
		else
			su.set_ip_port(htons(snow::conf[snow::DTLS_BIND6_PORT]));
		try {
			create_socket(su, dtls_socket::PERSISTENT);
			local_interface_addrs.push_back(su.get_ip_union());
		} catch(const e_check_sock_err &e) {
			eout() << "Could not create create UDP socket: " << e;
		}
	}
	if(local_addrs.size() > 0) {
		std::vector<ip_info> infos;
		for(auto& addr : local_addrs)
			infos.emplace_back(ip_info(addr));
		dout() << "local node info: " << pinit->local_hashkey().key_string() << "," << node_info(infos, htons(snow::conf[snow::DTLS_OUTGOING_PORT]));
	}
	query_natpmpupnp();
}

// thread entrypoint
void dtls_dispatch::operator ()()
{
	// nameserv thread wants to know about this node's hashkey/addr
	nameserv_thread->set_local_addr(get_hashkey(), vn->get_tun_ipaddr());
	update_dht_local_ipaddrs();
	
	while(run_state != SHUTDOWN || pinit->peer_count() > 0 || vn->peer_count() > 0)
	{
		int next_timer = timers.exec();
		if(cleanup_peers())
			continue; // in case cleanup causes loop condition to be satisfied, or sets a timer
		dout() << "Iterating dispatch event loop, next timer " << next_timer << " ms, sockets " << sockets.size() << " handshake " << pinit->peer_count() << " vnet " << vn->peer_count();
		sockets.event_exec_wait(next_timer);
	}
	dout() << "dtls dispatch thread exiting";
}

void dtls_dispatch::create_socket(const sockaddrunion& su, uint32_t flags)
{
	dout() << "Binding UDP socket on " << su;
	csocket sock(su.s.sa_family, SOCK_DGRAM);
	sock.setopt_exclusiveaddruse();
	sock.bind(su);
	sock.setopt_nonblock();
	if(su.s.sa_family == AF_INET)
		sock.setopt_dontfragment(); // (IPv6 does not have DF bit)
	socket_map.emplace(ip_info(su), sockets.size());
	csocket::sock_t sd = sock.fd();
	sockets.emplace_back(sd, pvevent::read, peer_socket_event_function, dtls_socket(std::move(sock), su, flags));
}

void dtls_dispatch::query_natpmpupnp()
{
	map_natpmpupnp_port(htons(snow::conf[snow::DTLS_BIND_PORT]), std::bind(&dtls_dispatch::natpmpupnp_results, this, std::placeholders::_1, std::placeholders::_2));
	timers.add(60*60*4, std::bind(&dtls_dispatch::query_natpmpupnp, this));
}

void dtls_dispatch::process_natpmpupnp_results(uint32_t addr, uint16_t port)
{
	natpmp_addr = addr;
	natpmp_port = port;
	update_dht_local_ipaddrs();
}

void dtls_dispatch::add_peer_visible_ipaddr(const ip_info& addr)
{
	// TODO: detect when peer is providing the same ipaddr as several other peers but a different port
		// it is possible that the peer is behind a NAPT which is translating the source port of the incoming packet(s)
		// and advertising that port to other peers would almost certaily be non-useful
		// using popular voting to determine which port to advertise on an address would probably be effective, as multiple peers seeing same addr+port probably means it's right
		// but democracy implies possible DoS by Sybil; any mitigation? maybe advertise any addr+port seen by at least two peers?
	if(addr.port == 0) {
		dout() << "Not adding peer visible addr with zero port " << addr;
		return;
	}
	size_t& entry = peer_visible_addrs.emplace(addr,0).first->second;
	++entry;
	// do nothing more if address is already known
	if(entry > 1)
		return;
	if(snow::conf[snow::PUBLIC_IPV4_ADDRS].size() > 0) {
		dout() << "Peer sees our address as " << addr << " which is ignored because config file specified PUBLIC_IPV4_ADDRS";
		return;
	}
	ip_info natpmp_ip(natpmp_addr, natpmp_port);
	const ip_union* non_rfc1918 = (natpmp_addr == 0 || natpmp_ip.addr.is_rfc1918()) ? nullptr : &natpmp_ip.addr;
	if(addr == natpmp_ip)
		return;
	for(const ip_union& ip : local_interface_addrs) {
		if(memcmp(ip.ip6.s6_addr, addr.addr.ip6.s6_addr, sizeof(in6_addr::s6_addr)) == 0)
			return;
		if(ip.is_ip4map6() && ip.is_rfc1918() == false)
			non_rfc1918 = &ip;
	}
	// peer sees our ipaddr as different than any known address, maybe ipaddr has changed and we are going to lose most/all existing connections
	vn->check_all_connections();
	char addr_buf[INET6_ADDRSTRLEN], addr_buf2[INET6_ADDRSTRLEN];
	if(non_rfc1918) {
		wout() << "Peer claims that this node's publicly visible IP address is " << inet_ntop(AF_INET6, addr.addr.ip6.s6_addr, addr_buf, INET6_ADDRSTRLEN)
			<< " even though it is known to be " << inet_ntop(AF_INET6, non_rfc1918->ip6.s6_addr, addr_buf2, INET6_ADDRSTRLEN)
		   << " (peer-provided IP will not be advertised to other peers)";
	} else if(snow::conf[snow::NEVER_TRUST_PEER_VISIBLE_IPADDRS] == false) {
		// going to trust peer because we don't know any better, but complain about it first
		wout() << "Trusting peer that this node's public IP is " << inet_ntop(AF_INET6, addr.addr.ip6.s6_addr, addr_buf, INET6_ADDRSTRLEN)
					  << ", consider manually specifying PUBLIC_IPV4_ADDRS in the snow configuration file or procuring a NAT-PMP or PCP enabled gateway."
					  << " Note that some versions of snow also support UPnP gateways, but the recommendation upon encountering a UPnP-only gateway is that you"
					  << " tender it to a local recycling firm such that it may be converted into lawn furniture.";
		update_dht_local_ipaddrs();
	} else {
		dout() << "Peer says this node's public IP address is " << inet_ntop(AF_INET6, addr.addr.ip6.s6_addr, addr_buf, INET6_ADDRSTRLEN) << " and actual address is unknown"
			   << " but this node is set for NEVER_TRUST_PEER_VISIBLE_IPADDRS";
	}
}
void dtls_dispatch::decrement_peer_visible_ipaddr(const ip_info& visible_ipaddr)
{
	if(visible_ipaddr.port == 0)
		return;
	auto it = peer_visible_addrs.find(visible_ipaddr);
	if(it != peer_visible_addrs.end()) {
		--it->second;
		if(it->second == 0) {
			dout() << "Address " << visible_ipaddr << " no longer visible to any peers";
			peer_visible_addrs.erase(it);
			update_dht_local_ipaddrs();
		}
	} else {
		dout() << "BUG: Tried to decrement peer visible ipaddr that did not exist: " << visible_ipaddr;
	}
}

void dtls_dispatch::update_dht_local_ipaddrs()
{
	local_advertised_addrs.clear();
	bool public_addr_known = false;
	if(snow::conf[snow::PUBLIC_IPV4_ADDRS].size() > 0) {
		for(uint32_t addr : snow::conf[snow::PUBLIC_IPV4_ADDRS])
			local_advertised_addrs.emplace_back(addr,  htons(snow::conf[snow::DTLS_BIND_PORT]));
		public_addr_known = true;
	}
	if(natpmp_addr != 0)  {
		local_advertised_addrs.emplace_back(natpmp_addr, natpmp_port ? natpmp_port : htons(snow::conf[snow::DTLS_BIND_PORT]));
		public_addr_known = true;
	}
	for(auto& ip : local_interface_addrs) {
		if(ip.is_ip4map6()) {
			local_advertised_addrs.emplace_back(ip, htons(snow::conf[snow::DTLS_BIND_PORT]));
			if(ip.is_rfc1918() == false)
				public_addr_known = true;
		} else {
			local_advertised_addrs.emplace_back(ip, htons(snow::conf[snow::DTLS_BIND6_PORT]));
		}
	}
	if(public_addr_known == false && snow::conf[snow::NEVER_TRUST_PEER_VISIBLE_IPADDRS] == false) {
		// public IPv4 addr is unknown, include any peer-provided non-RFC1918 IPv4 addresses
		for(auto& addr : peer_visible_addrs) {
			if(addr.first.addr.is_ip4map6() == true && addr.first.addr.is_rfc1918() == false)
				local_advertised_addrs.emplace_back(addr.first);
		}
	}
	while(local_advertised_addrs.size() > 16)
		local_advertised_addrs.pop_back(); // truncate if number of addrs becomes silly
	dht_thread->set_local_ipaddrs(local_advertised_addrs);
}


void dtls_dispatch::do_holepunch(const std::vector<ip_info>& addrs, in_port_t port)
{
	for(const ip_info& ip : addrs) {
		sockaddrunion remote, local;
		ip.copy_to(remote);
		try {
			csocket test(remote.s.sa_family, SOCK_DGRAM);
			test.connect(remote);
			test.getsockname(local);
		} catch(const e_check_sock_err& e) {
			// this is fairly common when e.g. peer provides IPv6 addr and this node doesn't have one
			dout() << "Could not do holepunch to " << remote << ": " << e;
			continue;
		}
		if(remote.s.sa_family == AF_INET) {
			local.set_ip_port(htons(snow::conf[snow::DTLS_BIND_PORT]));
		} else {
			local.set_ip_port(htons(snow::conf[snow::DTLS_BIND6_PORT]));
		}
		// addrs obtained from DHT CONNECT contain remote peer's incoming port rather than outgoing port, so if port != 0 then use as remote port
		if(port != 0)
			remote.set_ip_port(port);
		send_holepunch(local, remote);
	}
}

void dtls_dispatch::send_holepunch(const sockaddrunion& local, const sockaddrunion& remote)
{
	// send holepunch packet with zero byte payload
	dout() << "send_holepunch local " << local << " remote " << remote;
	auto it = socket_map.find(ip_info(local));
	if(it != socket_map.end()) {
		try {
			sockets[it->second].sock.sendto("", 0, remote);
		} catch(const check_err_exception &e) {
			eout() << "dispatch doing UDP holepunch local " << local << " remote " << remote << ": " << e;
		}
	} else {
		dout() << "Could not find local addr " << local << " in socket map for sending holepunch to " << remote;
	}
}

void dtls_dispatch::peer_socket_event(size_t index, pvevent event, sock_err err)
{
	if(event & (pvevent::read | pvevent::write)) {
		dbuf buf(buflist.get());
		try {
			sockaddrunion fromaddr;
			dtls_socket& dsock = sockets[index];
			// TODO: may be worth trying to read more than once here before giving control back to pollvector
				// with shared sockets there could be quite a few packets from several peers
				// do of course need a limit before returning because this could be starving other sockets, but doing e.g. up to 10 packets seems reasonable
			size_t len = dsock.sock.recvfrom(buf.data(), buf.size(), &fromaddr);
			if(len > 0) {
				auto it = dsock.peers.find(ip_info(fromaddr));
				if(it != dsock.peers.end()) {
					it->second->socket_read_event(buf, len);
				} else if(len != 16 || check_port_detect_nonce(buf, fromaddr) == false) {
					// new connection, give data to pinit in exchange for new dtls_peer ptr
					if(run_state == RUNNING) {
						std::shared_ptr<dtls_peer> newpeer = pinit->new_peer_socket_event(dsock.local_addr, fromaddr, buf, len, dsock.sock.fd());
						if(newpeer != nullptr)
							dsock.peers.emplace(ip_info(fromaddr), std::move(newpeer));
					} // (else ignore, no new connections during shutdown)
				}
			} else {
				dout() << "Read 0 bytes from " << fromaddr << " on dispatch UDP sock " << sockets[index].local_addr << " (possible holepunch packet)";
			}
		} catch(const e_check_sock_err& e) {
			dout() << "dispatch peer socket recvfrom failure: " << e;
		}
		buflist.recover(std::move(buf));
	} else {
		dout() << "dispatch got socket error " << err;
		// socket error could be attacker sending spurious ICMP or the like, ignore (maybe rebind socket depending on error? or check if addr is still on interface?)
	}
	cleanup_peers();
}

void dtls_dispatch::icmp_socket_event(size_t, pvevent event, sock_err err)
{
	if(event & pvevent::error) {
		eout() << "Error on ICMP socket: " << err;
		return;
	}
	try {
		dbuf buf(buflist.get());
		size_t bytes = sockets[ICMP4_FD].sock.recv(buf.data(), buf.size());
		if(bytes > 0) {
			snow_packet* packet = reinterpret_cast<snow_packet*>(buf.data());
			if(validate_packet4_length(packet, bytes)) {
				dout() << bytes << " byte icmp4 socket packet: " << *packet;
				if(packet->header.protocol == ipv4_header::ICMP) {
					icmp_header& icmp = packet->header.transport_header().icmp;
					if(icmp.icmp_type == icmp_header::DEST_UNREACHABLE && icmp.payload()->header.protocol == ipv4_header::UDP) {
						const snow_packet* inner_packet = icmp.payload();
						if(icmp.code == icmp_header::PACKET_TOO_BIG) {
							uint16_t mtu = ntohl(icmp.header_data) & 0xffff; // proposed MTU
							mtu += inner_packet->header.ihl();
							set_icmp_pmtu(ip_info(inner_packet->header.src_addr, inner_packet->header.transport_header().udp.src_port),
								ip_info(inner_packet->header.dst_addr, inner_packet->header.transport_header().udp.dst_port), mtu);
						} else {
							icmp_unreachable(ip_info(inner_packet->header.src_addr, inner_packet->header.transport_header().udp.src_port),
								ip_info(inner_packet->header.dst_addr, inner_packet->header.transport_header().udp.dst_port));
						}
					}
				}
			} else {
				dout() << bytes << " byte ICMP packet failed length validation";
			}
		} else {
			// (fail)
			dout() << "0 byte packet from vnet ICMP4 socket";
		}
		buflist.recover(std::move(buf));
	} catch(const e_check_sock_err& e) {
		eout() << "Recv error from ICMP socket: " << e;
	}
}
void dtls_dispatch::icmp6_socket_event(size_t, pvevent event, sock_err err)
{
	if(event & pvevent::error) {
		eout() << "Error on ICMP socket: " << err;
		return;
	}
	try {
		dbuf buf(buflist.get());
		size_t bytes = sockets[ICMP6_FD].sock.recv(buf.data(), buf.size());
		if(bytes > 0) {
			icmp6_header* packet = reinterpret_cast<icmp6_header*>(buf.data());
			if(validate_ipv6_icmp(packet, bytes)) {
				dout() << bytes << " byte icmp6 socket packet: " << *packet;
				if(packet->contains_inner_packet() && packet->payload()->header6.next_header == ipv4_header::UDP) {
					const snow_packet* inner_packet = packet->payload();
					if(packet->icmp_type == icmp6_header::PACKET_TOO_BIG) {
						// this fails to account for extension headers, but 'next_header == UDP' is ignoring packets with them anyway
						uint16_t mtu = ntohl(packet->header_data)/*proposed MTU*/ + sizeof(ipv6_header);
						set_icmp_pmtu(ip_info(inner_packet->header6.src_addr, inner_packet->header6.transport_header().udp.src_port),
							ip_info(inner_packet->header6.dst_addr, inner_packet->header6.transport_header().udp.dst_port), mtu);
					} else if(packet->icmp_type == icmp6_header::DEST_UNREACHABLE) {
						icmp_unreachable(ip_info(inner_packet->header6.src_addr, inner_packet->header6.transport_header().udp.src_port),
							ip_info(inner_packet->header6.dst_addr, inner_packet->header6.transport_header().udp.dst_port));
					}
				}
			} else {
				dout() << bytes << " byte ICMP6 packet failed length validation";
			}
		} else {
			// (fail)
			dout() << "0 byte packet from vnet ICMP6 socket";
		}
		buflist.recover(std::move(buf));
	} catch(const e_check_sock_err& e) {
		eout() << "Recv error from ICMP6 socket: " << e;
	}
}
void dtls_dispatch::set_icmp_pmtu(const ip_info& local, const ip_info& remote, uint16_t mtu)
{
	auto local_it = socket_map.find(local);
	if(local_it != socket_map.end()) {
		auto& peers = sockets[local_it->second].peers;
		auto remote_it = peers.find(remote);
		if(remote_it != peers.end()) {
			remote_it->second->set_icmp_mtu(mtu);
		}
	}
}
void dtls_dispatch::icmp_unreachable(const ip_info& local, const ip_info& remote)
{
	auto local_it = socket_map.find(local);
	if(local_it != socket_map.end()) {
		auto& peers = sockets[local_it->second].peers;
		auto remote_it = peers.find(remote);
		if(remote_it != peers.end()) {
			remote_it->second->socket_error_occurred();
		}
	}
}

// TODO: just eliminate local_port here and always use DTLS_OUTGOING_PORT
	// even if there are two nodes behind the same NAT that have chosen the same source port, the NAT should NAPT one of them which should be detected
	// and then that port should be sent as the holepunch port for counter-CONNECT in a DHT CONNECT [not implemented]
	// also not implemented: don't use DTLS_SOURCE_PORT here, use "source_port" variable which is DTLS_SOURCE_PORT unless that port couldn't be bound, in which case choose random port that can be bound to all addrs (like DHT does)
dtls_socket& dtls_dispatch::get_socket(const sockaddrunion& remote, in_port_t local_port)
{
	// get local ipaddr that would be used by OS routing table to reach remote ipaddr
	csocket test(remote.s.sa_family, SOCK_DGRAM);
	// TODO: this Does The Wrong Thing for IPv6 link-local addresses (throws exception, errno "invalid argument")
	// to use link-local address requires specifying the interface (scope_id in sockaddr_in6?); this should be easy if there is only one interface, but what if there isn't?
		// the answer is probably to do a separate connection for each link-local (fe80::) IPv6 address on the local machine
	test.connect(remote);
	sockaddrunion local;
	test.getsockname(local);
	// return existing socket if any, otherwise create new
	local.set_ip_port(local_port ? local_port : htons(snow::conf[snow::DTLS_OUTGOING_PORT]));
	auto local_it = socket_map.find(ip_info(local));
	if(local_it != socket_map.end())
		return sockets[local_it->second];
	create_socket(local);
	return sockets.back();
}

void dtls_dispatch::cleanup_socket(size_t index)
{
	dout() << "dispatch cleanup_socket index " << index << " sd " << sockets[index].sock.fd();
	socket_map[ip_info(sockets.back().local_addr)] = index; // back() becomes index
	sockets.set_fd(index, INVALID_SOCKET); // pollvector should not close socket as ~csocket() will do that
	socket_map.erase(ip_info(sockets[index].local_addr));
}

void dtls_dispatch::set_pointers(dht* d, nameserv* ns)
{
	dht_thread = d;
	nameserv_thread = ns;
	vn->set_pointers(d, pinit.get(), ns);
	pinit->set_pointers(d);
}

void dtls_dispatch::send_port_detect_nonce(std::shared_ptr<vnet_peer>& peer)
{
	port_detect_nonce nonce;
	dout() << "Sending port detect nonce " << std::hex << nonce.nonce0 << " " << nonce.nonce1 << std::dec << " to " << peer->conn->get_hashkey();
	port_nonce_map[nonce]=peer;
	timers.add(20, [this,nonce]() { port_nonce_map.erase(nonce); } );
	snow_port_detect port_detect(nonce.bytes());
	peer->get_conn().send(reinterpret_cast<uint8_t*>(&port_detect), sizeof(port_detect));
}
void dtls_dispatch::snow_port_detect_packet(snow_port_detect* packet, vnet_peer& frompeer)
{
	const sockaddrunion& fromaddr = frompeer.conn->get_peer();
	if(packet->port == 0) {
		try {
			csocket test(fromaddr.s.sa_family, SOCK_DGRAM);
			test.connect(fromaddr);
			sockaddrunion local;
			test.getsockname(local);
			local.set_ip_port(local.s.sa_family == AF_INET ? htons(snow::conf[snow::DTLS_BIND_PORT]) : htons(snow::conf[snow::DTLS_BIND6_PORT]));
			auto local_it = socket_map.find(ip_info(local));
			if(local_it != socket_map.end()) {
				sockets[local_it->second].sock.sendto(packet->data, sizeof(packet->data), fromaddr);
				dout() << "Sent port detect UDP nonce to peer at " << fromaddr;
			} else {
				// this happening is probably a bug, there should be a socket on every local address that the OS would use for an outgoing packet
				dout() << "No socket found on " << local << " to send port detect nonce to " << fromaddr;
			}
		} catch(const e_check_sock_err& e) {
			dout() << "Could not send port detect UDP nonce packet to peer at " << fromaddr << ": " << e;
		}
	} else {
		ip_info ip(packet->data, packet->port);
		// zero port means we don't know the port (this also prevents the peer from adding multiple addrs/ports, as the first packet sets the port to nonzero)
		if(frompeer.visible_ipaddr.port == 0) {
			if(frompeer.visible_ipaddr.addr == ip.addr) {
				dout() << "Got port detect from " << fromaddr << " with addr " << ip;
				frompeer.visible_ipaddr.port = ip.port;
				add_peer_visible_ipaddr(ip);
			} else {
				// TODO: in theory an address different than the one provided in snow hello could provide useful information (e.g. some kind of enterprise NAT)
					// but it could also be some kind of attack, so discard addr for now and maybe revisit this later
				dout() << "Discarded port detect from " << fromaddr << " with addr " << ip << " which did not match expected address " << frompeer.visible_ipaddr.addr;
			}
		} else {
			dout() << "Discarded port detect from " << fromaddr << " with addr " << ip << " because existing addr and port were previously discovered as " << frompeer.visible_ipaddr;
		}
	}
}
bool dtls_dispatch::check_port_detect_nonce(const uint8_t* nonce_data, const sockaddrunion& fromaddr)
{
	port_detect_nonce nonce(nonce_data);
	auto it = port_nonce_map.find(nonce);
	if(it != port_nonce_map.end()) {
		dout() << "Got port detect nonce " << std::hex << nonce.nonce0 << " " << nonce.nonce1 << std::dec << " from " << fromaddr;
		if(auto ptr = it->second.lock()) {
			ip_info from(fromaddr);
			snow_port_detect reply(from.addr.ip6.s6_addr, from.port);
			ptr->get_conn().send(reinterpret_cast<uint8_t*>(&reply), sizeof(reply));
		}
		port_nonce_map.erase(it);
		return true;
	} else {
		dout() << "16-byte UDP packet from " << fromaddr << " was not a recognized port detect nonce";
	}
	return false;
}

// dht -> pinit
void dtls_dispatch::add_peer(dht_connect_info&& info) {
	dout() << "add_connection doing new_connect_info for " << info.peer;
	interthread_msg_queue.put(std::bind(&peer_init::new_connect_info, pinit.get(), std::move(info)));
}
// pinit -> vnet, vnet -> pinit
void dtls_dispatch::update_peer(const ip_info& local, const ip_info& remote, std::shared_ptr<dtls_peer> newpeer)
{
	auto local_it = socket_map.find(local);
	if(local_it != socket_map.end()) {
		auto& peers = sockets[local_it->second].peers;
		auto remote_it = peers.find(remote);
		if(remote_it != peers.end()) {
			remote_it->second = std::move(newpeer);
		}
	}
}
// pinit -> bye bye
void dtls_dispatch::remove_peer(const ip_info& local, const ip_info& remote)
{
	dout() << "remove_peer local " << local << " remote " << remote;
	auto local_it = socket_map.find(local);
	if(local_it != socket_map.end()) {
		dtls_socket& sock = sockets[local_it->second];
		auto remote_it = sock.peers.find(remote);
		if(remote_it != sock.peers.end()) {
			sock.peers.erase(remote_it);
			if(sock.peers.size() == 0 && (sock.flags & dtls_socket::PERSISTENT) == 0) {
				dout() << "retiring disused non-persistent socket at idx " << local_it->second;
				sockets.mark_defunct(local_it->second);
				socket_map.erase(local_it);
			} else {
				dout() << "not removing socket with " << sock.peers.size() << " peers, flags " << sock.flags;
			}
		} else {
			eout() << "BUG: Requested to remove connection with non-existent peer from local " << local << " to remote " << remote;
		}
	} else {
		eout() << "BUG: Requested to remove connection with non-existent socket from local " << local << " to remote " << remote;
	}
}

bool dtls_dispatch::cleanup_peers() {
	bool any_removed = false;
	while(cleanup_queue.size() > 0) {
		if(std::shared_ptr<dtls_peer> ptr = cleanup_queue.front().lock()) {
			ptr->cleanup();
			any_removed = true;
		}
		cleanup_queue.pop();
	}
	return any_removed;
}

void dtls_dispatch::do_shutdown_thread_pending()
{
	run_state = SHUTDOWN_PENDING;
	pinit->shutdown_thread_pending();
	cleanup_peers();
	remove_natpmpupnp_mappings(htons(snow::conf[snow::DTLS_BIND_PORT]));
}
void dtls_dispatch::do_shutdown_thread()
{
	run_state = SHUTDOWN;
	vn->shutdown_thread();
	cleanup_peers();
}

void dtls_dispatch::check_connection(const hashkey& fingerprint) {
	void (vnet::*send_hb)(const hashkey&) = &vnet::send_heartbeat;
	interthread_msg_queue.put(std::bind(send_hb, vn.get(), fingerprint));
}
void dtls_dispatch::check_all_connections() {
	interthread_msg_queue.put(std::bind(&vnet::send_heartbeat_all, vn.get()));
}
void dtls_dispatch::touch_connection(const hashkey& fingerprint) {
	interthread_msg_queue.put(std::bind(&vnet::reset_idle_count, vn.get(), fingerprint));
}
const hashkey& dtls_dispatch::get_hashkey() { return pinit->local_hashkey(); }
uint32_t dtls_dispatch::virtual_interface_ipaddr() { return vn->get_tun_ipaddr(); }

dtls_dispatch::~dtls_dispatch() {} // unique_ptr members need destructor to be defined where class definition for T in unique_ptr<T> is visible
