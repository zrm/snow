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

#include<iostream>
#include<fstream>
#include<iomanip>
#include<algorithm>
#include<cstdio>
#include<cstdint>
#include<cstdlib>
#include<cstring>
#include<chrono>


#include"dht.h"
#include"dht_msgtype.h"
#include"../common/err_out.h"
#include"nameserv.h"
#include"../common/common.h"
#include"../common/network.h"
#include"configuration.h"
#include"peer_init.h"




dht_newconn dht::get_client()
{
	dht_newconn rv;
	sockaddrunion client_addr;
	try {
		rv.sock = dht_incoming.accept(&client_addr);
		if(client_addr.ss.ss_family != AF_INET)
			throw check_err_exception("unsupported address family for DHT client", false);
		rv.sock.setopt_nonblock();
		rv.sock.setopt_keepalive();
		dout() << "dht_listen::get_client(): accept()'d good new client";
		rv.nat_addr = client_addr.sa.sin_addr.s_addr;
	} catch(const e_check_sock_err &e) {
		if(sock_err_is_wouldblock(sock_err::get_last())) {
			dout() << "dht_listen::get_client(): accept() gave no additional client";
		} else {
			eout() << "dht_listen::get_client(): error accepting new DHT client: " << e;
			rv.sock = csocket();
		}
	}
	return rv;
}

/*
	DHT header format:
		Routed messages:
			[2:MSG TYPE][2:MSG LEN][2:HASH LEN][2:HASH TYPE][DESTINATION HASH] [message type specific data]
		Direct messages:
			[2:MSG TYPE][2:MSG LEN] [message type specific data]

		This allows DHT nodes with older software versions to successfully pass messages added to the protocol in later versions:
			as long as the header format is followed, a node doesn't need to know what a message contains to route it.
			
		Naturally this implies a distinction between routed and direct messages,
			e.g. direct messages have message types > 32768
			(and if a node gets a direct message it doesn't understand, it just ignores it, or maybe log warning about 'bad data or please upgrade')
*/

typedef dht::DHTMSG DHTMSG;

template<> void dht::process_msgtype<DHTMSG::CONNECT>(dhtmsg msg, dht_peer& frompeer)
{
	dhtmsg_type<DHTMSG::CONNECT> connect_msg(msg);
	typedef dht::msg_enum<DHTMSG::CONNECT>::FIELDS F;
	dht_flags flags = connect_msg.get<F::FLAGS>();
	if(flags.getflag(CONNECT_FLAGS::TRACKBACK)) {
		if(!trackback_follow(connect_msg, frompeer)) {
			// fail: trackback route expired or invalid
			dout() << "CONNECT with trackback flag had invalid route ID, trying normal routing";
			flags.clearflag(CONNECT_FLAGS::TRACKBACK);
			connect_msg.set<F::FLAGS>(flags);
			connect_msg.set<F::ROUTE_ID>(trackback_route_id(static_cast<uint64_t>(0)));
			trackback_forward(connect_msg, frompeer);
		}
	} else {
		trackback_forward(connect_msg, frompeer);
	}
}
template<> void dht::process_msgtype_final<DHTMSG::CONNECT>(dhtmsg msg, dht_peer& frompeer)
{
	// IPv4 addresses will be sent in IPv6 format, i.e. first 80 bits zero, next 16 bits one, last 32 bits IPv4 addr
	dhtmsg_type<DHTMSG::CONNECT> msg_inst(msg);
	typedef dht::msg_enum<DHTMSG::CONNECT>::FIELDS M;
	// do trackback sanity check
	dht_flags flags = msg_inst.get<M::FLAGS>();
	hashkey dest = msg_inst.get<M::DEST_HASHKEY>().get_hashkey();
	if(flags.getflag(CONNECT_FLAGS::TRACKBACK) && dest != dispatch_thread->get_hashkey()) {
		// this should not happen in practice, anyone who has trackback route ID should also have correct hashkey
		dout() << "Got trackback CONNECT not exact match for this node's hashkey, resending without trackback";
		flags.clearflag(CONNECT_FLAGS::TRACKBACK);
		msg_inst.set<M::FLAGS>(flags);
		process_msg(msg_inst.get_msg(), frompeer);
		return;
	}


	hashkey target = msg_inst.get<M::TARGET_HASHKEY>().get_hashkey();
	if(dest != dispatch_thread->get_hashkey()
			&& dest.algo() != md_hash::DATA // mismatch expected for DATA hashkey
			&& dest != target // mismatch expected for check route failure mitigation connection
			) {
		dout() << "DHT CONNECT destination mismatch, sending MISMATCH_DETECTED";
		dhtmsg_type<DHTMSG::MISMATCH_DETECTED> mismatch(msg_inst.get<M::TARGET_HASHKEY>(), msg_inst.get<M::ROUTE_ID>(), msg_inst.get<M::DEST_HASHKEY>());
		trackback_follow(mismatch, *connections[LOCAL_INDEX]);
	}
	if(!target.initialized())
	{
		wout() << "Unsupported DHT hash in DHT CONNECT message, request dropped";
		// TODO: should notify sender of failure (could be software version issue?)
		return;
	}
	if(target == connections[LOCAL_INDEX]->fingerprint) {
		dout() << "DHT CONNECT received with local node as target, ignored";
		return;
	}
	auto it =  peer_map.find(target);
	if(it != peer_map.end() && connected_peers.count(it->second.peer->nat_ipaddr) == 0) {
		// peer is DTLS connected but not DHT connected, try doing DHT connect in case CONNECT was sent for DHT congestion control
		dht_connect(it->second.peer);
		// but send request to dispatch even if connected, in case connection failed / is about to fail; dispatch is responsible to sort out things like that
	}
	
	// TODO: if peer's source port differs from the one in known_peers and this CONNECT has NO_RETRY set, we probably sent the holepunch to the wrong addrs for the original CONNECT
		// so if CONNECT src port doesn't match entry from known_peers, do the holepunch again right away with correct port and hopefully pick up the incoming connection before it times out
	
	// TODO: if this node knows that its source port will be NAPT'd to a specific port when it makes this connection, send trackback HOLEPUNCH_ADDRS to peer with that port
	
	std::vector<ip_info> addrs = msg_inst.get<M::IP_ADDRS>().get();
	in_port_t src_port = msg_inst.get<M::SRC_PORT>().get_nbo();
	if(flags.getflag(CONNECT_FLAGS::REQUEST_HP_ADDRS)) {
		// TODO: in theory different addrs could have different [visible] source ports but this is just using the default source port for all of them
		std::vector<ip_info> local_addrs(local_ipaddrs);
		for(ip_info& a : local_addrs)
			a.port = htons(snow::conf[snow::DTLS_OUTGOING_PORT]);
		dhtmsg_type<DHTMSG::HOLEPUNCH_ADDRS> hp(dht_hash(target), trackback_route_id(msg_inst.get<M::ROUTE_ID>()), dht_ip_addrs(local_addrs));
		process_msg(hp.get_msg(), *connections[LOCAL_INDEX]);
	}
	std::shared_ptr<dht_connect_retry> retry;
	if(flags.getflag(CONNECT_FLAGS::NO_RETRY) == false) {
		// if this CONNECT was a trackback then the retry can't be too so use FIRST_HOP in that case, otherwise use TRACKBACK
		if(flags.getflag(CONNECT_FLAGS::TRACKBACK))
			retry = std::make_shared<dht_connect_retry>(dht_connect_retry::FIRST_HOP, src_port, false, frompeer.fingerprint);
		else
			retry = std::make_shared<dht_connect_retry>(dht_connect_retry::TRACKBACK, src_port, false, msg_inst.get<M::ROUTE_ID>().get_hbo());
	}
	{
		dout out;
		out << "DHT CONNECT for " << target << " with addrs";
		for(auto& addr : addrs)
			out << " " << addr;
	}
	dispatch_thread->add_peer(dht_connect_info(std::move(target), std::move(addrs), true, std::move(retry)));
}
template<> void dht::reroute_msg<DHTMSG::CONNECT>(dhtmsg msg, dht_peer& frompeer)
{
	dhtmsg_type<DHTMSG::CONNECT> connect_msg(msg);
	typedef dht::msg_enum<DHTMSG::CONNECT>::FIELDS F;
	dht_flags flags = connect_msg.get<F::FLAGS>();
	if(flags.getflag(CONNECT_FLAGS::TRACKBACK)) {
		dout() << "CONNECT with trackback flag rerouted not using trackback";
		flags.clearflag(CONNECT_FLAGS::TRACKBACK);
		connect_msg.set<F::FLAGS>(flags);
		connect_msg.set<F::ROUTE_ID>(trackback_route_id(static_cast<uint64_t>(0)));
	}
	trackback_forward(connect_msg, frompeer);
}

template<> void dht::process_msgtype<DHTMSG::HOLEPUNCH_ADDRS>(dhtmsg msg, dht_peer& frompeer)
{
	dhtmsg_type<DHTMSG::HOLEPUNCH_ADDRS> hp_msg(msg);
	typedef dht::msg_enum<DHTMSG::HOLEPUNCH_ADDRS>::FIELDS F;
	if(hp_msg.get<F::ROUTE_ID>().get_hbo() != 0) {
		if(trackback_follow(hp_msg, frompeer))
			return;
		hp_msg.set<F::ROUTE_ID>(trackback_route_id(0UL));
	}
	route_msg(hp_msg.get_msg(), frompeer);
}
template<> void dht::process_msgtype_final<DHTMSG::HOLEPUNCH_ADDRS>(dhtmsg msg, dht_peer& /*frompeer*/)
{
	dhtmsg_type<DHTMSG::HOLEPUNCH_ADDRS> msg_inst(msg);
	typedef dht::msg_enum<DHTMSG::HOLEPUNCH_ADDRS>::FIELDS M;
	hashkey dest = msg_inst.get<M::DEST_HASHKEY>().get_hashkey();
	if(dest == dispatch_thread->get_hashkey()) {
		std::vector<ip_info> addrs = msg_inst.get<M::IP_ADDRS>().get();
		dispatch_thread->holepunch_request(std::move(addrs));
	} else {
		dout() << "Got DHT HOLEPUNCH_ADDRS for wrong hashkey " << dest;
	}
}

template<> void dht::process_msgtype<DHTMSG::MISMATCH_DETECTED>(dhtmsg msg, dht_peer& frompeer)
{
	
	dhtmsg_type<DHTMSG::MISMATCH_DETECTED> mismatch(msg);
	typedef dht::msg_enum<DHTMSG::MISMATCH_DETECTED>::FIELDS F;
	if(!trackback_follow(mismatch, frompeer)) {
		mismatch.set<F::ROUTE_ID>(trackback_route_id(0UL));
		route_msg(mismatch.get_msg(), frompeer);
	}
}
template<> void dht::process_msgtype_final<DHTMSG::MISMATCH_DETECTED>(dhtmsg msg, dht_peer&)
{
	dhtmsg_type<DHTMSG::MISMATCH_DETECTED> mismatch(msg);
	typedef dht::msg_enum<DHTMSG::MISMATCH_DETECTED>::FIELDS F;
	hashkey dest = mismatch.get<F::DEST_HASHKEY>().get_hashkey();
	hashkey target = mismatch.get<F::TARGET_HASHKEY>().get_hashkey();
	if(dest == dispatch_thread->get_hashkey()) {
		auto it = dht_connect_pending.find(target);
		if(it != dht_connect_pending.end() && (it->second.flags & dhtconnect_opts::BROADCAST_RETRY)) {
			// either peer is down or routing failure, try broadcasting CONNECT to see if some other path will get us there
			dout() << "Got valid MISMATCH_DETECTED for " << target << ", retrying with broadcast CONNECT";
			send_broadcast_connect(mismatch.get<F::TARGET_HASHKEY>().get_hashkey());
		}
	} else {
		dout() << "Got MISMATCH_DETECTED for wrong hashkey or without having sent CONNECT, ignored";
		// TODO: anything useful that could be done in this case?
	}
}
template<> void dht::reroute_msg<DHTMSG::MISMATCH_DETECTED>(dhtmsg msg, dht_peer& frompeer)
{
	dhtmsg_type<DHTMSG::MISMATCH_DETECTED> mismatch(msg);
	typedef dht::msg_enum<DHTMSG::MISMATCH_DETECTED>::FIELDS F;
	if(mismatch.get<F::ROUTE_ID>().get_nbo() != 0)
		mismatch.set<F::ROUTE_ID>(trackback_route_id(static_cast<uint64_t>(0)));
	route_msg(mismatch.get_msg(), frompeer);
}


template<> void dht::process_msgtype<DHTMSG::CHECK_ROUTE>(dhtmsg msg, dht_peer& frompeer)
{
	dhtmsg_type<DHTMSG::CHECK_ROUTE> check(msg);
	typedef dht::msg_enum<DHTMSG::CHECK_ROUTE>::FIELDS F;
	trackback_forward(check, frompeer, false);
	// CHECK_ROUTE will intentionally bypass a directly connected exact match destination unless it is this node's immediate antecedent
	// that way a routing failure will be detected that would not be detected by the coincidence of the target being directly connected to this node
	// (this has the consequence that CHECK_ROUTE will always be received through the target's successor if routing is working)
	hashkey dest = check.get<F::DEST_HASHKEY>().get_hashkey();
	if(dest == connections[LOCAL_INDEX]->fingerprint) {
		route_msg(msg, frompeer, *connections[LOCAL_INDEX]);
	} else if(dest == route_map.antecedent()->fingerprint) {
		route_msg(msg, frompeer, *route_map.antecedent());
	} else {
		route_msg(msg, frompeer, route_map.upper_bound(dest));
	}
}
template<> void dht::reroute_msg<DHTMSG::CHECK_ROUTE>(dhtmsg msg, dht_peer& frompeer)
{
	process_msgtype<DHTMSG::CHECK_ROUTE>(msg, frompeer);
}
template<> void dht::process_msgtype_final<DHTMSG::CHECK_ROUTE>(dhtmsg msg, dht_peer& frompeer)
{
	dhtmsg_type<DHTMSG::CHECK_ROUTE> check(msg);
	typedef dht::msg_enum<DHTMSG::CHECK_ROUTE>::FIELDS F;
	dht_hash hash = check.get<F::DEST_HASHKEY>();
	hashkey hk = hash.get_hashkey();
	if(dispatch_thread->get_hashkey() == hk) {
		// routing works, send CHECK_ROUTE_OK to appropriate peer from nonce table
		// TODO: check that frompeer is successor: if it isn't then frompeer thinks we're its antecedent even though we aren't, so cause frompeer to connect to antecedent
		auto it = nonce_map.find(check.get<F::NONCE>().get_hbo());
		if(it != nonce_map.end()) {
			/*if(it->second == fromidx) {
				// TODO: peer we sent CHECK_ROUTE to sent it directly back, this means routing was previously broken, any checks to run here?
			}*/
			if(auto ptr = it->second.lock()) {
				dout() << "CHECK_ROUTE matches local hashkey, sending CHECK_ROUTE_OK to peer idx " << ptr->index;
				write_peer(dhtmsg_type<DHTMSG::CHECK_ROUTE_OK>().get_msg(), *ptr, *connections[LOCAL_INDEX]);
			} else {
				dout() << "Got CHECK_ROUTE with valid nonce but the peer it was sent through has disconnected";
			}
			nonce_map.erase(it);
		} else {
			// FAIL: what is this about? routing so slow that the timeout occurred before we got the CHECK_ROUTE?
				// (this can also occur if peer was disconnected between sending HELLO and receiving CHECK_ROUTE)
			if(check.get<F::NONCE>().get_hbo() == 0)
				dout() << "Got CHECK_ROUTE destined for this node with zero nonce, must have been a verify but routing worked (or last peer disconnected and successor is self)";
			else 
				dout() << "Got CHECK_ROUTE but nonce not found in nonce_map";
		}
	} else {
		// check if directly connected
		auto it = peer_map.find(hk);
		if(it != peer_map.end() && it->second.dht_connected) {
			// CHECK_ROUTE couldn't be routed anywhere closer to the newly connected peer than this node, so technically there is a routing failure
			// but the failure is only that routing is not enabled between the two peers, so send the message directly and cause routing to be enabled
			// do this instead of just enabling routing so that the peer knows routing will be enabled
				// (this is OK even if CHECK_ROUTE is not directly from this peer, because the one that is will end up here too and routing gets enabled either way)
			dout() << "CHECK_ROUTE for directly connected peer " << hk << ", sending CHECK_ROUTE directly to peer";
			write_peer(msg, *it->second.peer, frompeer);
			// when this happens, it indicates possible routing problems in general,
				// so send a gratuitious CHECK_ROUTE for this node's antecedent through the new peer (the successor will have been caught by the peer's CHECK_ROUTE)
			if(route_map.antecedent() != it->second.peer && route_map.antecedent()->index != LOCAL_INDEX) {
				// adding trackback route with route_id 0, which is reserved to never be assigned and if received, peer should revert msg to normal routing
				dhtmsg_type<DHTMSG::CHECK_ROUTE> check_peer(dht_hash(route_map.antecedent()->fingerprint),
					nonce64(0UL), trackback_route_id(add_trackback_route(0, *route_map.antecedent())));
				write_peer(check_peer.get_msg(), *it->second.peer, *connections[LOCAL_INDEX]);
			}
		} else {
			dout() << "got CHECK_ROUTE from " << frompeer.fingerprint << " not matching this node, possible routing problem, sending trackback CONNECT";
			bool req_hp_addrs = true, follow_trackback = true;
			send_connect(hash, dhtconnect_opts(htons(snow::conf[snow::DTLS_OUTGOING_PORT]), req_hp_addrs), follow_trackback, check.get<F::ROUTE_ID>().get_hbo());
			// after this the sending peer's CHECK_ROUTE will time out and in a minute or so it will send another one
		}
	}
}



template<> void dht::process_msgtype<DHTMSG::TRACKBACK_FORWARD>(dhtmsg msg, dht_peer& frompeer)
{
	dhtmsg_type<DHTMSG::TRACKBACK_FORWARD> fwd(msg);
	trackback_forward(fwd, frompeer);
}
template<> void dht::process_msgtype_final<DHTMSG::TRACKBACK_FORWARD>(dhtmsg msg, dht_peer& frompeer)
{
	dhtmsg_type<DHTMSG::TRACKBACK_FORWARD> forward(msg);
	forward_payload(forward.get<dht::msg_enum<DHTMSG::TRACKBACK_FORWARD>::FIELDS::PAYLOAD>(), frompeer);
}

template<> void dht::process_msgtype<DHTMSG::FORWARD>(dhtmsg msg, dht_peer& frompeer)
{
	route_msg(msg, frompeer); // just forward to destination
}
template<> void dht::process_msgtype_final<DHTMSG::FORWARD>(dhtmsg msg, dht_peer& frompeer)
{
	dhtmsg_type<DHTMSG::FORWARD> forward(msg);
	forward_payload(forward.get<dht::msg_enum<DHTMSG::FORWARD>::FIELDS::PAYLOAD>(), frompeer);
}


/* direct messages:
 * process_msgtype does the normal work
 * process_msgtype_final is only called on error,
 *		in particular if the message couldn't be routed to the peer for some reason (e.g. congestion, disconnect) and can be used for cleanup
 *		but generally just complain and drop (which is the default for unimplemented templates)
*/

template<>
void dht::process_msgtype<DHTMSG::HELLO>(dhtmsg msg, dht_peer& peer)
{
	dout() << "DHT HELLO from " << peer.fingerprint;
	if(peer.flags[peer.RECEIVED_HELLO]) {
		dout() << "Received duplicate DHT HELLO from peer, ignored";
		return;
	}
	peer.flags[peer.RECEIVED_HELLO] = true;
	peer.reconnect_delay = peer.flags[peer.PRIMARY] ? 0 : 15; // reset to default on receiving HELLO

	dhtmsg_type<DHTMSG::HELLO> hello(msg);
	typedef dht::msg_enum<DHTMSG::HELLO>::FIELDS F;
	int64_t time_diff = hello.get<F::TIME>().get_hbo() - get_time();
	if(time_diff < -3600 || time_diff > 3600) {
		wout() << "Connected to peer with significant disagreement on current time (" 
					  << (time_diff/60) << " minutes off), check your system clock";
	}
	// TODO: consider some mitigation in case of serious time differences -- any secure way to determine when local clock is inaccurate? worry about sybil attack
		// (peer time agreement is no longer required anyway, maybe remove from message?)

	// protocol version is currently ignored because no version of the protocol has been finalized
	
	// get CHECK_ROUTE nonce from HELLO and do routing check
	uint64_t route_id = hello.get<F::NONCE>().get_hbo(); // (need something to fill in route id, nonce will do)
	dhtmsg_type<DHTMSG::CHECK_ROUTE> check(dht_hash(peer.fingerprint), hello.get<F::NONCE>(), trackback_route_id(route_id));
	process_msg(check.get_msg(), peer);
}


template<>
void dht::process_msgtype<DHTMSG::CHECK_ROUTE_OK>(dhtmsg, dht_peer& frompeer)
{
	// OK, add peer 'frompeer' to route map
	if(!frompeer.flags[dht_peer::RECEIVED_HELLO]) {
		wout() << "Possible bug: got CHECK_ROUTE_OK from peer before HELLO, not enabling DHT routing to peer";
		return;
	}
	dout() << "CHECK_ROUTE_OK, enabled routing to peer idx " << frompeer.index << ", " << frompeer.fingerprint;
	// if this peer is the new successor or antecedent then make sure it's connected to the old antecedent or successor
	dht_peer &successor = *route_map.successor(), &antecedent = *route_map.antecedent();
	route_map.insert(connections[frompeer.index]);
	if(route_map.antecedent() == connections[frompeer.index] && antecedent.index != LOCAL_INDEX) {
		dhtmsg_type<DHTMSG::CONNECT> connect(dht_hash(antecedent.fingerprint), trackback_route_id(add_trackback_route(0, antecedent)),
			dht_flags(), dht_hash(frompeer.fingerprint), dht_ip_addrs(frompeer.native_addrs), ip_port(frompeer.dtls_srcport));
		write_peer(connect.get_msg(), antecedent, *connections[LOCAL_INDEX]);
	} else if(route_map.successor() == connections[frompeer.index] && successor.index != LOCAL_INDEX) {
		dhtmsg_type<DHTMSG::CONNECT> connect(dht_hash(successor.fingerprint), trackback_route_id(add_trackback_route(0, successor)),
			dht_flags(), dht_hash(frompeer.fingerprint), dht_ip_addrs(frompeer.native_addrs), ip_port(frompeer.dtls_srcport));
		write_peer(connect.get_msg(), successor, *connections[LOCAL_INDEX]);
	}
}

template<>
void dht::process_msgtype<DHTMSG::TRACKBACK_ROUTE>(dhtmsg msg, dht_peer& frompeer)
{
	dhtmsg_type<DHTMSG::TRACKBACK_ROUTE> trackback_msg(msg);
	typedef dht::msg_enum<DHTMSG::TRACKBACK_ROUTE>::FIELDS F;
	if(!trackback_follow(trackback_msg, frompeer)) {
		// route expired or this was final hop; forward encapsulated message
		forward_payload(trackback_msg.get<F::PAYLOAD>(), frompeer);
	}
}
template<> void dht::reroute_msg<DHTMSG::TRACKBACK_ROUTE>(dhtmsg msg, dht_peer& frompeer)
{
	// trackback routing failed, just forward the payload normally
	dhtmsg_type<DHTMSG::TRACKBACK_ROUTE> trackback_msg(msg);
	typedef dht::msg_enum<DHTMSG::TRACKBACK_ROUTE>::FIELDS F;
	forward_payload(trackback_msg.get<F::PAYLOAD>(), frompeer);
}

template<>
void dht::process_msgtype<DHTMSG::NOP>(dhtmsg, dht_peer& frompeer)
{
	dout() << "Got DHT NOP from " << frompeer.fingerprint;
}

/* disconnect protocol:
 *	peer wanting disconnect sends 'GOODBYE_REQUEST' msg and removes routing to peer (see dht::initiate_disconnect())
 *	other peer receives it, removes first peer from route map and peer_map and adds 'GOODBYE_CONFIRM' to end of that peer's write buf
 *	first peer receives 'GOODBYE_CONFIRM' from second peer; it will close connection.
 *	(when first peer closes connection, second peer will get pollvector event and trigger removal with CLEAN_SHUTDOWN set)
 */
template<>
void dht::process_msgtype<DHTMSG::GOODBYE_REQUEST>(dhtmsg, dht_peer& frompeer)
{
	dout() << "Got GOODBYE_REQUEST from DHT peer " << frompeer.fingerprint;
	// About to do clean disconnect. 
	// remove peer from route map so no new data is added
	remove_routing(frompeer);
	// write GOODBYE_CONFIRM to end of write buffer so peer will know when all data is sent and can disconnect
	write_peer(dhtmsg_type<DHTMSG::GOODBYE_CONFIRM>().get_msg(), frompeer, *connections[LOCAL_INDEX]);
	frompeer.flags[dht_peer::CLEAN_SHUTDOWN] = true;
	// if peer is not clean disconnected after timeout, disconnect anyway
	std::weak_ptr<dht_peer> wptr = connections[frompeer.index];
	timers.add(15, [this, wptr]() {
		if(auto ptr = wptr.lock())
			mark_defunct(*ptr);
	});
}
template<>
void dht::process_msgtype<DHTMSG::GOODBYE_CONFIRM>(dhtmsg, dht_peer& frompeer)
{
	dout() << "Got GOODBYE_CONFIRM from DHT peer " << frompeer.fingerprint;
	// peer confirms clean disconnect we requested
	// all data is sent, write buffers on both sides should be empty, close connection
	if(!frompeer.bufs.write_buf_empty())
		dout() << "Received GOODBYE_CONFIRM from peer with non-empty write buffer, possible bug?";
	frompeer.flags[dht_peer::CLEAN_SHUTDOWN] = true;
	mark_defunct(frompeer);
}




// Unspecialized process_msgtype_final is just a nop for msgtypes that don't implement it:
// specific msgtypes will implement by specializing
template<DHTMSG DFLT>
void dht::process_msgtype_final(dhtmsg dmsg, dht_peer&)
{
	dout() << "!!! Reached process_msgtype_final for unspecialized msgtype " << dht_header(dmsg.msg).get_msgtype();
}

// Unspecialized reroute_msg just runs through route_msg again for routed msg (presumably following routing change) and drops direct msg
template<DHTMSG DFLT>
void dht::reroute_msg(dhtmsg dmsg, dht_peer& frompeer)
{
	if(dht_header(dmsg.msg).get_msgtype() < DHTMSG_DIRECT_START) {
		route_msg(dmsg, frompeer);
	} else {
		dout() << "reroute_msg dropped unspecialized direct msg type " << dht_header(dmsg.msg).get_msgtype();
	}
}


/* This is a recursive templated class that creates a nested instance of itself for each message type.
 *	The dht constructor then instantiates it and calls the init_fpointers(), which recursively initialize the dht_fptr arrays.
 */
template<uint16_t I>
struct dht::init_dhtmsg_pointers
{
	init_dhtmsg_pointers<I - 1> i;
	void init_fpointers(dht_fptr fptr[], size_t start) {
		fptr[I - start - 1].process = &dht::process_msgtype<DHTMSG(I-1)>;
		fptr[I - start - 1].process_final = &dht::process_msgtype_final<DHTMSG(I-1)>;
		fptr[I - start - 1].validate = &dhtmsg_type<DHTMSG(I-1)>::validate;
		i.init_fpointers(fptr, start);
	}
};
// specialized templates to stop the recursion
template<> 
struct dht::init_dhtmsg_pointers<dht::DHTMSG_ROUTED_START>
{
	void init_fpointers(dht_fptr [], size_t) {}
};
template<>
struct dht::init_dhtmsg_pointers<dht::DHTMSG_DIRECT_START>
{
	void init_fpointers(dht_fptr [], size_t) {}
};

dht::dht(dtls_dispatch_thread* dd, worker_thread* io)
	: io_thread(io), dispatch_thread(dd), running(true), connections(std::bind(&dht::cleanup_connection, this, std::placeholders::_1), DHT_NONPEER::NUM_NONPEER_FDS, "DHT")
{
	init_dhtmsg_pointers<static_cast<uint16_t>(DHTMSG::MAX_ROUTED_DHT_MESSAGE)> routed;
	routed.init_fpointers(process_routed_msgtype, DHTMSG_ROUTED_START);
	init_dhtmsg_pointers<static_cast<uint16_t>(DHTMSG::MAX_DIRECT_DHT_MESSAGE)> direct;
	direct.init_fpointers(process_direct_msgtype, DHTMSG_DIRECT_START);
	
	nbo_virtual_interface_addr = dispatch_thread->virtual_interface_ipaddr();
	
	sockaddrunion listen_sockaddr;
	listen_sockaddr.sa.sin_family = AF_INET;
	listen_sockaddr.sa.sin_addr.s_addr = nbo_virtual_interface_addr;
	listen_sockaddr.sa.sin_port = htons(snow::conf[snow::DHT_PORT]);
	dout() << "DHT listening on " << ss_ipaddr(listen_sockaddr.sa.sin_addr.s_addr) << " port " << ntohs(listen_sockaddr.sa.sin_port);
	try {
		dht_incoming = csocket(AF_INET, SOCK_STREAM);
		dht_incoming.bind(listen_sockaddr);
		dht_incoming.listen();
		dht_incoming.setopt_nonblock();
		dhtport = listen_sockaddr.sa.sin_port;
	} catch(const check_err_exception &e) {
		eout() << "DHT failed to set up listen socket:" << e;
		if(sock_err::get_last() == sock_err::eaddrinuse) {
			try {
				listen_sockaddr.sa.sin_port = 0;
				dht_incoming.bind(listen_sockaddr);
				dht_incoming.listen();
				dht_incoming.setopt_nonblock();
				dht_incoming.getsockname(listen_sockaddr);
				dhtport = listen_sockaddr.sa.sin_port;
				iout() << "DHT could not bind configured port, will use OS-assigned port " << ntohs(dhtport);
			} catch(const check_err_exception &ee) {
				eout() << "DHT failed even with OS-assigned port: " << ee;
				dht_incoming = csocket();
				dhtport = 0;
			}
		} else {
			dht_incoming = csocket();
			dhtport = 0;
		}
	}
	dispatch_thread->set_dhtport(dhtport);

	for(size_t i=0; i < DHT_NONPEER::NUM_NONPEER_FDS; ++i)
	{
		connections.emplace_back(INVALID_SOCKET, pvevent::read, nullptr, std::make_shared<dht_peer>(dht_peer(hashkey(), std::vector<ip_info>(), 0, 0, 0, false)));
	}
	connections.set_fd(DHT_NONPEER::DHTLISTEN_FD, dht_incoming.fd());
	connections.set_event_function(DHT_NONPEER::DHTLISTEN_FD, std::bind(&dht::listen_socket_event, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
	connections[DHT_NONPEER::DHTLISTEN_FD]->index = DHT_NONPEER::DHTLISTEN_FD;
	connections.set_fd(DHT_NONPEER::INTERTHREAD_FD, interthread_msg_queue.getSD());
	connections.set_event_function(DHT_NONPEER::INTERTHREAD_FD, std::bind(&function_tqueue::pv_execute, &interthread_msg_queue, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
	connections[DHT_NONPEER::INTERTHREAD_FD]->index = DHT_NONPEER::INTERTHREAD_FD;
	peer_socket_event_function = std::bind(&dht::peer_socket_event, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
	
	// now check to make sure we didn't  miss any
	for(size_t i=0; i < DHT_NONPEER::NUM_NONPEER_FDS; ++i)
	{
		if(connections.get_fd(i) == INVALID_SOCKET) {
			eout() << "!!! Failed to initialize DHT non-peer file descriptor " << i;
			std::abort();
		}
	}
}

uint64_t dht::add_trackback_route(uint64_t route_id, dht_peer& peer)
{
	uint64_t local_id = route_id;
	while(trackback_route_map.count(local_id) > 0 || local_id == 0)
		local_id = random_distribution64(random_engine);
	trackback_route_map[local_id] = trackback_route(peer.fingerprint, route_id);
	// delete trackback route after a bit
	timers.add(60, [this, local_id]() {
		trackback_route_map.erase(local_id);
	});
	return local_id;
}

template<class DHTMSG_T>
void dht::trackback_forward(DHTMSG_T& msg, dht_peer& frompeer, bool route_message)
{
	// crazy "template" thing is to do what you might expect to get from "msg.get<DHTMSG_T::FIELD::ROUTE_ID>().get_hbo();"
	uint64_t route_id = msg.template get<DHTMSG_T::FIELD::ROUTE_ID>().get_hbo();
	uint64_t local_id = add_trackback_route(route_id, frompeer);
	if(local_id != route_id) 
		msg.template set<DHTMSG_T::FIELD::ROUTE_ID>(trackback_route_id(local_id));
	if(route_message)
		route_msg(msg.get_msg(), frompeer); // forward to destination
}

template<class DHTMSG_T>
bool dht::trackback_follow(DHTMSG_T& msg, dht_peer& frompeer)
{
	// crazy "template" thing is to do what you might expect to get from "msg.get<DHTMSG_T::FIELD::ROUTE_ID>().get_hbo();"
	uint64_t route_id = msg.template get<DHTMSG_T::FIELD::ROUTE_ID>().get_hbo();
	auto it = trackback_route_map.find(route_id);
	if(it != trackback_route_map.end()) {
		// use peer_map, sometimes trackback goes through peers not enabled for normal routing
		auto peer_it = peer_map.find(it->second.peer);
		if(peer_it != peer_map.end() && peer_it->second.dht_connected) {
			if(it->second.route_id != route_id)
				msg.template set<DHTMSG_T::FIELD::ROUTE_ID>(trackback_route_id(it->second.route_id));
			route_msg(msg.get_msg(), frompeer, *peer_it->second.peer);
			return true;
		}
	}
	return false;	
}

void dht::forward_payload(const dht_forward_payload& payload, dht_peer& frompeer)
{
	dhtmsg fwd_msg = payload.get_dhtmsg();
	// forwarded message has not been validated, make sure it has at least a route header and is not a direct message type
	if(dht_route_header::validate_route_header(fwd_msg, payload.size())
			&& dht_header::get_msgtype(fwd_msg) < DHTMSG_DIRECT_START
			&& dht_header::get_msgtype(fwd_msg) != static_cast<uint16_t>(DHTMSG::FORWARD)) // no nesting forwards
	{
		process_msg(fwd_msg, frompeer);
	} else {
		wout() << "Got invalid forwarded DHT message, dropped";
	}
}

void dht::connection_retry(const hashkey& target, std::shared_ptr<dht_connect_retry>& retry)
{
	interthread_msg_queue.put(std::bind(&dht::handle_retry, this, target, retry));
}
void dht::handle_retry(const hashkey& target, std::shared_ptr<dht_connect_retry>& retry)
{
	in_port_t holepunch = htons(snow::conf[snow::DTLS_OUTGOING_PORT]);
	bool request_hp_addrs = false, no_retry = retry->flags[retry->NO_RETRY], follow_trackback = false;
	switch(retry->retry_type) {
	case dht_connect_retry::NORMAL_ROUTE:
		dout() << "DHT retry to " << target << " normal routing";
		send_connect(target, dhtconnect_opts(holepunch));
		break;
	case dht_connect_retry::FIRST_HOP: {
		dout() << "DHT retry to " << target << " with first hop " << retry->first_hop;
		auto hop_it = peer_map.find(retry->first_hop);
		if(hop_it != peer_map.end() && hop_it->second.dht_connected)
			send_connect(target, dhtconnect_opts(holepunch, request_hp_addrs, no_retry), follow_trackback, hop_it->second.peer->index);
		else	// next hop was set but has disconnected, just route normally
			send_connect(target, dhtconnect_opts(holepunch, request_hp_addrs, no_retry), follow_trackback, LOCAL_INDEX);
		break;
	}
	case dht_connect_retry::TRACKBACK:
		dout() << "DHT retry to " << target << " using trackback routing";
		follow_trackback = true;
		send_connect(target, dhtconnect_opts(holepunch, request_hp_addrs, no_retry), follow_trackback, retry->trackback_route_id);
		break;
	case dht_connect_retry::BOOTSTRAP:
		connect_known_peer();
		known_peers.mark_fail(target, io_thread);
		break;		
	}
}

void dht::newtls(std::shared_ptr<dht_peer> dntls, bool is_client)
{
	dout() << "dht newtls " << dntls->fingerprint << " at NAT IP " << ss_ipaddr(dntls->nat_ipaddr);
	known_peers.add_peer(dntls->fingerprint, dntls->dtls_srcport, dntls->native_addrs, io_thread, is_client);
	auto it = connected_peers.find(dntls->nat_ipaddr);
	if(it == connected_peers.end()) {
		peer_map[dntls->fingerprint] = map_peer(dntls, false);
		if(dntls->flags[dht_peer::PRIMARY]) {
			dout() << "DHT primary making outgoing DHT connection for newtls";
			dht_connect(std::move(dntls));
		} else {
			// try outgoing if no connection arrives after timeout
			uint32_t nat_addr = dntls->nat_ipaddr;
			timers.add(15, [this, nat_addr]() { std::bind(&dht::pending_connect_timeout, this, nat_addr); });
			// store dht_peer until other side makes DHT connection or for use by pending_connect_timeout
			dht_pending_map.insert(std::make_pair(nat_addr, std::move(dntls)));
		}
	} else {
		dout() << "dht::newtls not making new connection because NAT IP is already connected to DHT";
		peer_map[it->second->fingerprint] = map_peer(it->second, false);
		// if existing connection was marked NO_RECONNECT because of DTLS disconnect, clear flag so that reconnect occurs on cleanup
		it->second->flags[dht_peer::NO_RECONNECT] = false;
		it->second->dhtport = dntls->dhtport; // for reconnect, in case this has changed
		it->second->dtls_srcport = dntls->dtls_srcport;
	}
}
/*
DHT connections:
	Primary (i.e. snow handshake primary) makes first outgoing connection attempt
	Secondary adds dht_peer to dht_pending_map and sets timer
		If incoming connection is received then dht_peer is retreived from dht_pending_map and all is well
		After timeout, pending_connect_timeout is executed, and if peer is not connected and dht_peer still in dht_pending_map, it makes outgoing connection
	In either case, if connection fails without clean shutdown (i.e. DHTMSG::GOODBYE), cleanup puts dht_peer back in dht_pending_map and schedules a reconnect
		pending_connect_timeout then executes the reconnect after a timeout, which increases exponentially up to ~3600s
		reconnect attempts continue until successful or until DHT is notified that underlying DTLS connection is closed
	When underlying DTLS connection is closed, DHT disconnects existing connection, marks it clean shutdown to prevent reconnect, and removes any associated entry in dht_pending_map
	If a DHT connection request comes in from dispatch while an existing DHT connection exists, the cause is expected to be that DTLS disconnected and then reconnected
		In that case, if no DHT connection exists, a new one is created
		If a DHT connection does exist then the clean shutdown flag is cleared so that when it gets cleaned up a reconnect will occur
*/

void dht::schedule_reconnect(std::shared_ptr<dht_peer> &ptr)
{
	uint32_t natip = ptr->nat_ipaddr;
	if(dht_pending_map.count(natip) == 0) {
		size_t reconnect_delay = ptr->reconnect_delay;
		// keep doubling retries until they get to twice DTLS disconnect period, so DTLS will not stay active just b/c of failing DHT attempts
		ptr->reconnect_delay = reconnect_delay ? (reconnect_delay < 2*snow::conf[snow::DTLS_IDLE_TIMEOUT_SECS]) ? (reconnect_delay << 1) : reconnect_delay: 1;
		dht_pending_map.insert(std::make_pair(natip, ptr));
		timers.add(reconnect_delay, std::bind(&dht::pending_connect_timeout, this, natip));
	}
}
		
void dht::pending_connect_timeout(uint32_t nat_addr)
{
	if(connected_peers.count(nat_addr) == 0) {
		// incoming connection failed / never happened, try outgoing connection
		dout() << "pending_connect_timeout or hard disconnect to " << ss_ipaddr(nat_addr) << ", making outgoing connection";
		auto it = dht_pending_map.find(nat_addr);
		if(it != dht_pending_map.end()) {
			// order is important here because dht_connect re-adds to dht_pending_map on fail
			std::shared_ptr<dht_peer> p(it->second.lock());
			dht_pending_map.erase(it);
			if(p != nullptr)
				dht_connect(std::move(p));
		} else {
			dout() << "Oops, could not make outgoing connection because dht_pending_map doesn't have the dht_peer";
		}
	} else {
		dht_pending_map.erase(nat_addr); // delete entry because peer is now already connected
	}
}

void dht::dtls_disconnect(const hashkey& fingerprint, uint32_t nbo_nat_addr)
{
	// DTLS peer has disconnected, disconnect DHT peer and don't bother trying to reconnect
	dout() << "DHT got DTLS disconnect of " << fingerprint << " / " << ss_ipaddr(nbo_nat_addr);
	peer_map.erase(fingerprint);
	auto it = connected_peers.find(nbo_nat_addr);
	if(it != connected_peers.end()) {
		it->second->flags[dht_peer::NO_RECONNECT] = true;
		mark_defunct(*it->second);
	}
	// drop pending connection retries too
	dht_pending_map.erase(nbo_nat_addr);
}


void dht::dht_connect(std::shared_ptr<dht_peer> dntls)
{
	if(!running)
		return;
	dntls->connection_timestamp = std::chrono::steady_clock::now();
	auto it = connected_peers.find(dntls->nat_ipaddr);
	if(it == connected_peers.end()) {
		// make new DHT connection and add to list
		try {
			csocket sock(AF_INET, SOCK_STREAM);
			sockaddrunion remote_addr;
			remote_addr.sa.sin_addr.s_addr = dntls->nat_ipaddr;
			remote_addr.sa.sin_family = AF_INET;
			remote_addr.sa.sin_port = dntls->dhtport;
			sock.setopt_nonblock();
			sock.connect(remote_addr);
			sock.setopt_keepalive();
			dout() << "dht_connect connected " << dntls->fingerprint << " at " << ss_ipaddr(dntls->nat_ipaddr) << " idx " << connections.size();
			add_peer(std::move(dntls), sock.release_fd());
		} catch(const check_err_exception &e) {
			eout() << "Creating socket for new DHT connection: " << e;
			schedule_reconnect(dntls);
		}
	}
}

void dht::process_dht_incoming()
{
	if(!running)
		return;
	for(dht_newconn newpeer = get_client(); newpeer.sock.fd() != INVALID_SOCKET; newpeer = get_client())
	{
		auto it = dht_pending_map.find(newpeer.nat_addr);
		if(it == dht_pending_map.end() || it->second.expired()) {
			// tuntap adds dht_newtls to queue before putting peer online,
			// but still possible race condition if it's added to msg queue after we check it but before we get here, so check again on fail
			interthread_msg_queue.execute();
			it = dht_pending_map.find(newpeer.nat_addr);
			if(it == dht_pending_map.end() || it->second.expired()) {
				dout() << "Received DHT connection from unknown peer (" << ss_ipaddr(newpeer.nat_addr) << ")";
				// this can still happen following DTLS disconnect/reconnect if peer tries to reconnect after DHT gets DTLS disconnect msg but before reconnect msg
				// just ignore, peer will retry in a few seconds and then we'll have the reconnect msg and know who the peer is again
				continue;
			}
		}
		std::shared_ptr<dht_peer> peer = it->second.lock();
		if(!peer) continue;
		auto peer_it = connected_peers.find(newpeer.nat_addr);
		if(peer_it == connected_peers.end()) {
			dout() << "got incoming DHT connect for " << peer->fingerprint << " at " << ss_ipaddr(peer->nat_ipaddr) << " / " << ss_ipaddr(newpeer.nat_addr) << " idx " << connections.size();
			peer->nat_ipaddr = newpeer.nat_addr; // NOP?
			add_peer(std::move(peer), newpeer.sock.release_fd());
		} else {
			dout() << "disconnected incoming DHT connection because NAT IP (" << ss_ipaddr(newpeer.nat_addr) << ") was already connected";
		}
		dht_pending_map.erase(it);
	}
}

void dht::add_peer(std::shared_ptr<dht_peer> &&ptr, csocket::sock_t sd)
{
	try {
		ptr->index = connections.size();
		connections.emplace_back(sd, pvevent::read, peer_socket_event_function, std::move(ptr));
		connected_peers[connections.back()->nat_ipaddr] = connections.back();
		peer_map[connections.back()->fingerprint].dht_connected = true;
		send_hello(*connections.back());
	} catch(const check_err_exception& e) {
		wout() << "Failed to add DHT peer: " << e;
	}
}

void dht::send_hello(dht_peer& peer)
{
	unix_time time(get_time());
	dht_version version(DHT_VERSION);
	uint64_t nonce; // CHECK_ROUTE nonce
	do {
		nonce = random_distribution64(random_engine);
		// check for collision (rare)
	} while(nonce_map.count(nonce) > 0 || trackback_route_map.count(nonce) > 0 || nonce == 0);
	nonce_map[nonce] = connections[peer.index];
	trackback_route_map[nonce] = trackback_route(dispatch_thread->get_hashkey(), nonce);
	// if CHECK_ROUTE hasn't removed nonce from nonce_map after timeout, try to do something about it
	timers.add(30, std::bind(&dht::check_route_timeout, this, nonce, false, false));
	nonce64 dht_nonce(nonce);
	dhtmsg_type<DHTMSG::HELLO> hello_msg(time, dht_nonce, version);
	write_peer(hello_msg.get_msg(), peer, *connections[LOCAL_INDEX]);
}
	
void dht::check_route_timeout(uint64_t nonce, bool sent_connect, bool sent_retry)
{
	auto it = nonce_map.find(nonce);
	if(it != nonce_map.end()) {
		if(auto ptr = it->second.lock()) {
			if(!sent_connect) {
				// haven't got CHECK_ROUTE after timeout, send CONNECT to "self" through peer that check failed through
				// that way the node the CHECK_ROUTE ended up at will connect to this node and fix the routing failure
				// (presumably the CONNECT it should have sent us either didn't get here or didn't work)
				send_connect(dht_hash(dispatch_thread->get_hashkey()), dhtconnect_opts(htons(snow::conf[snow::DTLS_OUTGOING_PORT]), true, false), false, ptr->index);
				timers.add(30, std::bind(&dht::check_route_timeout, this, nonce, true, false));
			} else if(!sent_retry) {
				// the CONNECT has had a chance to do its thing, try sending another CHECK_ROUTE
				dhtmsg_type<DHTMSG::CHECK_ROUTE> check(dht_hash(dispatch_thread->get_hashkey()), nonce64(nonce), trackback_route_id(nonce));
				write_peer(check.get_msg(), *ptr, *connections[LOCAL_INDEX]);
				timers.add(30, std::bind(&dht::check_route_timeout, this, nonce, true, true));
			} else {
				// if the second CHECK_ROUTE hasn't arrived by now, complain about it and then wait a few minutes and start over
				wout() << "CHECK_ROUTE failed to peer " << ptr->fingerprint << ", mitigation was unsuccessful, DHT routing may be unreliable";
				timers.add(300, std::bind(&dht::check_route_timeout, this, nonce, false, false));
			}
		} else {
			nonce_map.erase(it);
		}
	}
}

void dht::connect_known_peer()
{
	try {
		node_hkinfo info = known_peers.get_next_bootstrap();
		while(peer_map.count(info.fingerprint) > 0)
			info = known_peers.get_next_bootstrap(); // no use in connecting to already-connected peers
		bool remote_request = false, no_retry = false;
		dispatch_thread->add_peer((dht_connect_info(std::move(info.fingerprint), std::move(info.addrs), remote_request, std::make_shared<dht_connect_retry>(dht_connect_retry::BOOTSTRAP, info.dtls_source_port, no_retry))));
	} catch(const e_not_found &) {
		// FAIL: zero known peers whatsoever, DHT will not function unless remote DHT peer makes incoming connection
		eout() << "No known peers, snow DHT cannot bootstrap";
	} catch(const e_slow_down &) {
		dout() << "tried to connect_known_peer too soon after exhausting known peers list";
	}
}

void dht::do_initiate_connection(hashkey lookup)
{
	// request to look up peer and initiate DTLS connection
		// sent by both nameserv following user request and by tuntap after disconnections if packet arrives for disconnected peer during grace period
		// may be called many times during period between first request and actual DTLS connection establishment
	const node_info* ni = known_peers.get_node_info(lookup);
	if(ni != nullptr) {
		// (maybe shouldn't do this every time for repeated calls, but peer_init can handle the duplicates pretty well)
		std::vector<ip_info> addrs;
		for(auto& addr : ni->addrs)
			addrs.emplace_back(addr.first);
		dout() << "DHT asked to initiate connection for known peer " << lookup << ", trying cached info";
		// this is probably faster and leaks less information to DHT than going straight to DHT CONNECT
		// but if node has very low recency then go to DHT concurrent with outgoing connection instead of as a retry
		bool remote_request = false, no_retry = false;
		if(ni->recency * 2 > node_info::DEFAULT_PEER_RECENCY) {
			dispatch_thread->add_peer(dht_connect_info(std::move(lookup), std::move(addrs), remote_request, std::make_shared<dht_connect_retry>(dht_connect_retry::NORMAL_ROUTE, ni->dtls_source_port, no_retry)));
		} else {
			send_connect(lookup);
			dispatch_thread->add_peer(dht_connect_info(std::move(lookup), std::move(addrs), remote_request, nullptr));
		}
	} else {
		dout() << "DHT asked to connect to unknown peer " << lookup << ", sending DHT CONNECT";
		// (send_connect should do the right thing re: duplicate requests)
		send_connect(lookup);
	}
}

void dht::send_connect(const dht_hash& dest, const dhtconnect_opts& opts, bool follow_trackback, uint64_t route_id)
{
	hashkey dest_hk = dest.get_hashkey();
	if(!follow_trackback && route_id == LOCAL_INDEX && dht_connect_pending.count(dest_hk) > 0) {
		dout() << "send_connect: already a pending connect to " << dest_hk << ", not sending another default one";
		return;
	}
	auto it = peer_map.find(dest_hk);
	if(it != peer_map.end() && connected_peers.count(it->second.peer->nat_ipaddr) == 0) {
		// peer is DTLS connected but not DHT connected, try doing DHT connect in case CONNECT is being sent for DHT congestion control
		dht_connect(it->second.peer);
		// TODO: does it make any sense to still send the CONNECT in this case? We're already DTLS connected (but maybe DTLS connection just died and DHT doesn't know yet?)
	}

	// broadcast_retry is only false when calling send_connect as part of a broadcast (to avoid infinite recursion), in any other connect to a real hashkey, add to dht_connect_pending
	if((opts.flags & dhtconnect_opts::BROADCAST_RETRY) && dest_hk.algo() != md_hash::DATA) {
		dht_connect_pending.insert(std::pair<hashkey,dhtconnect_opts>(dest_hk, opts));
		timers.add(5, [this,dest_hk]() {
			send_broadcast_connect(dest_hk);
			dht_connect_pending.erase(dest_hk);
		});
	}
	if(local_ipaddrs.size() == 0) {
		eout() << "Tried to send DHT CONNECT when local IP address is unknown";
		return;
	} else {
		dout out;
		out << "DHT sending CONNECT to peer " << dest_hk << " req hp addrs " << ((opts.flags & opts.REQUEST_HP_ADDRS) ? true : false) << " providing local addrs";
		for(auto& addr: local_ipaddrs)
		  out << " " << addr;
	}
	
	ip_port holepunch_port(opts.holepunch_port ? opts.holepunch_port : htons(snow::conf[snow::DTLS_OUTGOING_PORT]));
	dht_ip_addrs dht_addrs(local_ipaddrs);
	dht_flags flags;
	if(opts.flags & dhtconnect_opts::REQUEST_HP_ADDRS)
		flags.setflag(CONNECT_FLAGS::REQUEST_HP_ADDRS);
	if(opts.flags & dhtconnect_opts::NO_RETRY)
		flags.setflag(CONNECT_FLAGS::NO_RETRY);
	if(follow_trackback) {
		flags.setflag(CONNECT_FLAGS::TRACKBACK);
		dhtmsg_type<DHTMSG::CONNECT> connect_msg(dest, trackback_route_id(route_id), flags, dht_hash(dispatch_thread->get_hashkey()), 
			dht_addrs, holepunch_port);
		process_msg(connect_msg.get_msg(), *connections[LOCAL_INDEX]);
	} else {
		uint64_t r_id = add_trackback_route(0, *connections[LOCAL_INDEX]);
		dhtmsg_type<DHTMSG::CONNECT> connect_msg(dest, trackback_route_id(r_id), flags, dht_hash(dispatch_thread->get_hashkey()),
			dht_addrs, holepunch_port);
		// route_id passed to send_connect is next hop index when not following a trackback
		if(route_id == LOCAL_INDEX)
			route_msg(connect_msg.get_msg(), *connections[LOCAL_INDEX]);
		else
			write_peer(connect_msg.get_msg(), *connections[route_id], *connections[LOCAL_INDEX]); 
	}
}

void dht::send_broadcast_connect(const hashkey& dest_hk)
{
	auto pending_it = dht_connect_pending.find(dest_hk);
	auto peer_it = peer_map.find(dest_hk);
	if(peer_it == peer_map.end() && (pending_it->second.flags & dhtconnect_opts::BROADCAST_RETRY)) {
		// original connect failed (e.g. timeout or MISMATCH_DETECTED), try broadcasting connect
		pending_it->second.flags ^= dhtconnect_opts::BROADCAST_RETRY; // set to false to prevent recursion
		dht_hash dest(dest_hk);
		for(std::pair< const hashkey, map_peer > &peer : peer_map)
			if(peer.second.peer->index != LOCAL_INDEX && peer.second.dht_connected)
				send_connect(dest, pending_it->second, false, peer.second.peer->index);
	}
}

void dht::do_shutdown_thread()
{
	running = false;
	// disconnect non-antecedent peers first so that routing doesn't break until non-antecedent peers have disconnected
	dout() << "dht::do_shutdown_thread initiating disconnect of all non-antecedent peers";
	for(size_t i = DHT_NONPEER::NUM_NONPEER_FDS; i < connections.size(); ++i)
		if(connections[i] != route_map.antecedent())
			initiate_disconnect(*connections[i]);
	// if only antecedent is connected then disconnect it now too
	if(route_map.size() == 2) {
		dout() << "dht::do_shutdown_thread with exactly one route_map peer, initiating disconnect of antecedent";
		initiate_disconnect(*route_map.antecedent());
	}
}

void dht::initiate_disconnect(dht_peer& peer)
{
	if(peer.index == LOCAL_INDEX) {
		dout() << "BUG: called initiate_disconnect on local index!";
		return;
	}
	dout() << "sending GOODBYE_REQUEST to " << peer.fingerprint;
	remove_routing(peer);
	write_peer(dhtmsg_type<DHTMSG::GOODBYE_REQUEST>().get_msg(), peer, *connections[LOCAL_INDEX]);
	// if peer is not clean disconnected after timeout, disconnect anyway
	std::weak_ptr<dht_peer> wptr = connections[peer.index];
	timers.add(30, [this, wptr]() {
		if(auto ptr = wptr.lock())
			mark_defunct(*ptr);
	});
}

void dht::dht_startup()
{
	// set sensible values for LOCAL_INDEX
	connections[LOCAL_INDEX] = std::make_shared<dht_peer>(dispatch_thread->get_hashkey(), std::vector<ip_info>(), 0, 0, nbo_virtual_interface_addr, false);
	connections[LOCAL_INDEX]->index = LOCAL_INDEX;
	route_map = dht_route_map(connections[LOCAL_INDEX]);
	peer_map[dispatch_thread->get_hashkey()] = map_peer(connections[LOCAL_INDEX], true);
	connected_peers[nbo_virtual_interface_addr] = connections[LOCAL_INDEX];
	// TODO: start any other timers that may need starting
	
	// on startup the DHT needs to connect to some known peers to bootstrap
	for(size_t c=0; c < snow::conf[snow::DHT_BOOTSTRAP_TARGET]; ++c)
		connect_known_peer();
	timers.add(30, std::bind(&dht::check_dht_peer_count, this));
}

void dht::check_dht_peer_count()
{
	if(connections.size() == DHT_NONPEER::NUM_NONPEER_FDS)
		wout() << "No DHT peers connected, DHT is currently offline. Check your internet connection or firewall or update " << snow::conf[snow::KNOWN_PEERS_FILE];
	// if # DHT connections is below bootstrap threshold, connect_known_peer() a few times
	for(size_t i = connections.size() - DHT_NONPEER::NUM_NONPEER_FDS; i < snow::conf[snow::DHT_BOOTSTRAP_TARGET]; ++i) 
		connect_known_peer();
	// check that existing peers are appropriately spaced to get ~log(n) lookups
	uint64_t nbo_val=0, hbo_val=0, bit = 1UL << (sizeof(nbo_val)*8 - 1);
	const hashkey& hk = dispatch_thread->get_hashkey();
	memcpy(&nbo_val, hk.get_raw(), std::min<size_t>(hk.size(), sizeof(nbo_val)));
	hbo_val = be64toh(nbo_val) + bit;
	nbo_val = htobe64(hbo_val);
	hashkey prev(&nbo_val, md_hash::HASHTYPE::DATA, sizeof(nbo_val));
	dht_peer* prev_peer = &route_map.lower_bound(prev);
	for(size_t i = 0; bit != 0 && prev_peer->index != LOCAL_INDEX; ++i) {
		bit >>= 1;
		hbo_val += bit;
		nbo_val = htobe64(hbo_val);
		hashkey next(&nbo_val, md_hash::HASHTYPE::DATA, sizeof(nbo_val));
		dht_peer* next_peer = &route_map.lower_bound(next);
		bool request_hp_addrs = true; // we don't have the peer's ipaddrs so ask for them in order to be able to do holepunch
		if(prev_peer == next_peer)
			send_connect(dht_hash(prev), dhtconnect_opts(htons(snow::conf[snow::DTLS_OUTGOING_PORT]), request_hp_addrs));
		prev_peer = next_peer;
		prev = std::move(next);
	}
	
	// check that there are not too many DHT peers
	size_t num_peers = connections.size() - DHT_NONPEER::NUM_NONPEER_FDS;
	if(num_peers > snow::conf[snow::DHT_MAX_PEERS]) {
		// don't want to disconnect newest peers (just connected e.g. for congestion control) or oldest peers (most stable), so disconnect middle peers
		// but never disconnect direct antecedent or successor
		std::vector<dht_connection_timestamp> timestamps;
		for(size_t i = DHT_NONPEER::NUM_NONPEER_FDS; i < connections.size(); ++i)
			timestamps.push_back(*connections[i]);
		std::sort(timestamps.begin(), timestamps.end());
		size_t low = (num_peers / 2), high = low, next = low, num_disconnects = num_peers - snow::conf[snow::DHT_MAX_PEERS];
		while(num_disconnects > 0) {
			if(next < timestamps.size() && timestamps[next].peer != route_map.antecedent().get() && timestamps[next].peer != route_map.successor().get()) {
				initiate_disconnect(*timestamps[next].peer);
				--num_disconnects;
			}
			if(next == low || low > high)
				next = ++high;
			else
				next = --low;
		}
	}
	// reschedule check
	timers.add(300, std::bind(&dht::check_dht_peer_count, this));
}


void dht::operator()()
{
	dht_startup();
	
	while(running || connections.size() > DHT_NONPEER::NUM_NONPEER_FDS)
	{
		dout() << "Iterating DHT main loop";
		int next_timer = timers.exec();
		connections.event_exec_wait(next_timer);
	}
}

void dht::listen_socket_event(size_t, pvevent event, sock_err err)
{
	// get new connections from DHT listen and add to list (and send HELLO)
	if(event == pvevent::read) {
		process_dht_incoming();
	} else {
		eout() << "poll() error on new DHT listen file descriptor: " << err;
	}
}

void dht::peer_socket_event(size_t i, pvevent event, sock_err err)
{
	if(event & pvevent::read) {
		dout() << "peer_socket_event read idx " << i;
		read_peer(*connections[i]);
	}
	if(event & pvevent::write) {
		dout() << "peer_socket_event write idx " << i;
		write_peer(*connections[i]);
	}
	if(event & pvevent::error) {
		// TODO: should break this out more: any different treatment for specific errors? (but don't use switch because of combinatorial explosion)
		dout() << "dht event loop poll() error event on peer connection: " << err;
		mark_defunct(*connections[i]);
	}
}

void dht::remove_routing(dht_peer& peer)
{
	if(peer.index == LOCAL_INDEX) {
		eout() << "BUG: remove_routing called for local node";
		return;
	}
	if(&peer == route_map.successor().get())
		peer.flags[dht_peer::DISCONNECT_CHECK_ROUTE] = true;
	route_map.remove(connections[peer.index]);

	auto peer_it = peer_map.find(peer.fingerprint);
	if(peer_it != peer_map.end() && peer_it->second.peer.get() == &peer)
		peer_it->second.dht_connected = false;
}
void dht_route_map::insert(std::shared_ptr<dht_peer>& ptr)
{
	auto insert_pair = route_map.insert(std::make_pair(ptr->fingerprint, ptr));
	if(!insert_pair.second) {
		dout() << "BUG: tried to insert dht_route_map entry for fingerprint already present";
		return;
	}
	// update antecedent/successor if necessary
	auto prev = (insert_pair.first == route_map.begin()) ? --route_map.end() : std::prev(insert_pair.first);
	auto next = std::next(insert_pair.first);
	if(next == route_map.end())
		next = route_map.begin();
	if(antecedent_ptr == prev->second)
		antecedent_ptr = ptr;
	if(successor_ptr == next->second)
		successor_ptr = ptr;
}
void dht_route_map::remove(std::shared_ptr<dht_peer>& ptr)
{
	auto route_it = route_map.find(ptr->fingerprint);
	if(route_it != route_map.end() && route_it->second == ptr) {
		if(ptr == successor_ptr) {
			auto next_it = std::next(route_it);
			successor_ptr = ((next_it == route_map.end()) ? route_map.begin() : next_it)->second;
			dout() << "Set DHT successor to " << successor_ptr->fingerprint << " (was " << ptr->fingerprint << ")";
		}
		if(ptr == antecedent_ptr) {
			auto prev_it = (route_it == route_map.begin()) ? --route_map.end() : std::prev(route_it);
			antecedent_ptr = prev_it->second;
			dout() << "Set DHT antecedent to " << antecedent_ptr->fingerprint << " (was " << ptr->fingerprint << ")";
		}
		route_map.erase(route_it);
	}
}


void dht::mark_defunct(dht_peer& peer)
{
	if(peer.index == LOCAL_INDEX) {
		dout() << "mark_defunct called on local index!";
	}
	if(peer.index >= connections.size() || peer.index < DHT_NONPEER::NUM_NONPEER_FDS) {
		eout() << "BUG: tried to remove DHT peer at invalid index " << peer.index;
	}
	// remove connection from route map immediately, then schedule for removal from 'connections' at next main loop iteration
	remove_routing(peer);
	connections.mark_defunct(peer.index);
}

void dht::cleanup_connection(size_t remove_index)
{
	dout() << "Disconnecting DHT peer with index " << remove_index;
	if(!running && connections.size() == DHT_NONPEER::NUM_NONPEER_FDS + 2/*(antecedent + disconnecting peer)*/) {
		dout() << "Disconnected last non-antecedent peer on shutdown, initiating disconnect on antecedent";
		initiate_disconnect(*route_map.antecedent());
	}

	dht_peer* remove_peer = connections[remove_index].get();
	// connections.back() is about to have its index changed to remove_index, some things need to be updated
	connections.back()->index = remove_index;
	
	auto it = connected_peers.find(remove_peer->nat_ipaddr);
	if(it != connected_peers.end() && it->second == connections[remove_index])
		connected_peers.erase(it);
	
	// (remove_peer is already removed from route_map and dht_connected is set to false in peer_map by mark_defunct()/remote_routing())

	// TODO: is there anything we want to or can do with data in a write buf on hard disconnect?
		// can't reroute it w/o knowing where message boundaries are, but we don't currently track that
	
	if(remove_peer->flags[dht_peer::DISCONNECT_CHECK_ROUTE] && route_map.successor()->index != LOCAL_INDEX) {
		dhtmsg_type<DHTMSG::CHECK_ROUTE> check(dht_hash(connections[LOCAL_INDEX]->fingerprint),	nonce64(0UL), trackback_route_id(0UL));
		route_msg(check.get_msg(), *connections[LOCAL_INDEX], *route_map.successor());
	}
	
	auto peer_it = peer_map.find(remove_peer->fingerprint);
	if(peer_it != peer_map.end() && peer_it->second.peer->index == remove_index) {
		remove_peer->index = SIZE_MAX;
		peer_it->second.peer = std::make_shared<dht_peer>(std::move(*remove_peer));
		dht_peer* peer = peer_it->second.peer.get();
		if(!peer->flags[dht_peer::CLEAN_SHUTDOWN] && !peer->flags[dht_peer::NO_RECONNECT]) {
			dout() << "DHT hard disconnect, scheduling reconnect";
			peer->bufs = dht_peer_bufs(); // clear any remaining buffers
			peer->flags = std::bitset<dht_peer::DHT_PEER_FLAGS::NUM_FLAGS>();
			schedule_reconnect(peer_it->second.peer);
		}
	} else {
		dout() << "dht_peer in cleanup_connection was not found in peer_map (DTLS hard disconnect?)";
		remove_peer->index = SIZE_MAX;
	}
	if(connections[remove_index].unique() == false)
		dout() << "BUG: dht_peer was not unique on cleanup, use count: " << connections[remove_index].use_count();
	if(running && connections.size() - DHT_NONPEER::NUM_NONPEER_FDS < snow::conf[snow::DHT_BOOTSTRAP_TARGET])
		connect_known_peer();
}





void dht::process_msg(dhtmsg msg, dht_peer& frompeer)
{
	uint16_t msgtype = dht_header::get_msgtype(msg);
	//dout() << "process_msg<" << msgtype << ">";
	if(msgtype < DHTMSG_DIRECT_START) {
		if(msgtype < (uint16_t)DHTMSG::MAX_ROUTED_DHT_MESSAGE) {
			process_routed_msgtype[msgtype].process_msg(this, msg, frompeer);
		} else {
			wout() << "Invalid DHT message or unsupported message type " << msgtype << " (maybe check for updated software version).";
			// forward message to next hop, maybe it can make more sense of it
			// careful: we're calling route_msg() without validate(), so first check that there is at least a sane routing header on it
			if(dht_route_header::validate_route_header(msg, dht_header::get_msglen(msg)))
				route_msg(msg, frompeer);
		}
	} else {
		if(msgtype < (uint16_t)DHTMSG::MAX_DIRECT_DHT_MESSAGE) {
			process_direct_msgtype[msgtype - DHTMSG_DIRECT_START].process_msg(this, msg, frompeer);
		} else {
			wout() << "Invalid DHT message or unsupported message type (check for updated software version).";
			// (unknown direct messages are ignored)
			
			// maybe we should add a message for 'unknown message' -- tell the peer that it's sending something weird
			// then non-malicious peers who receive that can take some action
			//	e.g. reduce protocol version, stop routing routed messages to peer that doesn't understand if doing so is counterproductive, etc.
			// (or report bug, if message sent is known-understandable by all versions or by peer's version, or identified message isn't one we thought we sent)
		}
	}
}

// do not call route_msg for messages originating at this node which are to be routed to the DHT
// instead, call process_msg(), which will call process_msgtype<TYPE>, which will validate msg and in turn call route_msg as necessary
// calling route_msg directly will cause process_msgtype to never be called for the message on this node as it needs to be for some msg types
inline void dht::route_msg(dhtmsg msg, dht_peer& frompeer)
{
	route_msg(msg, frompeer, dht_route_header(msg).get_hashkey());
}
inline void dht::route_msg(dhtmsg msg, dht_peer& frompeer, const hashkey& dest)
{
	route_msg(msg, frompeer, route_map.nearest_peer(dest));
}
void dht::route_msg(dhtmsg msg, dht_peer& frompeer, dht_peer& topeer)
{
	uint16_t msgtype = dht_header::get_msgtype(msg);
	//dout() << "route_msg type " << msgtype << " from " << frompeer.fingerprint << " to " << topeer.fingerprint;
	if(topeer.index != LOCAL_INDEX) {
		write_peer(msg, topeer, frompeer);
	} else {
		// message final destination is this node
		// do destination msg processing for this message type
		dout() << "process_msg_final<" << msgtype << ">";
		if(msgtype < static_cast<uint16_t>(DHTMSG::MAX_ROUTED_DHT_MESSAGE))
			process_routed_msgtype[msgtype].process_msg_final(this, msg, frompeer);
		else
			dout() << "Received unknown routed message of type " << msgtype;
	}
}



void dht::read_peer(dht_peer& peer) 
{
	if(peer.index == LOCAL_INDEX) {
		// this can happen when peers are connected but none are in route_map and so antecedent/successor are LOCAL_INDEX
		dout() << "DHT cannot read from LOCAL_INDEX";
		return;
	}
	size_t offset = peer.bufs.read_bytes_available();
	// individual partial message can't be larger than bufsize==65536 because msg size field is 16-bit, but check anyway
	if(offset >= bufsize)
	{
		eout() << "BUG: DHT read msg buffer data larger than maximum msg size";
		return;
	}
	size_t rv = 0;
	try {
		csocket_borrow sock(connections.get_fd(peer.index));
		rv = sock.recv(buf + offset, bufsize - offset);
	} catch(const e_check_sock_err &e) {
		dout() << "Socket error reading data from DHT peer: " << e;
		mark_defunct(peer);
		return;
	}
	if(rv == 0 && sock_err::get_last() == sock_err::enotconn) {
		dout() << "DHT peer " << peer.fingerprint << " closed connection, removing";
		mark_defunct(peer);
		return;
	}
	if(offset > 0)
		peer.bufs.read_buffered_data(buf);
	size_t bytes = rv + offset;
	// process every complete message in buf
	uint8_t* msg = buf;
	// need msg to contain at least dht_header for msglen to be non-garbage
	while(bytes >= dht_header::size())
	{
		size_t msglen = dht_header::get_msglen(msg);
		if(msglen < dht_header::size()) {
			dout() << "DHT peer sent " << msglen << " byte message shorter than any legitimate DHT message, disconnecting";
			mark_defunct(peer);
			return;
		}
		if(bytes < msglen)
			break;
		process_msg(dhtmsg(msg), peer);
		bytes -= msglen;
		msg += msglen;
	}
	if(bytes != 0)
	{
		// partial message still in buffer, store it until the rest arrives
		peer.bufs.buffer_read_data(msg, bytes);
	} 
}

void dht::write_peer(dht_peer& peer)
{
	if(peer.index == LOCAL_INDEX) {
		// this can happen when peers are connected but none are in route_map and so antecedent/successor are LOCAL_INDEX
		dout() << "DHT cannot write to LOCAL_INDEX";
		return;
	}
	if(peer.bufs.write_buf_empty())
	{
		// nothing to write, stop polling for it
		connections.clear_events(peer.index, pvevent::write);
		dout() << "dht::write_peer called with nothing to send";
		return;
	}
	try {
		size_t start_bytes = peer.bufs.write_bytes_buffered();
		peer.bufs.write_buffered_data(connections.get_fd(peer.index));
		peer.bytes_sent += (start_bytes - peer.bufs.write_bytes_buffered());
		if(peer.bufs.write_buf_empty())
			connections.clear_events(peer.index, pvevent::write);
	} catch(const check_err_exception &e) {
		dout() << "Socket error sending data to DHT peer: " << e;		
		mark_defunct(peer);
	}
}

void dht::write_peer(dhtmsg dmsg, dht_peer& peer, dht_peer& frompeer) 
{
	if(peer.index == LOCAL_INDEX) {
		dout() << "write_peer to LOCAL_INDEX, dropped";
		return;
	}
	uint16_t size = dht_header::get_msglen(dmsg);
	const uint8_t* msg_buf = dmsg.msg;
	if(peer.bufs.write_buf_empty())	{
		// no existing write buffer, try to send directly
		size_t bytes =  0;
		try {
			csocket_borrow sock(connections.get_fd(peer.index));
			bytes = sock.send(msg_buf, size);
		} catch(const e_check_sock_err &e) {
			dout() << "Socket error sending data to DHT peer: " << e;		
			mark_defunct(peer);
		}
		peer.bytes_sent += bytes;
		if(bytes < size) {
			peer.bufs.buffer_write_data(msg_buf+bytes, size - bytes);
			connections.add_events(peer.index, pvevent::write);
		}
	} else {
		// existing write buffer, append to end and try to write
		if(peer.bufs.write_bytes_buffered() < 1024) {
			peer.bufs.buffer_write_data(msg_buf, size);
		} else {
			handle_excessive_write_buffer(dmsg, peer, frompeer);
		}
		write_peer(peer);
	}
}



void dht::handle_excessive_write_buffer(dhtmsg dmsg, dht_peer& peer, dht_peer& frompeer)
{
	// make sure peer is making progress
	if(peer.flags[dht_peer::PENDING_PROGRESS_CHECK] == false) {
		peer.flags[dht_peer::PENDING_PROGRESS_CHECK] = true;
		std::weak_ptr<dht_peer> wptr = connections[peer.index];
		uint64_t current_bytes = peer.bytes_sent;
		timers.add(30, [this, wptr, current_bytes]() {
			if(auto ptr = wptr.lock()) {
			   ptr->flags[dht_peer::PENDING_PROGRESS_CHECK] = false;
				if(ptr->bytes_sent == current_bytes) {
				   // no progress in 30 seconds, peer is dead
				   mark_defunct(*ptr);
				}
			}
		});
	}
	uint16_t msgtype = dht_header::get_msgtype(dmsg);
	uint16_t size = dht_header::get_msglen(dmsg);
	if(msgtype >= DHTMSG_DIRECT_START) {
		if(peer.bufs.write_bytes_buffered() < 8192)
			peer.bufs.buffer_write_data(dmsg.msg, size);
		else
			dout() << "Dropped direct DHT msg to " << peer.fingerprint << " because write buffer was excessive";
		return;
	}
	hashkey dest = dht_route_header(dmsg).get_hashkey();
	if(dest == peer.fingerprint) {
		// no sense trying to reroute messages for exact match destination
		if(peer.bufs.write_bytes_buffered() < 8192)
			peer.bufs.buffer_write_data(dmsg.msg, size);
		else
			dout() << "Dropped routed DHT msg to " << peer.fingerprint << " because write buffer was excessive";
		return;
	}
	// TODO: since dest is not exact match, ask congested peer to connect this peer with its antecedent and successor to possibly reduce congestion
		// (and set flag so that this msg isn't sent excessively)
		// maybe make this a direct message, something like CONGESTION_DETECTED (very small, no params), meaning "buffer to you is getting big, please help route around you"
			// could also use some way to distinguish message boundaries in the write buffer and move one to the front of the queue
			// possible solution is to store offset of start of first non-partially-sent message in buf, from which all the others can be parsed
				// (or just memmove the rest of the buf back by the size of the message you want to put near the front)
		// also maybe send CONNECT for this node's antecedent and successor to frompeer for the same reason, in case congestion is this node
	std::vector<size_t> rtremoved_peers;
	if(route_map.contains(peer.fingerprint)) {
		route_map.remove(connections[peer.index]);
		rtremoved_peers.emplace_back(peer.index);
	}
	dht_peer* next_hop = &route_map.nearest_peer(dest);
	while(next_hop->index != LOCAL_INDEX && next_hop->bufs.write_bytes_buffered() >= 1024) {
		route_map.remove(connections[next_hop->index]);
		rtremoved_peers.emplace_back(next_hop->index);
		next_hop = &route_map.nearest_peer(dest);
	}
	if(next_hop->index != LOCAL_INDEX) {
		process_routed_msgtype[msgtype - DHTMSG_ROUTED_START].reroute_msg(this, dmsg, frompeer);
		// TODO: send CONNECT on behalf of fromaddr to dest through next_hop
			// but probably need some kind of 'sent connect' flag to keep from doing it for every msg that arrives after buffer is full
	} else if(peer.bufs.write_bytes_buffered() < 4096) {
		peer.bufs.buffer_write_data(dmsg.msg, size); // nobody else can take it, send anyway
	} else {
		dout() << "Dropped packet from " << frompeer.fingerprint << " to " << peer.fingerprint << " final dest " << dest << " because write buffer was excessive and no alt route";
	}
	for(size_t idx : rtremoved_peers)
		route_map.insert(connections[idx]);
	
	// TODO: make sure retransmit timeouts from msg sources do the right thing for dropped messages
}

// convert decimal string to unsigned integer type
// six dozen library functions to do this and they're all terrible
template<class T>
T stou(const std::string& s)
{
	T num = 0;
	for(size_t i=0; i < s.size(); ++i) {
		if(static_cast<T>(num*10)/10 != num)
			throw e_invalid_input("Integer overflow converting string to integer");
		num*=10;
		if(s[i] < '0' || s[i] > '9')
			throw e_invalid_input("Non-numeric character in expected numeric string");
		num+=s[i]-'0';
	}
	return num;
}



node_info::node_info(const std::vector<std::string>& fields) {
	if(fields.size() < 6 || (fields.size()-3) % 3 != 0)
		throw e_invalid_input("node_info(): invalid number of fields in node string");
	size_t field;
	try {
		field=0;
		recency = stou<uint32_t>(fields[1]);
		field=1;
		dtls_source_port = htons(stou<uint16_t>(fields[2]));
		for(size_t i=3; i < fields.size();) {
			field=2;
			ip_info ip;
			if(inet_pton(AF_INET6, fields[i].c_str(), ip.addr.ip6.s6_addr) <= 0)
				throw e_invalid_input("inet_pton() could not parse IP address");
			++i;
			field=3;
			ip.port = htons(stou<uint16_t>(fields[i]));
			++i;
			field=4;
			addrs[ip] = stou<uint16_t>(fields[i]);
			++i;
		}
	} catch(const e_invalid_input&) {
		const char *fieldnames[] = { "node recency", "DTLS source port", "IP address", "IP port", "address recency" };
		eout out;
		out << "Could not parse node_info() " << fieldnames[field] << " field, line was:\n";
		for(const std::string& s : fields)
			out << "[" << s << "] ";
		throw;
	}
}

node_info::node_info(const std::vector<ip_info> &infos, uint16_t dtls_source)
	: recency(DEFAULT_PEER_RECENCY), dtls_source_port(dtls_source)
{
	for(auto& ip : infos)
		addrs[ip] = DEFAULT_ADDR_RECENCY;
}

std::ostream& operator<<(std::ostream& out, const node_info& ni)
{
	out << ni.recency << "," << ntohs(ni.dtls_source_port);
	for(auto& ip : ni.addrs) {
		char ip_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, ip.first.addr.ip6.s6_addr, ip_str, sizeof(ip_str)); // <- should not be possible for this to fail here
		out << "," << ip_str << "," << ntohs(ip.first.port) << "," << ip.second.recency;
	}
	return out;
}



known_peer_set::known_peer_set() : recency_threshold(node_info::DEFAULT_PEER_RECENCY), next_recency_threshold(0), active_serial(0), written_serial(0), too_soon(std::chrono::steady_clock::now()) {
	std::ifstream infile(snow::conf[snow::KNOWN_PEERS_FILE].c_str(), std::ios::in);
	std::string str;
	for(size_t linenum = 1; std::getline(infile, str); ++linenum)
	{
		if(str.size()==0 || str[0]=='#')
			continue;
		try {
			std::vector<std::string> fields = splitstring(str);
			auto entry = known_peers.insert(std::make_pair<hashkey,node_info>(fields[0], fields));
			if(entry.first->first.initialized() == false) {
				wout() << "Discarded known peer line " << linenum << " as hashkey was invalid";
				known_peers.erase(entry.first);
			} else if(entry.second == false) {
				wout() << "Discarded known peer line " << linenum << " as duplicate entry";
			}
		} catch (const e_invalid_input& e) {
			eout() << "Reading known peers file: Error on line " << linenum << ":" << e;
		}
	}
}

std::vector<std::string> known_peer_set::splitstring(const std::string& line)
{
	std::vector<std::string> strings;
	const char delim = ',';
	size_t pos = 0, endpos;
	do {
		while(pos < line.size() && isspace(line[pos]))
			++pos; // consume all preceding whitespace
		endpos = line.find_first_of(delim, pos);
		strings.emplace_back(line.substr(pos, endpos-pos));
		pos = endpos+1;
	} while(endpos != std::string::npos);
	return std::move(strings);
}

node_hkinfo known_peer_set::get_next_bootstrap()
{
	std::lock_guard<std::mutex> lk(mtx);
	if(known_peers.size() == 0)
		throw e_not_found("known_peer_set::get_next_bootstrap()");
	auto it = known_peers.find(last_bootstrap);
	do {
		if(it != known_peers.end())
			{ ++it; }
		if(it == known_peers.end()) {
			if(recency_threshold == 0) {
				if(std::chrono::steady_clock::now() < too_soon)
					throw e_slow_down("known_peer_set::get_next_bootstrap()");
				dout() << "Out of bootstrap peers, starting over from all known peers";
				too_soon = std::chrono::steady_clock::now() + std::chrono::seconds(30);
				recency_threshold = node_info::DEFAULT_PEER_RECENCY;
			} else {
				recency_threshold = next_recency_threshold;
			}
			next_recency_threshold = 0;
			it = known_peers.begin();
		}
		if(it->second.recency < recency_threshold && it->second.recency > next_recency_threshold)
			next_recency_threshold = it->second.recency;
	} while(it->second.recency != recency_threshold);
	last_bootstrap = it->first;
	return node_hkinfo(it->first, it->second.get_addrs(), it->second.dtls_source_port);
}

// TODO: not all of this is implemented yet (particularly removals):
// reliability metrics:
	// each address gets its own metric, similar to the one for the peer itself:
		// each address has unsigned value that starts at e.g. 256
		// each time we successfully connect to a peer, it gives us all its addresses
		// every new address is added to the list with metric 256
		// existing addresses still on the list are reset to 256
		// existing addresses not on the list have their values decremented by one
			// if an address reaches zero it is removed from the list
	// the logic here is that truly defunct addresses are eventually removed,
	// but we don't immediately remove addresses for peers whose addresses shift between a consistent few
		// e.g. device has address A at home, address B at work
	// also, sanity check for removing nodes entirely:
		// if one gets all the way down to zero, normalize every node against the node with the highest recency (in case network has been down for an extended period)
		// additionally, never remove nodes if there are fewer than e.g. 64 known peers
void known_peer_set::add_peer(const hashkey& fingerprint, uint16_t dtls_srcprt, const std::vector<ip_info>& addrs, worker_thread* io, bool is_client)
{
	std::lock_guard<std::mutex> lk(mtx);
	auto ipair = known_peers.insert(std::pair<hashkey,node_info>(fingerprint, node_info()));
	ipair.first->second.dtls_source_port = dtls_srcprt;
	if(ipair.second == false) {
		// entry already exists, decrement recency of addrs not provided
		// TODO: remove addresses and peers that hit zero (but not if there would be nothing remaining etc.)
		for(auto& addr : ipair.first->second.addrs)
			if(addr.second.recency != 0)
				--addr.second.recency;
	}
	for(auto& ip : addrs)
		ipair.first->second.addrs[ip] = node_info::DEFAULT_ADDR_RECENCY;
	// don't reset peer recency for incoming connections, we only really care about how often outgoing connections work
	if(is_client)
		ipair.first->second.recency = node_info::DEFAULT_PEER_RECENCY;
	save_modified_data(io);
}

void known_peer_set::mark_fail(const hashkey& target, worker_thread* io)
{
	std::lock_guard<std::mutex> lk(mtx);
	auto it = known_peers.find(target);
	if(it != known_peers.end() && it->second.recency != 0) {
		--it->second.recency;
		save_modified_data(io);
	}
}

void known_peer_set::save_modified_data(worker_thread* io)
{
	if(active_serial == written_serial) {
		io->add(std::bind(&known_peer_set::save_to_disk, this));
	} // else there is already a pending write which will write latest version when it execs
	++active_serial;
}
// TODO: this is not optimal (similar problem to address leases)
	// we're writing to disk in a separate thread but doing it with a mutex locked
	// if DHT thread tries to lock then it's sitting there waiting for disk anyway
	// better alternative might be to use fixed-width fields in the data file and use the vector O(1) unsorted removal trick
	// could even still use plaintext file format and pad with spaces (and just correct padding on startup)
	// then mmap the file and keep a map of hashkeys (or first 64-bits of hashkey data) to file offsets
void known_peer_set::save_to_disk()
{
	std::string tmpfn = snow::conf[snow::KNOWN_PEERS_FILE] + "~";
	std::lock_guard<std::mutex> lk(mtx);
	if(written_serial != active_serial) {
		dout() << "Writing known_peers file to filesystem " << tmpfn;
		std::ofstream outfile(tmpfn.c_str(), std::ios::binary | std::ios::out);
		if(!outfile.good()) {
			eout() << "Could not open temporary known_peers file for write (" << tmpfn << ")";
			return;
		}
		try {
			outfile.exceptions( std::ofstream::failbit | std::ofstream::badbit );
			if(outfile.tellp() != 0) {
				wout() << "Found non-empty known_peers temporary file " << tmpfn << ", contents will be overwritten";
				outfile.seekp(0);
			}
			outfile << "# Do not edit this file while the service is running, your changes will be overwritten\n";
			for(const auto& ni: known_peers)
				outfile << ni.first.key_string() << "," << ni.second << "\n";
			outfile.flush();
			outfile.close();
			std::rename(tmpfn.c_str(), snow::conf[snow::KNOWN_PEERS_FILE].c_str());
			written_serial = active_serial;
		} catch(const std::exception& e) {
			eout() << "Got exception writing known_peers file: " << e.what();
		}
	}
}

