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
#include"peer_init.h"
#include"vnet.h"
#include"dht.h"
#include"../common/common.h"
#include"configuration.h"







std::shared_ptr<dtls_peer> peer_init::new_peer_socket_event(const sockaddrunion& local_su, const sockaddrunion& remote_su, uint8_t* buf, size_t readlen, csocket::sock_t sd)
{
	
	dtls_ptr newconn = tls_conn::getNewClient(local_su, remote_su, buf, readlen, sd);
	if(newconn == nullptr)
		return nullptr;
	return new_connection(std::move(newconn), false);
	// TODO:
		// consider the possibility that a peer changes its ipaddr
		// then we would get a packet from the new ip that isn't assigned to any connection
		// and the ideal thing to do in that case is to swap out the sockets and maintain the existing connection
		// the problem is how to authorize that transfer after the original connection is gone; DHT?
			// the other issue is how to tell it was actually a change in remote peer and not just a coincidence that some new conn picked same ports
		// (doing it with advance notice of the change is obviously much easier)
		// a different possibility is that peers could establish a nonce+shared secret when initially connected
			// then if addr changes, peer sends datagram containing the nonce (to identify) and HMAC(secret, its new ipaddr) to authenticate
			// and whatever addr/port that packet is received using, that's the new one to use for the connection identified by that secret
			// when peer receives the packet and it validates, it confirms by sending port detect msg over existing DTLS to new ipaddr	
				// (which also gives peer its new NAPT port if different)
			// if peer with new addr doesn't get confirmation promptly it can retransmit nonce+HMAC packet until it does or timeout
}


void peer_init::new_connect_info(dht_connect_info& info) {
	// new connection request, usually from DHT
	if(!dispatch->is_running())
		return; // no new connections during shutdown
	if(info.peer == tls_listen.get_hashkey()) {
		dout() << "peer init got request to make TLS connection to self, dropped";
		return;
	}
	
	if(connection_exists(info.peer)) {
		// already connected to this peer, store peer info temporarily while vnet verifies that existing connection is still alive
		dht_connect_info* temp = new dht_connect_info(std::move(info));
		attempt_info_map[temp->peer].insert(temp);
		timers.add(30, [this, temp] () {
			// remove if still there after timeout
			auto it = attempt_info_map.find(temp->peer);
			if(it != attempt_info_map.end()) {
				it->second.erase(temp);
				if(it->second.size() == 0)
					{ attempt_info_map.erase(it); }
			}
			delete temp;
		});
		// check that existing connection is still good, maybe existing connection died and peer noticed first
		vn->check_connection(temp->peer);
		return;
	}

	// do connection attempt(s): set retries and create tls_conn objects
	dout() << "peer not in connected_peers, new_connect_info doing connect attempt";
	bool remote_request = info.get_flag(dht_connect_info::REMOTE_REQUEST);
	for(const ip_info& ip: info.ip_addrs)
	{
		if(ip.port == 0) continue;
		// if peer has an address in this node's natpool, that will never work so don't even try
		if(ip.addr.is_ip4map6() && vn->natpool_contains_addr(ip.addr.ip4_addr())) continue;
		attempt_new_connection(info.peer, ip, info.connect_retry, remote_request);
	}
	if(info.connect_retry != nullptr) {
		// use provided outgoing addrs for holepunch on retry
		info.connect_retry->holepunch_addrs = std::move(info.ip_addrs);
		if(info.connect_retry.unique()) {
			// all the attempts died immediately, do retry now
			exec_retry(info.connect_retry, info.peer);
		}
	}
}

void peer_init::attempt_new_connection(const hashkey& hk, const ip_info& ip, std::shared_ptr<dht_connect_retry>& retry, bool remote_request)
{
	// try to get socket to use for this
	sockaddrunion remote_addr;
	write_sockaddr(ip.addr.ip6.s6_addr, ip.port, &remote_addr);
	try {
		// could be allocating new socket here, so would have to destroy if not used
		// but here we either use it or there is an existing connection (which means it wasn't a new socket)
		dtls_socket& socket = dispatch->get_socket(remote_addr, 0);
		auto remote_it = socket.peers.find(ip);
		if(remote_it == socket.peers.end()) {
			dout() << "peer_init::attempt_new_connection making connection to " << hk << " at " << ip << " with local socket " << socket.local_addr;
			std::shared_ptr<snow_handshake_conn> newpeer = new_connection(dtls_ptr(new tls_conn(socket.local_addr, remote_addr, hk, socket.sock.fd())), remote_request);
			if(retry != nullptr)
				{ newpeer->add_retry(retry); }
			std::weak_ptr<snow_handshake_conn> wptr = newpeer;
			timers.add(2, [wptr]() { if(auto ptr = wptr.lock()) ptr->exec_retries(); }); // if not in vnet in 2 seconds then do retries
			socket.peers.emplace(ip, std::move(newpeer));
		} else if(remote_it->second->peer_type() == dtls_peer::HANDSHAKE && static_cast<snow_handshake_conn*>(remote_it->second.get())->get_hashkey() == hk) {
			// already trying to connect to this peer with these params, just add retry (if any) to existing connection attempt
			if(retry != nullptr) {
				snow_handshake_conn* hc = static_cast<snow_handshake_conn*>(remote_it->second.get());
				hc->add_retry(retry);
				std::weak_ptr<snow_handshake_conn> wptr = hc->get_wptr();
				timers.add(2, [wptr]() { if(auto ptr = wptr.lock()) ptr->exec_retries(); }); // if not in vnet in 2 seconds then do retries
			}
		} else {
			// got conflict with another peer, e.g. because two peers behind same NAT provided same incoming port
			dout() << "attempt_new_connection to " << hk << " at " << remote_addr << " not proceeding because of conflict with peer address and port";
			// TODO: address possible peer conflict
			// one possibility would be to bind new local socket and use that, and send peer HOLEPUNCH_ADDRS specifying port to use,
				// but that's actually likely to fail, because if we successfully connected to a different peer using the same addr+port, another connection to that port should go to the same peer and not this one
				// what you kind of want in this case is to ask the *peer* to bind a new port and then connect to it on that port
			// there is also a possible DoS scenario here where the attacker keeps sending CONNECT with peer's addrs but wrong hashkey, and when real CONNECT arrives the failed attempt has the ports
				// in that case just choosing a different local port (and sending HOLEPUNCH_ADDRS) would be likely to succeed
			// the existing mitigation is that if all the attempts die immediately then new_connect_info will do the retries (i.e. counter-CONNECT), which should work much of the time, but could be improved
		}
	} catch(const check_err_exception& e) {
		dout() << "new_connect_info failed to get socket from dispatch for remote addr " << remote_addr << ": " << e;
		// TODO: deal with failed socket, what are the possible causes? maybe nothing to be done?
		// could be peer addr is broken (e.g. IPv6 on host with no IPv6 addr or some invalid address), what else?
		// one possibility is that until we get OS to provide address change notifications, local device may have new addr without existing socket
			// and OS chose it as source for outgoing to this peer, but bind for that socket failed (e.g. port in use or priv port after dropping privs)
	}
}

void peer_init::exec_retry(std::shared_ptr<dht_connect_retry>& retry, const hashkey &hk)
{
	dispatch->do_holepunch(retry->holepunch_addrs, retry->holepunch_port);
	dht_thread->connection_retry(hk, retry);
}

void peer_init::cleanup_peer(snow_handshake_conn& hconn)
{
	duplicates.remove_duplicate(hconn);
	handshake_peers.erase(hconn.get_wptr().lock());
}

void peer_init::cleanup_active(const dtls_ptr& conn, bool primary)
{
	const hashkey& hk = conn->get_hashkey();
	if(connected_peers.unregister_hashkey(hk) == false)
		return; // this is secondary and another conn has already been activated
	// see if there are any duplicates wanting to replace the old connection, otherwise exec deferred connection attempts
	std::shared_ptr<snow_handshake_conn> dup = nullptr;
	if(primary)
		{ dup = duplicates.activate_duplicate(conn->get_pubkey()); }
	if(dup != nullptr) {
		dout() << "Found dup for shutdown DTLS connection " << hk;
		dup->activate_duplicate();
	} else {
		// since no duplicate was available, do any pending attempts to reconnect
		// (secondary does this unconditionally because it doesn't track duplicates)
		auto attempt_it = attempt_info_map.find(hk);
		if(attempt_it != attempt_info_map.end()) {
			for(dht_connect_info* ptr : attempt_it->second) {
				dout() << "executing cached reconnect attempt after active DTLS disconnect";
				new_connect_info(*ptr);
				ptr->connect_retry = nullptr; // clear this to allow retries to exec (retries only exec when shared_ptr is unique) [is this doing anything here?]
			}
			attempt_info_map.erase(attempt_it);
		}
	}
}

void peer_init::reconnect_after_failure(hashkey peer, std::vector<ip_info> addrs, in_port_t holepunch_port)
{
	bool remote_request = false, no_retry = false;
	dht_connect_info retry(std::move(peer), std::move(addrs), remote_request, std::make_shared<dht_connect_retry>(dht_connect_retry::NORMAL_ROUTE, holepunch_port, no_retry));
	dout() << "reconnect_after_failure doing new_connect_info";
	new_connect_info(retry);
}

// previously live connection came back from vnet to be shut down and cleaned up
void peer_init::shutdown_connection(dtls_ptr conn, std::vector<ip_info>&& peer_addrs, in_port_t hp_port) {
	ip_info local(conn->get_local()), remote(conn->get_peer());
	bool is_error = conn->is_error(), remote_request = false, active = true;
	std::shared_ptr<snow_handshake_conn> cptr = std::make_shared<snow_handshake_conn>(std::move(conn), std::move(peer_addrs), hp_port, remote_request, active);
	cptr->set_self(cptr);
	handshake_peers.emplace(cptr);
	if(is_error) {
		dout() << "DTLS connection from vnet was error, attempting reconnect";
		cptr->mark_handshake_error();
	} else {
		// connection is still good, probably just idle for too long
		dout() << "DTLS connection from vnet was still good, doing clean disconnect";
		cptr->mark_disconnecting();
	}
	std::weak_ptr<snow_handshake_conn> wptr(cptr);
	timers.add(3, [this, wptr]() { if(!wptr.expired()) {dout() << "DTLS disconnect timeout"; dispatch->cleanup_peer(wptr);} });
	dispatch->update_peer(local, remote, std::move(cptr));
}

