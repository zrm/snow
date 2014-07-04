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

#include "handshake.h"
#include "vnet.h"
#include "tls.h"
#include "peer_init.h"
#include "ip_packet.h"

dtls_dispatch* snow_handshake_conn::dispatch(nullptr);
peer_init* snow_handshake_conn::pinit(nullptr);
vnet* snow_handshake_conn::vn(nullptr);
timer_queue *snow_handshake_conn::timers(nullptr);
buffer_list* snow_handshake_conn::buflist(nullptr);

snow_hello::snow_hello(dbuf&& buf, size_t read_len) : data(std::move(buf))
{
	if(data.size() < read_len)
		{ throw e_invalid_input("snow_hello(): buffer had less data than read_len"); }
	if(read_len < sizeof(hello_fields))
		{ throw e_invalid_input("snow_hello(): read less data than static hello fields"); }
	hfields = reinterpret_cast<hello_fields*>(data.data());
	addrs = reinterpret_cast<connect_addr*>(data.data() + sizeof(hello_fields));
	if(read_len < hello_size())
		{ throw e_invalid_input("snow_hello(): snow_hello was incomplete or malformed"); }
	if(hfields->ipaddrs > 12) {
		dout() << "Peer sent more than 12 IP addresses, truncating";
		hfields->ipaddrs = 12;
	}
}

snow_hello::snow_hello(const hashkey& local_hashkey, const dtls_ptr& peer_conn, const std::vector<ip_info>& local_ipaddrs, uint16_t mtu, uint16_t dhtport)
{
	data.resize(hello_size(local_ipaddrs.size()));

	uint16_t peer_hashlen, peer_hashalgo;
	if(peer_conn != nullptr && peer_conn->get_hashkey().initialized()) {
		peer_hashlen = peer_conn->get_hashkey().size();
		peer_hashalgo = peer_conn->get_hashkey().algo();
	} else {
		peer_hashlen = peer_hashalgo = 0;
	}
	
	hfields = reinterpret_cast<hello_fields*>(data.data());
	hfields->packet_type = PACKET_TYPE::SNOW_PACKET | SNOW_PACKET_TYPE::SNOW_HELLO_PACKET;
	hfields->ipaddrs = std::min<size_t>(local_ipaddrs.size(), 12); // don't send more than 12 addrs
	if(peer_conn != nullptr) {
		peer_conn->get_peer().write_ipaddr(hfields->peer_ip);
		hfields->peer_ip_port = peer_conn->get_peer().get_ip_port();
	} else {
		memset(hfields->peer_ip, 0, sizeof(hfields->peer_ip));
		hfields->peer_ip_port = 0;
	}
	hfields->flags = 0;
	hfields->protocol_version = 0;
	hfields->mtu = mtu;
	hfields->heartbeat_seconds = htons(snow::conf[snow::HEARTBEAT_SECONDS]);
	hfields->nbo_hashalgo = htons(local_hashkey.algo());
	hfields->nbo_hashlen = htons(local_hashkey.size());
	hfields->nbo_dhtport = dhtport;
	hfields->nbo_dtls_srcport = htons(snow::conf[snow::DTLS_OUTGOING_PORT]);
	hfields->peer_hashalgo = htons(peer_hashalgo);
	hfields->peer_hashlen = htons(peer_hashlen);
	
	addrs = reinterpret_cast<connect_addr*>(data.data() + sizeof(hello_fields));
	size_t idx = 0, stop = hfields->ipaddrs;
	for(auto addr = local_ipaddrs.begin(); addr != local_ipaddrs.end() && idx < stop; ++addr, ++idx) {
		memcpy(addrs[idx].ipaddr, addr->addr.ip6.s6_addr, 16);
		addrs[idx].nbo_port = addr->port;
	}
}

snow_handshake_conn::snow_handshake_conn(dtls_ptr&& dtls, bool remote_request, bool activ)
	: conn(std::move(dtls)), hello_send(pinit->local_hashkey(), conn, dispatch->get_advertised_ipaddrs(), vn->get_tun_mtu(), dispatch->get_dhtport()),
	  retransmit_counter(0), retransmit_max(DEFAULT_COUNT), retransmit_msecs(DEFAULT_MSECS), write_retry_msecs(DEFAULT_WRITE_MSECS),
	  handshake_status(HANDSHAKE_STATUS::DTLS_HANDSHAKE), peer_mtu(MIN_PMTU), peer_dht_port(0), peer_dtls_srcport(0),
	  primary(false), duplicate(false), verified_peer(false), active(activ)
{
	// conn is nullptr for nonpeer entries, non-active conn may at this point not have initialized hashkey
	if(conn != nullptr && active)
		{ primary = (conn->get_pubkey() < pinit->local_pubkey()); }
	if(remote_request)
		{ hello_send.set_flag(snow_hello::EXTERNAL_CONNECT_REQUEST); }
}

bool snow_handshake_conn::check_status(ssize_t status)
{
	if(status > 0) {
		write_retry_msecs = DEFAULT_WRITE_MSECS;
		return true; // positive values are success (e.g. # bytes transferred)
	}
	switch(status)
	{
	case tls_conn::TLS_OK:
		write_retry_msecs = DEFAULT_WRITE_MSECS;
		return true;
	case tls_conn::TLS_WANT_READ:
		// do nothing, socket_read_event will already be called again if there is a read event
		break;
	case tls_conn::TLS_SOCKET_ERROR:
		dout() << "handshake: socket error from DTLS connection, ignored";
		// fall through, treat as possible write failure
	case tls_conn::TLS_WANT_WRITE: {
		// waiting for writability on unconnected UDP socket is meaningless, just try again in a bit (exponential backoff up to max)
		std::weak_ptr<snow_handshake_conn> wptr = self;
		timers->add(std::chrono::steady_clock::now() + std::chrono::milliseconds(write_retry_msecs), [wptr]() { if(auto ptr = wptr.lock()) ptr->socket_pretend_event(); });
		if(write_retry_msecs < MAX_WRITE_MSECS)
			write_retry_msecs<<=1;
		break;
	}
	case tls_conn::TLS_CONNECTION_SHUTDOWN:
		// other side sent shutdown msg, do clean disconnect
		dout() << "handshake got TLS_CONNECTION_SHUTDOWN, disconnecting";
		mark_disconnecting();
		break;
	default:
		eout() << "handshake thread: DTLS error";
		mark_handshake_error();
		break;
	}
	return false;
}


void snow_handshake_conn::socket_read_event(dbuf& buf, size_t read_len)
{
	switch(handshake_status) {
	case DTLS_HANDSHAKE:
		dtls_handshake(buf.data(), read_len);
		break;
	case SNOW_HELLO:
		recv_snow_hello(buf.data(), read_len);
		break;
	case DISCONNECTING:
		dtls_shutdown(buf.data(), read_len);
		break;
	default:
		// remaining states require no action here, connection should be removed in next cleanup iteration
		break;
	}
}

void snow_handshake_conn::dtls_timeout_occurred() { pinit->dtls_timeout_occurred(*this); }

void snow_handshake_conn::dtls_handshake(uint8_t* read_buf, size_t read_len)
{
	dout() << "Doing DTLS handshake with " << conn->get_hashkey() << " local " << conn->get_local() << " remote " << conn->get_peer() << " read bytes " << read_len;
	int handshake_rv = conn->do_handshake(read_buf, read_len);
	if(check_status(handshake_rv) == false)
		{ return; } // DTLS handshake not finished yet
	// DTLS handshake finished, proceed to snow hello
	if(conn->get_pubkey() == pinit->local_pubkey()) {
		// we should already have filtered out self-connections, so either that failed, or something crazy is happening (or user configured two nodes with same pubkey)
		eout() << "Dropped connection after handshake to peer with same pubkey as this node (bug or defective peer)";
		mark_handshake_error();
		return;
	}
	if(conn->cert_verified_ok() == false) {
		wout() << "Dropped connection after handshake because certificate verification failed";
		mark_handshake_error();
		return;
	}
	dout() << "DTLS new connection finished DTLS handshake with local " << conn->get_local() << " remote " << conn->get_peer() << ", state is now SNOW_HELLO";
	handshake_status = HANDSHAKE_STATUS::SNOW_HELLO;
	primary = (conn->get_pubkey() < pinit->local_pubkey()); // primary is chosen based on lexical comparison of public keys
	if(primary) {
		if(pinit->register_connection(*this)) {
			active = true;
		} else {
			set_duplicate(true);
			// primary duplicate sends hello only once w/o requesting retransmit, secondary will carry on requesting retransmits until either it times out or primary activates
			send_hello();
			// set removal timer, since primary DUP does not retransmit and retransmit exceeded is the usual timeout
			// this is ~4s shorter than secondary, so that primary won't activate a dup that secondary just killed on timeout
			std::weak_ptr<snow_handshake_conn> wptr = self;
			timers->add(DUP_COUNT*DUP_MSECS/1000 - 4, [wptr]() {
				if(auto ptr = wptr.lock()) {
					if(ptr->handshake_status == SNOW_HELLO)
						{ ptr->mark_disconnecting(); }
				}
			});
		}
	}
	if(duplicate == false)
		{ retransmit_hello(); }
}

// this function is called with the same arguments by both peers
// this helps ensure mutual verification can occur solely given the two hello messages which both peers have access to
// and therefore that both peers come to the same conclusion
bool snow_handshake_conn::snow_hello_check_static(const snow_hello& primary_hello, const snow_hello& secondary_hello, bool primary_is_client)
{
	// only port seen by client is verified, client port from listen peer is often enough changed by NAPT that failing over that is unproductive
	if(primary_hello.get_flag(snow_hello::EXTERNAL_CONNECT_REQUEST) || secondary_hello.get_flag(snow_hello::STRICT_ADDRESS_VERIFY)) {
		if(secondary_hello.address_exists(primary_hello.fields().peer_ip, primary_is_client ? primary_hello.fields().peer_ip_port : 0) == false) {
			dout() << "IP address check failed checking address for secondary";
			return false;
		}
	}
	if(secondary_hello.get_flag(snow_hello::EXTERNAL_CONNECT_REQUEST) || primary_hello.get_flag(snow_hello::STRICT_ADDRESS_VERIFY)) {
		if(primary_hello.address_exists(secondary_hello.fields().peer_ip, primary_is_client ? 0 : secondary_hello.fields().peer_ip_port) == false) {
			dout() << "IP address check failed checking address for primary";
			return false;
		}
	}
	const unsigned min_mtu = 512;
	if(primary_hello.fields().mtu < min_mtu || secondary_hello.fields().mtu < min_mtu) {
		dout() << "snow hello MTU was too small (must be >= " << min_mtu
			   << "), primary mtu: " << primary_hello.fields().mtu << ", secondary mtu: " << secondary_hello.fields().mtu;
		return false;
	}
	if(primary_hello.hashkey_ok(secondary_hello) == false) {
		dout() << "primary hello validation of secondary hashkey FAILED";
		return false;
	}
	if(secondary_hello.hashkey_ok(primary_hello) == false) {
		dout() << "secondary hello validation of primary hashkey FAILED";
		return false;
	}
	return true;
}

bool snow_handshake_conn::snow_hello_check(snow_hello& hello_recv) {
	// TODO: possibly add protocol version check (once there are distinct versions to check against)
	if(primary) {
		if( snow_hello_check_static(hello_send, hello_recv, (primary == conn->is_client()) ) == false)
			{ return false; }
	} else {
		if( snow_hello_check_static(hello_recv, hello_send, (primary == conn->is_client()) ) == false)
			{ return false; }
	}
	if(conn->get_hashkey().initialized()) {
		hashkey check = conn->get_pubkey().get_hashkey(ntohs(hello_recv.fields().nbo_hashalgo), ntohs(hello_recv.fields().nbo_hashlen));
		if(check != conn->get_hashkey()) {
			dout() << "snow hello hashkey did not match known hashkey";
			return false;
		}
	} else {
		conn->set_hashkey_type(ntohs(hello_recv.fields().nbo_hashalgo), ntohs(hello_recv.fields().nbo_hashlen));
		if(!conn->get_hashkey().initialized()) {
			dout() << "snow handshake peer hashkey could not be calculated";
			return false;
		}
	}

	peer_addrs = hello_recv.get_addrs();
	peer_mtu = std::min<unsigned>(hello_recv.fields().mtu, vn->get_tun_mtu());
	peer_dht_port = hello_recv.fields().nbo_dhtport;
	peer_dtls_srcport = hello_recv.fields().nbo_dtls_srcport;
	dout() << "snow handshake check succeeded";
	return true;
}


void snow_handshake_conn::recv_snow_hello(uint8_t* read_buf, size_t read_len)
{
	dbuf buf(buflist->get());
	ssize_t bytes = conn->recv(read_buf, read_len, buf.data(), buf.size());
	if(check_status(bytes) == false)
		{ return; }
	if(bytes == 0) {
		eout() << "Got packet from peer containing nothing, disconnecting";
		mark_handshake_error();
		buflist->recover(std::move(buf));
		return;
	}
	if(buf[0] != (PACKET_TYPE::SNOW_PACKET | SNOW_PACKET_TYPE::SNOW_HELLO_PACKET)) {
		// peer has already sent a non-hello packet, we must have lost its hello
		// buffer packet if there are not too many already and then request a hello retransmit by resending our hello with REQUEST_RETRANSMIT
		buffer_packet(std::move(buf), bytes);
		hello_send.set_flag(snow_hello::REQUEST_RETRANSMIT);
		send_hello();
		return;
	}
	try {
		snow_hello hello_recv(std::move(buf), bytes);
		if(snow_hello_check(hello_recv)) {
			verified_peer = true;
			// client port is theoretically not interesting, set to zero (TODO: could be useful for NAPT+holepunch: peer sends holepunch to visible port to open its NAT for our NAPT'd outgoing)
				// in other words, could possibly benefit from sending this port as holepunch port in DHT CONNECT;
				// but current use of visible_ipaddr is to provide to peers for incoming connection, so has to stay zero until that's fixed or incoming peers would start connecting to outgoing port
			visible_ipaddr = ip_info(hello_recv.fields().peer_ip, conn->is_client() ? 0 : hello_recv.fields().peer_ip_port); 
			if(hello_recv.get_flag(snow_hello::REQUEST_RETRANSMIT))
				{ send_hello(); }
			/* duplicates:
			 * primary identifies duplicates; when a duplicate is identified the primary sends the initial hello with the DUP flag set
			 * in that case, the primary does not retransmit the hello on a timer;
			 * instead there is a removal timer which removes the duplicate after a timeout (this timer is shorter than secondary's DUP retransmit timeout)
			 * when the secondary receives a hello from the primary with the DUP flag set, it continues to retransmit the hello (now with the DUP and REQUEST_RETRANSMIT flags set)
			 * when the primary receives a hello from the secondary with REQUEST_RETRANSMIT, it sends the hello again
			 * this way the secondary keeps requesting a hello until the primary either activates the dup by clearing the DUP flag or disconnects (or times out)
			*/
			if(primary == false)
				{ set_duplicate(hello_recv.get_flag(snow_hello::DUP)); }
			if(duplicate) {
				// got duplicate, probably going to drop soon, meanwhile check that existing connection is still good
				dout() << "Have duplicate for " << conn->get_hashkey() << ", checking active connection";
				vn->check_connection(conn->get_hashkey());
			} else {
				mark_live(); // mark for send to vnet
			}
		} else {
			dout() << "Disconnecting remote peer because snow hello check failed";
			mark_handshake_error();
		}
		buf = hello_recv.destroy();
	} catch(const e_invalid_input& e) {
		dout() << "Received invalid snow hello from peer: " << e;
		mark_handshake_error();
	}
	buflist->recover(std::move(buf));
}

void snow_handshake_conn::send_hello()
{
	ssize_t status = conn->send(hello_send.hello_buf(), hello_send.hello_size());
	hello_send.clear_flag(snow_hello::REQUEST_RETRANSMIT); // clear this by default, reduce chance of accidental infinite recursion
	check_status(status);
}

void snow_handshake_conn::retransmit_hello(bool request_retransmit)
{
	// retransmits the most recent handshake message until either the retransmit count is exceeded or the connection is disconnected or moved to vnet
	if(++retransmit_counter <= retransmit_max) {
		if(request_retransmit)
			{ hello_send.set_flag(snow_hello::REQUEST_RETRANSMIT); }
		send_hello();
		// send another retransmit with request_retransmit in a bit, if conn is still here then one peer or both has not received actionable hello
		timers->add(std::chrono::steady_clock::now() + std::chrono::milliseconds(retransmit_msecs),
						  std::bind(&snow_handshake_conn::retransmit_hello_static, std::weak_ptr<snow_handshake_conn>(self)));
		retransmit_msecs = (retransmit_msecs < 1000) ? retransmit_msecs*2 : 2000;
	} else {
		// retransmit count exceeded
		if(duplicate) {
			mark_disconnecting();
		} else {
			mark_handshake_error();
		}
	}
}

void snow_handshake_conn::add_retry(std::shared_ptr<dht_connect_retry>& retry) {
	for(auto& r : retries)
		if(*r == *retry)
			return;
	retries.emplace_back(retry);
}
	   
void snow_handshake_conn::exec_retries()
{
	if(conn->is_client() == false)
		{ return; } // only outgoing connections have retries
	if(pinit->connection_exists(conn->get_hashkey()) == false) { // only do retries if there is not a live connection
		for(std::shared_ptr<dht_connect_retry>& retry : retries) {
			if(retry.unique())
				{ pinit->exec_retry(retry, get_hashkey()); } // last one, do retry

		}
		retries.clear();
	} else {
		vn->check_connection(conn->get_hashkey()); // if there is a live connection then make sure it's still good
	}
}

void snow_handshake_conn::mark_live()
{
	if(dispatch->is_running()) {
		if(handshake_status != MAKE_LIVE) {
			handshake_status = MAKE_LIVE;
			pinit->register_hashkey(conn->get_hashkey());
			hello_send.clear_flag(snow_hello::REQUEST_RETRANSMIT);
			active = true;
			dispatch->cleanup_peer(self);
		}
	} else {
		mark_disconnecting(); // (don't send to vnet if shutting down)
	}
}


void snow_handshake_conn::cleanup()
{
	pinit->cleanup_peer(*this);
	if(active == true && handshake_status != MAKE_LIVE) {
		pinit->cleanup_active(conn, primary);
	}
	
	switch(handshake_status) {
	case SNOW_HELLO:
		eout() << "BUG: connection got to cleanup in snow_handshake_conn with invalid cleanup state";
		break;
	case DTLS_HANDSHAKE: // <- this is still set when there is a DTLS handshake timeout
	case HANDSHAKE_ERROR:
		exec_retries();
		// if active failed, do complete do over: try connecting direct to peer, then retry with DHT using holepunch to previously connected IP 
		if(active)
			{ pinit->reconnect_after_failure(get_hashkey(), peer_addrs, peer_dtls_srcport); }
		break;
	case MAKE_LIVE:
		vn->add_peer(std::move(conn), std::move(hello_send), packets, std::move(peer_addrs), peer_dht_port, peer_dtls_srcport, visible_ipaddr, peer_mtu, primary);
		return; // for MAKE_LIVE do not fall through to remove_peer()
	case DISCONNECTING:
		break;
	}
	dispatch->remove_peer(ip_info(conn->get_local()), ip_info(conn->get_peer()));
}


