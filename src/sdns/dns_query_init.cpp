/*	sdns
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

#include "../common/pollvector.h"
#include "../common/pbind.h"
#include "dns_query_init.h"
#include "dns_query.h"
#include "eventloop.h"

dns_query_init::dns_query_init(pollvector< std::shared_ptr<dns_query> >& queriesref, timer_queue & timers_ref, void(eventloop::*eventfn)(size_t, pvevent, sock_err), eventloop * eventlp)
	: queries(queriesref), timers(timers_ref), use_ip_family(IP_FAMILY::IPV4)
{
	try {
		snow_query_socket = csocket(AF_INET, SOCK_DGRAM);
		sockaddrunion sockaddr = get_sockaddr(htonl(0x7f000001), 0); // 127.0.0.1
		snow_query_socket.setopt_exclusiveaddruse();
		snow_query_socket.bind(sockaddr);
		sockaddr.sa.sin_port = htons(sdns::conf[sdns::SNOW_NAMESERV_PORT]);
		snow_query_socket.connect(sockaddr);
		snow_query_socket.setopt_nonblock();
	} catch(const check_err_exception& e) {
		eout() << "Failed to set up snow query socket: " << e;
		abort();
	}
	query_socket_event_function = std::bind(eventfn, eventlp, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
	dns_query::set_pointers(this, &query_socket_event_function, &queries);
	forwarders.configure_forwarders();
	read_static_records();
}

ns_track dns_query_init::get_closest_ns(const domain_name &name, unsigned family_mask)
{
	// TODO: if ns vec is returned and some ns has addr but not the other(s), send query for addrs for other ns
		// maybe do this at call site so query depth can be set appropriately
	if(family_mask == 0)
		family_mask = use_ip_family;
	const std::vector<sockaddrunion> *forwarder = forwarders.get_forwarder(name);
	if(forwarder != nullptr) {
		ns_track fwdr_nameservs(true);
		size_t index = fwdr_nameservs.add_ns();
		for(auto su : *forwarder) {
			if(su.s.sa_family == AF_INET && (family_mask & IP_FAMILY::IPV4))
				fwdr_nameservs.add_ns_addr(index, su);
			if(su.s.sa_family == AF_INET6 && (family_mask & IP_FAMILY::IPV6))
				fwdr_nameservs.add_ns_addr(index, su);
		}
		return std::move(fwdr_nameservs);
	}
	ns_track nameservs(false);
	dns_cache::closest_ns ns_records = cache.get_closest_ns(name, family_mask);
	for(const ns_rdata & ns : ns_records.ns) {
		if(family_mask & IP_FAMILY::IPV4) {
			rrset_rdata<a_rdata> a_records = cache.get_rrset_target<a_rdata>(ns.name);
			if(a_records.record_count() > 0)
				nameservs.add_ns(&a_records);
		}
		if(family_mask & IP_FAMILY::IPV6) {
			rrset_rdata<aaaa_rdata> aaaa_records = cache.get_rrset_target<aaaa_rdata>(ns.name);
			if(aaaa_records.record_count() > 0)
				nameservs.add_ns(&aaaa_records);
		}
	}
	return std::move(nameservs);
}

void dns_query_init::do_cache_population_query(const dns_question &q, uint16_t depth)
{
	do_cache_query(q, [](dns_response && r){ dout() << "Finished cache population query with rcode " << r.rcode; }, depth);
}

void dns_query_init::do_cache_query(const dns_question &q, std::function<void(dns_response&&)> &&notifier, uint16_t recursion_depth)
{
	if(q.qtype() == dns_qtype_t::ANY) {
		dout() << "do_cache_query: ANY query, must do_query";
		do_query(q, std::move(notifier), get_closest_ns(q.qname()), recursion_depth);
		return;
	}
	dout() << "do_cache_query checking cache before doing outgoing query";
	std::unique_ptr<rrset_data> rrset = cache.get_rrset(q.qname(), q.qtype(), q.qclass());
	if(rrset != nullptr && rrset->record_count() > 0) {
		dout() << "do_cache_query cache hit for " << q << " : " << *rrset;
		notifier(dns_response_answer(dns_rcode_t::DNS_NO_ERROR, q.qname(), *rrset));
	} else if(rrset != nullptr && rrset->expire.expired() == false) {
		// unexpired TTL with zero records means ncached NODATA
		ncache_soa ncache = cache.get_ncache_soa(q.qname());
		if(ncache.soa != nullptr) {
			dout() << "ncache NODATA hit with SOA for " << q;
			notifier(dns_response_nx(dns_rcode_t::DNS_NO_ERROR, std::move(ncache.soa)));
		} else {
			dout() << "ncache NODATA hit without SOA, doing outgoing query for " << q;
			do_query(q, std::move(notifier), get_closest_ns(q.qname()), recursion_depth);
		}
	} else {
		if(q.qtype() != dns_type_t::CNAME) {
			rrset_rdata<cname_rdata> cname = cache.get_rrset<cname_rdata>(q.qname());
			if(cname.record_count() > 0) {
				dout() << "do_cache_query for " << q << " got " << cname;
				try {
					std::vector< dns_record<cname_rdata> > cname_chain = cache.follow_cname(q.qname(), cname);
					dns_question cname_q(cname_chain.back().rdata.name, q.qtype(), q.qclass());
					auto notif = std::bind(&dns_query_init::resolved_cname_chain, this, dns_response_notifier(std::move(notifier)), std::move(cname_chain), std::placeholders::_1);
					do_cache_query(cname_q, std::move(notif), recursion_depth + 1);
				} catch(const dns_cache::cname_loop_exception&) {
					dout() << "SERVFAIL: CNAME loop for " << q;
					notifier(dns_response_error(dns_rcode_t::SERVFAIL));
				}
				return;
			}
			// (CNAME NODATA means nothing, known lack of CNAME does not imply lack of actual record)
		}
		ncache_soa ncache = cache.get_ncache_soa(q.qname());
		if(ncache.nxdomain && ncache.soa != nullptr) {
			dout() << "ncache NXDOMAIN hit for " << q;
			notifier(dns_response_nx(dns_rcode_t::NAME_ERROR, std::move(ncache.soa)));
		} else {
			dout() << "cache/ncache miss, doing outgoing query for " << q;
			do_query(q, std::move(notifier), get_closest_ns(q.qname()), recursion_depth);
		}
	}
}

bool is_key_name(const domain_name& name) { return sdns::conf[sdns::SNOW] && name.num_labels() > 0 && name.from_root(0)=="key"; }

dns_query * dns_query_init::do_query(const dns_question &q, std::function<void(dns_response&&)> &&notifier, ns_track &&nameservs, uint16_t recursion_depth)
{
	if(sdns::conf[sdns::SNOW] && is_key_name(q.qname())) {
		do_snow_query(q, std::move(notifier), recursion_depth);
		return nullptr;
	}
	auto it = query_map.find(q);
	if(it != query_map.end()) {
		if(auto ptr = it->second.lock()) {
			if(!ptr->is_defunct()) {
				dout() << "do_query() found existing query for " << q << ", assigning notifier to existing";
				ptr->add_notifier(std::move(notifier));
				return nullptr;
			}
		}
	}
	if(recursion_depth > sdns::conf[sdns::MAX_DNS_QUERY_DEPTH]) {
		wout() << "Failed to do_query() for " << q << " because max query depth (" << sdns::conf[sdns::MAX_DNS_QUERY_DEPTH] << ") exceeded";
		notifier(dns_response_error(dns_rcode_t::SERVFAIL));
		return nullptr;
	}
	dout() << "Doing new query (#" << queries.size() << ") at depth " << recursion_depth << "  for " << q;
	nameservs.randomize_order();
	queries.emplace_back(INVALID_SOCKET, pvevent::read, query_socket_event_function, std::make_shared<dns_query>(new dns_udp_socket(), std::move(notifier), q, queries.size(), std::move(nameservs), recursion_depth));
	queries.back()->send_query();
	query_map[q] = queries.back();
	return queries.back().get();
}

bool is_ip4_inaddr(const domain_name& name) { return name.num_labels()==6 && name.from_root(0)=="arpa" && name.from_root(1)=="in-addr"; }
uint32_t inaddr_arpa_to_ipv4(const domain_name& name)
{
	if(!is_ip4_inaddr(name))
		return 0;
	std::string addrstr;
	addrstr.reserve(INET_ADDRSTRLEN);
	for(size_t i=2; i < 6; ++i) {
		addrstr+=name.from_root(i).get_string();
		addrstr+='.';
	}
	addrstr.pop_back();
	uint32_t addr;
	if(inet_pton(AF_INET, addrstr.c_str(), &addr) == 1)
		return addr;
	return 0;
}
domain_name ipv4_to_inaddr_arpa(uint32_t addr)
{
	// addr must be reverse of network byte order (note that "reverse of network byte order" is not "host byte order" on all architectures)
	addr = ((addr & 0xff000000) >> 24) + ((addr & 0x00ff0000) >> 8) + ((addr & 0x0000ff00) << 8) + ((addr & 0x000000ff) << 24);
	char addrstr[INET_ADDRSTRLEN];
	std::string name = inet_ntop(AF_INET, &addr, addrstr, INET_ADDRSTRLEN);
	name += ".in-addr.arpa";
	dout() << "Converted addr to " << name;
	return domain_name(name);
}

std::unique_ptr< dns_record<soa_rdata> > get_key_soa() // provide ncache SOA for NODATA / NXDOMAIN key names
{
	static const domain_name key("key");
	static const domain_name key_ns("ns.key");
	static const domain_name key_ns_rname("postmaster.localhost");
	static const uint32_t serial=1, refresh=60*15, retry=60*60*24, expire=60*15, minimum=10;
	return std::unique_ptr< dns_record<soa_rdata> >(new dns_record<soa_rdata>(key, dns_type_t::SOA, dns_class_t::IN, ttlexp(15), soa_rdata(key_ns, key_ns_rname, serial, refresh, retry, expire, minimum)));
}

void dns_query_init::do_snow_query(const dns_question &q, std::function<void(dns_response&&)> &&notifier, size_t depth)
{
	if(q.qclass() != dns_class_t::IN) {
		dout() << "key query for " << q << " has qclass not IN, sending NXDOMAIN";
		notifier(dns_response_nx(dns_rcode_t::NAME_ERROR, get_key_soa()));
		return;
	}
	if(q.qtype() != dns_qtype_t::A && q.qtype() != dns_qtype_t::PTR && q.qtype() != dns_qtype_t::ANY) {
		dout() << "key query for non-A non-PTR non-wildcard qtype, sending NODATA";
		notifier(dns_response_nx(dns_rcode_t::DNS_NO_ERROR, get_key_soa()));
		return;
	}
	uint32_t addr = inaddr_arpa_to_ipv4(q.qname());
	if(q.qtype() == dns_qtype_t::PTR && !addr) {
		if(is_key_name(q.qname())) {
			dout() << "PTR query for key name, sending NODATA";
			notifier(dns_response_nx(dns_rcode_t::DNS_NO_ERROR, get_key_soa()));
		} else {
			dout() << "PTR query for name that did not parse as in-addr.arpa: " << q.qname() << ", sending to internet DNS";
			do_cache_query(q, std::move(notifier), depth);
		}
		return;
	}
	uint64_t serial = ++snow_query_serial;
	auto p = snow_queries.insert(std::make_pair(q.qname(), serial));
	if(p.second) {
		send_snow_query(q.qname(), addr);
		timers.add(sdns::conf[sdns::SNOW_NAMESERV_TIMEOUT_SECS], std::bind(&dns_query_init::snow_query_retry, this, q.qname(), serial, 1));
	}
	p.first->second.notifiers.emplace_back(q.qtype(), std::move(notifier));
}

void dns_query_init::send_snow_query(const domain_name & qname, uint32_t addr)
{
	std::string name = qname.to_string();
	dout() << "snow query for " << name;
	try {
		size_t sent = addr ? snow_query_socket.send(&addr, sizeof(addr)) : snow_query_socket.send(name.c_str(), name.size()+1);
		dout() << "sent " << sent << " byte snow query";
	} catch(const check_err_exception& e) {
		dout() << "Failed to send snow query: " << e;
		// will retry again later if there are any retries left
	}
}


void dns_query_init::snow_query_retry(const domain_name & qname, uint64_t serial, size_t retry)
{
	auto it = snow_queries.find(qname);
	if(it != snow_queries.end() && it->second.serial == serial) {
		if(retry < sdns::conf[sdns::SNOW_NAMESERV_TIMEOUT_RETRIES]) {
			dout() << "key query timeout " << retry << " for " << qname;
			send_snow_query(qname, inaddr_arpa_to_ipv4(qname));
			timers.add(sdns::conf[sdns::SNOW_NAMESERV_TIMEOUT_SECS], std::bind(&dns_query_init::snow_query_retry, this, qname, serial, retry+1));
		} else {
			dout() << "key query final timeout (" << retry << ") for " << qname;
			for(auto &kq : it->second.notifiers)
				kq.notifier(dns_response_nx(dns_rcode_t::NAME_ERROR, get_key_soa()));
			snow_queries.erase(it);
		}
	}
}

void dns_query_init::snow_socket_error()
{
	// fail: snow configured but not available, so we don't even know the snow address pool
	// send all the non-rfc1918 PTR queries to internet DNS servers and give NODATA with no SOA for the RFC1918 ones
	for(auto it = snow_queries.begin(); it != snow_queries.end();) {
		if(is_ip4_inaddr(it->first)) {
			uint32_t addr = inaddr_arpa_to_ipv4(it->first);
			if(ip_union(addr).is_rfc1918()) {
				for(auto &kq : it->second.notifiers)
					kq.notifier(dns_response_nx(dns_rcode_t::DNS_NO_ERROR, nullptr));
			} else {
				for(auto &kq : it->second.notifiers)
					do_cache_query(dns_question(it->first, kq.qtype, dns_qclass_t::IN), std::move(kq.notifier), 0/*recursion depth*/);
			}
			it = snow_queries.erase(it);
		} else {
			++it;
		}
	}
}

void dns_query_init::snow_socket_event()
{
	try {
		char buf[72];
		size_t len = snow_query_socket.recv(buf, sizeof(buf));
		if(len > 4 && len < sizeof(buf)) {
			size_t slen = strnlen(buf, len-5);
			domain_name name(std::string(buf, slen));
			uint32_t addr;
			memcpy(&addr, buf+len-sizeof(addr), sizeof(addr));
			process_snow_response(name, addr);
		} else {
			dout() << "Key query socked recv()'d abnormal length " << len;
		}
	} catch(const e_check_sock_err &e) {
		dout() << "Failed to recv() from key query socket: " << e;
	} catch(const e_invalid_input &e) {
		dout() << "Failed to parse domain_name from snow_query_socket: " << e;
	}
}

void dns_query_init::process_snow_response(const domain_name &name, uint32_t addr)
{
	dout() << "key query response for " << name << " at " << ss_ipaddr(addr);
	auto it = snow_queries.find(name);
	if(it != snow_queries.end()) {
		if(addr != 0) {
			rrset_rdata<a_rdata> ans(dns_type_t::A, dns_class_t::IN, ttlexp(600), a_rdata(addr));
			for(auto &kq : it->second.notifiers)
				kq.notifier(dns_response_answer(dns_rcode_t::DNS_NO_ERROR, name, ans));
		} else {
			for(auto &kq : it->second.notifiers)
				kq.notifier(dns_response_nx(dns_rcode_t::NAME_ERROR, get_key_soa()));
		}
		snow_queries.erase(it);
	} else {
		dout() << "key query response did not correspond to any active forward query";
	}
	if(!addr) return;
	domain_name rname = ipv4_to_inaddr_arpa(addr);
	auto rit = snow_queries.find(rname);
	if(rit != snow_queries.end()) {
		if(name.num_labels() > 0) {
			rrset_rdata<ptr_rdata> ans(dns_type_t::PTR, dns_class_t::IN, ttlexp(5), ptr_rdata(name));
			for(auto &kq : rit->second.notifiers)
				kq.notifier(dns_response_answer(dns_rcode_t::DNS_NO_ERROR, rname, ans));
		} else {
			// for reverse queries not in address pool, now they go to internet DNS
			for(auto &kq : rit->second.notifiers)
				do_cache_query(dns_question(rname, kq.qtype, dns_qclass_t::IN), std::move(kq.notifier), 0/*recursion depth*/);
		}
		snow_queries.erase(rit);
	} else {
		dout() << "key query response did not correspond to any active reverse query";
	}
}



void dns_query_init::process_query(const dns_message &msg, std::function<void(dns_message &&, const edns_options&)> &&client_sender)
{
	dout() << "process_query()";
	if(msg.header().qr == true) {
		wout() << "Got DNS response on query port, dropped";
		return;
	}
	const edns_options &options = msg.additional().get_edns_options();
	bool edns = options.edns_present();
	if(options.duplicate_exists()) {
		dout() << "FORMAT_ERROR in DNS query: duplicate EDNS OPT record";
		dns_message format_error(msg.header().id, true/*qr*/, false/*aa*/, msg.header().rd, msg.header().opcode, dns_rcode_t::FORMAT_ERROR, msg.question(), true);
		client_sender(std::move(format_error), options);
		return;
	}
	if(msg.question().size() != 1) {
		dout() << "unsupported question count in query (" << msg.question().size() << ')';
		dns_message not_implemented(msg.header().id, true/*qr*/, false/*aa*/, msg.header().rd, msg.header().opcode, dns_rcode_t::NOT_IMPLEMENTED, msg.question(), edns);
		client_sender(std::move(not_implemented), options);
		return;
	}
	const dns_question &q = msg.question()[0];
	if(msg.header().opcode != dns_opcode_t::STANDARD_QUERY) {
		dout() << "unsupported opcode in query";
		dns_message not_implemented(msg.header().id, true/*qr*/, false/*aa*/, msg.header().rd, msg.header().opcode, dns_rcode_t::NOT_IMPLEMENTED, msg.question(), edns);
		client_sender(std::move(not_implemented), options);
		return;
	}
	if(msg.header().tc) {
		dout() << "got query with truncated flag set";
		dns_message format_error(msg.header().id, true/*qr*/, false/*aa*/, msg.header().rd, msg.header().opcode, dns_rcode_t::FORMAT_ERROR, msg.question(), edns);
		client_sender(std::move(format_error), options);
		return;
	}
	if(!msg.header().rd) {
		dout() << "got request for non-recursive query";
		// this resolver is never authoritative so nobody should be making iterative queries, so respond with REFUSED
		dns_message refused(msg.header().id, true/*qr*/, false/*aa*/, msg.header().rd, msg.header().opcode, dns_rcode_t::REFUSED, msg.question(), edns);
		client_sender(std::move(refused), options);
		return;
	}
	
	if(q.qclass() != dns_qclass_t::IN) {
		// discard queries for non-internet classes, we don't have any root servers for them anyway
		dns_message not_implemented(msg.header().id, true/*qr*/, false/*aa*/, msg.header().rd, msg.header().opcode, dns_rcode_t::NOT_IMPLEMENTED, msg.question(), edns);
		client_sender(std::move(not_implemented), options);
		return;
	}
	
	if(q.qtype() == dns_qtype_t::AXFR || q.qtype() == dns_qtype_t::IXFR) {
		// no zone transfers
		dns_message refused(msg.header().id, true/*qr*/, false/*aa*/, msg.header().rd, msg.header().opcode, dns_rcode_t::REFUSED, msg.question(), edns);
		client_sender(std::move(refused), options);
		return;
	}
	
	if(q.qtype() == dns_qtype_t::INVALID || q.qclass() == dns_qclass_t::INVALID) {
		dout() << "Rejected query with invalid (zero) qtype or qclass: " << q;
		dns_message format_error(msg.header().id, true/*qr*/, false/*aa*/, msg.header().rd, msg.header().opcode, dns_rcode_t::FORMAT_ERROR, msg.question(), edns);
		client_sender(std::move(format_error), options);
		return;
	}
	
	dout() << "process_query() will do_cache_query()";
	std::function<void(dns_response&&)> notifier = std::bind(&dns_query_init::send_client_response, this, std::move(client_sender), msg.header().id, q, options, std::placeholders::_1);
	if(sdns::conf[sdns::SNOW] && is_ip4_inaddr(q.qname()) && (q.qtype() == dns_qtype_t::PTR || q.qtype() == dns_qtype_t::ANY) && q.qclass() == dns_qclass_t::IN) {
		do_snow_query(q, std::move(notifier), 0/*recursion depth*/);
	} else {
		do_cache_query(q, std::move(notifier), 0/*recursion depth*/);
	}
}



void dns_query_init::process_response(const dns_message &msg, const sockaddrunion &fromaddr, dns_query &q)
{
	dout() << "process_response() got msg from " << fromaddr <<" in " << q.query_duration() << "ms:\n" << msg;
	// first check for problems that can cause the response to be rejected entirely
	if(msg.header().qr == false) {
		wout() << "Got DNS query on bizarre port when expecting DNS response (query ignored)";
		return;
	}
	if(msg.header().id != q.id()) {
		wout() << "Dropped query response from " << fromaddr << " for " << q.question() << " with id " << ntohs(msg.header().id) << " because id should have been " << ntohs(q.id());
		q.resend_tcp(); // TCP has greater resistance to poisoning attempts
		return;
	}
	if(msg.question().size() != 1) {
		wout() << "Dropped query response from " << fromaddr << " with irregular number of question sections (" << msg.question().size() << ")";
		return;
	}
	if(msg.question()[0] != q.question()) {
		wout() << "Dropped query response from " << fromaddr << " because response question section (" << msg.question()[0] << ") did not match query (" << q.question() << ")";
		return;
	}
	if(q.await_response() == false) {
		return;
	}
	if(msg.header().tc) {
		q.resend_trunc();
		return;
	}
	dns_rcode_t rcode = msg.header().rcode;
	if(q.edns_trunc_retry() && rcode != dns_rcode_t::DNS_NO_ERROR && rcode != dns_rcode_t::NAME_ERROR) {
		// some broken DNS servers give error responses to EDNS queries, which means truncated responses from them can only be retried with TCP
		dout() << "EDNS query attempt to resolve non-EDNS truncated query got error rcode from server, retrying with TCP";
		q.resend_tcp();
		return;
	}

	// at this point we are going to accept the response as legitimate
	switch(rcode) {
	case dns_rcode_t::DNS_NO_ERROR:
	case dns_rcode_t::NAME_ERROR:
		// deal with these below
		break;
	case dns_rcode_t::FORMAT_ERROR:
		wout() << "Got format error from " << fromaddr << " for " << q.question() << ", this probably should not happen";
		q.notify(dns_response_error(dns_rcode_t::FORMAT_ERROR));
		return;
	case dns_rcode_t::SERVFAIL:
		dout() << "Got SERVFAIL from " << fromaddr << " for " << q.question();
		q.send_query(); // send retry to a different NS if possible
		return;
	case dns_rcode_t::NOT_IMPLEMENTED:
		dout() << "Got not implemented rcode from " << fromaddr << " for " << q.question();
		q.notify(dns_response_error(dns_rcode_t::NOT_IMPLEMENTED));
		return;
	case dns_rcode_t::REFUSED:
		dout() << "Got REFUSED rcode from " << fromaddr << " for " << q.question();
		q.notify(dns_response_error(dns_rcode_t::REFUSED));
		return;
	default:
		wout() << "Got DNS response with unknown rcode " << (unsigned)msg.header().rcode << " from " << fromaddr << " for " << q.question();
		q.notify(dns_response_error(dns_rcode_t::SERVFAIL));
		return;
	}
	
	// defer execution of cache population queries until all the queries actually in service of this request have been sent, to reduce client response latency (slightly)
	deferred_queries do_queries_later; 
	process_answer(msg, fromaddr, q, do_queries_later);
	do_queries_later.exec(this, q.depth()+1);
}

void dns_query_init::process_answer(const dns_message &msg, const sockaddrunion &fromaddr, dns_query &q, deferred_queries &do_queries_later)
{
	const dns_rrset *final_answer = nullptr;
	for(const dns_rrset &r : msg.answer()) {
		if(r.get_name() == q.question().qname() && r.get_class() == q.question().qclass() && (r.get_type() == q.question().qtype() || r.get_type() == dns_type_t::CNAME )) {
			final_answer = &r;
			cache_answer_record(r);
		} else {
			// something like CNAME chain or A record to go with a CNAME, cache if in bailiwick, otherwise schedule cache population query
			if(!cache_other_record(r, fromaddr))
				do_queries_later.add(r);
		}
	}
	for(const dns_rrset &r : msg.authority())
		if(!cache_other_record(r, fromaddr))
			do_queries_later.add(r);
	for(const dns_rrset &r : msg.additional())
		if(!cache_other_record(r, fromaddr))
			do_queries_later.add(r);
	
	if(q.question().qtype() == dns_qtype_t::ANY && msg.header().rcode != dns_rcode_t::NAME_ERROR && msg.answer().rrset_exists(q.question().qname(), q.question().qclass())) {
		// wildcard type won't have matched any record so answer will be nullptr, but if any answer was there that's what we send
		std::vector<dns_rrset> answers;
		for(auto it = msg.answer().begin(); it != msg.answer().end(); ++it) {
			if(it->get_name() == q.question().qname() && it->get_class() == q.question().qclass()) {
				answers.emplace_back(*it);
			} else {
				dout() << "Ignored irrelevant answer record for wildcard query: " << *it;
			}
		}
		q.notify(dns_response_wildcard_answer(std::move(answers), dns_rcode_t::DNS_NO_ERROR));
	} else if(final_answer != nullptr) {
		// got some answer, could be the real answer, could be unterminated CNAME chain
		if(final_answer->get_type() == dns_type_t::CNAME && q.question().qtype() != dns_type_t::CNAME) {
			dout() << "Got CNAME, going to follow it";
			std::vector< dns_record<cname_rdata> > cname_chain = get_valid_cname_chain(q.question(), msg.answer(), fromaddr);
			// cname_chain should not ever actually be empty, but still check
			domain_name cname_target = cname_chain.size() > 0 ? cname_chain.back().rdata.name : q.question().qname().get_name();
			if(in_bailiwick(cname_target, fromaddr)) {
				const rrset_data &cname_target_rrset = msg.answer().get_rrset(cname_target, q.question().qtype(), q.question().qclass());
				if(cname_target_rrset.get_type() == q.question().qtype()) {
					dout() << "Got entire CNAME chain and target";
					q.notify(dns_response_answer(dns_rcode_t::DNS_NO_ERROR, cname_target, cname_target_rrset, std::move(cname_chain)));
					return;
				}
			}
			// don't check for NODATA in case of CNAME target: CNAME is the "answer" and the server is not required to provide any further referrals
			// referral may exist for CNAME target but we don't use it b/c it could be out of bailiwick
			if(msg.header().rcode == dns_rcode_t::NAME_ERROR && cname_chain.size() > 0 && in_bailiwick(cname_chain.back().rdata.name, fromaddr)) {
				notify_nx(q, msg, std::move(cname_chain), fromaddr);
			} else {
				do_cache_query(
					dns_question(cname_target, q.question().qtype(), q.question().qclass()),
					std::bind(&dns_query_init::resolved_cname_chain, this, q.release_notifier(), std::move(cname_chain), std::placeholders::_1),
					q.depth()+1
				);
			}
		} else {
			// got direct answer
			q.notify(dns_response_answer(dns_rcode_t::DNS_NO_ERROR, *final_answer));
		}
	} else if(msg.header().rcode == dns_rcode_t::NAME_ERROR || msg.authority().nodata() || /*forwarders should be authoritative or recursive, no referrers:*/ q.is_forwarder()) {
		notify_nx(q, std::vector< dns_record<cname_rdata> >(), msg.header().rcode, msg.authority().get_authority_soa(q.question().qname()), fromaddr);
	} else {
		process_referral(msg,  q);
	}
	
	if(!q.is_defunct()) {
		dout() << "BUG: failed to notify or release query after response";
		q.notify(dns_response_error(dns_rcode_t::SERVFAIL));
	}
}

void dns_query_init::process_referral(const dns_message &msg, dns_query &q)
{
	// got some kind of referral, have to keep going
	// send the original question to the referral servers as follows:
		// first we check if the name listed in the ns record in authority section has an addr in the additional section; if so, use it
		// if not we check the cache for an addr for that ns; if we have it, use it
		// if we don't have any addr for this ns, schedule subsidiary query to get one, meanwhile move on to the next ns
		// if we don't have addr for any ns then we wait for a subsidiary query to complete before we can continue
	const dns_rrset * nsrr = nullptr;
	for(const dns_rrset &r : msg.authority()) {
		if(r.get_type() != dns_type_t::NS || r.get_class() != q.question().qclass()) {
			dout() << "Got non-NS record (" << r << ") in authority section";
		} else if(r.get_name() != q.question().qname().get_name().get_root(r.get_name().num_labels()).name) {
			dout() << "Got irrelevant NS record (" << r << ") in authority section for query " << q.question();
		} else {
			nsrr = &r;
			break;
		}
	}
	if(nsrr == nullptr) {
		dout() << "SERVFAIL: Got \"referral\" with no relevant NS records in authority";
		q.notify(dns_response_error(dns_rcode_t::SERVFAIL));
		return;
	}
	ns_track nameservs(false);
	std::vector<domain_name> ns_need_addr;
	for(const ns_rdata & ns : nsrr->rrdata->get<ns_rdata>()) {
		const domain_name &ns_name = ns.name;
		// look for associated address records
		bool found_addr = false;
		for(const dns_rrset &a_r : msg.additional()) {
			if((use_ip_family & IP_FAMILY::IPV4) && a_r.get_type() == dns_type_t::A && a_r.get_name() == ns_name && a_r.record_count() > 0) {
				dout() << "Got addr for NS " << ns_name << ' ' <<  *a_r.rrdata << " from additional section";
				found_addr = true;
				nameservs.add_ns(a_r.rrdata.get());
			} else if((use_ip_family & IP_FAMILY::IPV6) && a_r.get_type() == dns_type_t::AAAA && a_r.get_name() == ns_name && a_r.record_count() > 0) {
				dout() << "Got addr for NS " << ns_name << ' ' << *a_r.rrdata << " from additional section";
				found_addr = true;
				nameservs.add_ns(a_r.rrdata.get());
			}
		}
		if(!found_addr) {
			// check cache for A/AAAA records
			if(use_ip_family & IP_FAMILY::IPV4) {
				rrset_rdata<a_rdata> cached_A_records = cache.get_rrset<a_rdata>(ns_name);
				if(cached_A_records.record_count() > 0) {
					dout() << "Got IPv4 addr for " << ns_name << " from cache";
					nameservs.add_ns(&cached_A_records);
					found_addr = true;
				}
			}
			if(use_ip_family & IP_FAMILY::IPV6) {
				rrset_rdata<aaaa_rdata> cached_AAAA_records = cache.get_rrset<aaaa_rdata>(ns_name);
				if(cached_AAAA_records.record_count() > 0) {
						dout() << "Got IPv6 addr for " << ns_name << " from cache";
						nameservs.add_ns(&cached_AAAA_records);
						found_addr = true;
				}
			}
			if(!found_addr) {
				dout() << "Need to do query to get IP addr for " << ns_name;
				ns_need_addr.emplace_back(ns_name);
				nameservs.queries_pending_inc();
				if((use_ip_family & IP_FAMILY::IPV4) && (use_ip_family & IP_FAMILY::IPV6))
					nameservs.queries_pending_inc();
			}
		}
	}
	// now going to send a recursive query
	query_map.erase(q.question());
	dns_query *recursive_query = do_query(q.question(), q.release_notifier(), std::move(nameservs), q.depth()+1);
	// also request addrs for nameservers with unknown addrs for cache and notify recursive query when they arrive, so it may use them if necessary
		// when notification comes in they get added as NS to recursive query, and if recursive query status is AWAIT_NS_ADDR the new addr causes status update and sends query
	if(recursive_query != nullptr) {
		for(const domain_name &name : ns_need_addr) {
			dout() << "Doing subsidiary query for NS IP addr of " << name;
			if(use_ip_family & IP_FAMILY::IPV4) {
				dns_question ns_question(name, dns_type_t::A, dns_class_t::IN);
				do_cache_query(ns_question, PBINDF(&dns_query::provide_ns_ipaddr, void(dns_response&&), recursive_query->get_ptr(), std::placeholders::_1), q.depth()+1);
			}
			if(use_ip_family & IP_FAMILY::IPV6) {
				dns_question ns_question(name, dns_type_t::AAAA, dns_class_t::IN);
				do_cache_query(ns_question, PBINDF(&dns_query::provide_ns_ipaddr, void(dns_response&&), recursive_query->get_ptr(), std::placeholders::_1), q.depth()+1);
			}
		}
	}
}

std::vector< dns_record<cname_rdata> > dns_query_init::get_valid_cname_chain(const dns_question &question, const dns_rr_section &answer, const sockaddrunion &fromaddr)
{
	// this ensures that every element in a CNAME chain came from the correct forwarder and is entirely in bailiwick
		// if a CNAME points to a name that has a forwarder, the CNAME is processed no further unless fromaddr is that forwarder
		// that way the CNAME target can be resolved using the correct forwarder
	std::vector< dns_record<cname_rdata> > cname_chain = answer.get_cname_chain(question);
	for(auto cname = cname_chain.begin(); cname != cname_chain.end(); ++cname) {
		if(in_bailiwick(cname->rdata.name, fromaddr) == false || is_key_name(cname->rdata.name)) {
			cname_chain.erase(cname+1, cname_chain.end());
			break;
		}
	}
	return std::move(cname_chain);
}


void dns_query_init::cache_answer_record(const dns_rrset &record)
{
	dout() << "Got answer record " << record << ", going to cache it";
	cache.cache_rrset(record);
}

// cache_other_record: caches the record if in bailiwick, returns true if the record does not need to be re-queried to get it from an in-bailiwick server
bool dns_query_init::cache_other_record(const dns_rrset &record, const sockaddrunion &fromaddr)
{
	// TODO: if DNSSEC support is implemented, record can be cached here if it has a valid signature regardless of bailiwick
		// also: records with valid signatures can overwrite unvalidated records or update TTL of older validated records
	// similarly, we shouldn't cache RRSIG here because if it was in authority then it might not be a complete set
		// probably the thing to do is to store RRSIG as part of the rrset_rdata that it signs rather than as a separate rrset
	// also, NXT records have some strange behavior at zone cuts that may need to be addressed (see RFC2181 5.3.2, there may be two with the same name)
	// but this is only necessary to implement DNSSEC, because if we don't request DNSSEC (D0 bit in EDNS0) then we don't get DNSSEC records in authority section
	if(cache.contains_record(record.get_name(), record.get_type(), record.get_class())) {
		dout() << "Got non-answer record " << record << " already in cache, no action required";
		return true;
	}
	if(in_bailiwick(record.get_name(), fromaddr)) {
		cache.cache_rrset(record);
		return true;
	}
	// else response was not in bailiwick for this name, will initiate subsidiary query to populate cache
	// there are two reasons for doing cache population queries (given that we don't cache out of bailiwick responses):
		// 1) it improves latency for subsequent queries which are likely to occur (e.g. user is browsing website and may encounter subdomains)
		// 2) NS records from authority tend to be in bailiwick while A/AAAA records from additional tend not to be
			// so what happens is, user asks for x.example.us and we ask cctld.us which give us 'example.us NS ns1.example.net' and out of bailiwick IP addr
			// then query comes for y.example.us and we have no IP addr for ns1.example.net so it can't be used, so we go back to cctld.us, repeat forever
	// what we could do instead is wait until the next query comes and then fetch the IP for the NS, but several problems there:
		// that would mean that the A/AAAA query doesn't happen until the client is waiting, which increases client query response latency;
		// if NS record itself is out of bailiwick then we would never cache it, because the next query goes back to the higher level server and does the same thing; and
		// if seeing the NS record without an IP addr causes a query for the IP addr, that query may want to go to that same NS without an IP addr
			// so we would have to detect that and send *those* queries to the higher level servers, including detecting glueless NS loops and so forth; excessive complexity
	dout() << "Got out-of-bailiwick non-answer record " << record << " not in cache, going to fetch it";
	return false;	
}

void dns_query_init::notify_nx(dns_query &query, const dns_message &response, std::vector< dns_record<cname_rdata> > && cname_chain, const sockaddrunion &fromaddr)
{
	const domain_name &final_name = cname_chain.size() > 0 ? cname_chain.back().rdata.name : query.question().qname().get_name();
	const dns_rrset *soa = response.authority().get_authority_soa(final_name);
	notify_nx(query, std::move(cname_chain), response.header().rcode, soa, fromaddr);
}

void dns_query_init::notify_nx(dns_query &query, std::vector< dns_record<cname_rdata> > &&cnames, dns_rcode_t rcode, const dns_rrset *soa, const sockaddrunion &fromaddr)
{
	const dns_question &q = query.question();
	const domain_name &final_name = cnames.size() > 0 ? cnames.back().rdata.name : q.qname().get_name();
	// SOA could be out of bailiwick if e.g. ns.example.com gives "com" as nearest SOA for foo.example.com
	if(soa != nullptr && soa->record_count() > 0 && soa->get_type() == dns_type_t::SOA && in_bailiwick(soa->get_name(), fromaddr)) {
		if(rcode == dns_rcode_t::NAME_ERROR) {
			dout() << "ncache NXDOMAIN for " << q << " SOA " << *soa;
			cache.ncache_nxdomain(final_name, q.qclass(), soa->get_name(), soa->rrdata->get<soa_rdata>());
		} else {
			dout() << "ncache NODATA for " << q << " SOA " << *soa;
			cache.ncache_nodata(final_name, q.qtype(), q.qclass(), soa->get_name(), soa->rrdata->get<soa_rdata>());
		}
		query.notify(dns_response_nx(rcode, soa, std::move(cnames)));
	} else {
		dout() << "will not ncache because no or out of bailiwick SOA provided: " << q;
		query.notify(dns_response_nx(rcode, nullptr, std::move(cnames)));
	}
}

void dns_query_init::send_client_response(std::function<void(dns_message &&, const edns_options&)> &client, uint16_t id, const dns_question &q, const edns_options &e, dns_response &&r)
{
	// AA has to be true for NAME_ERROR as a result of bugs in older resolvers
	dns_message response(id, true/*qr*/, r.rcode==dns_rcode_t::NAME_ERROR/*aa*/, true/*rd: always true here*/, dns_opcode_t::STANDARD_QUERY, r.rcode, q, e.edns_present());

	// all responses contain the CNAME chain (if any)
	for(dns_record<cname_rdata> &cname : r.cname_chain)
		response.emplace_answer(std::move(cname));
	// also include SIG records and such like if any, or answers to dns_qtype_t::WILDCARD query
	for(dns_rrset &anc : r.ancillary)
		response.emplace_answer(std::move(anc));
	// (not very interested in glue here since we are never authoritative)
	
	if(r.final_answer() != nullptr) {
		response.emplace_answer(*r.final_answer());
	} else if(r.ncache_soa() != nullptr) {
		response.emplace_authority(*r.ncache_soa());
	}
	client(std::move(response), e);
}

void dns_query_init::resolved_cname_chain(dns_response_notifier &notifier, std::vector< dns_record<cname_rdata> > &existing_chain, dns_response &&r)
{
	std::swap(existing_chain, r.cname_chain);
	r.cname_chain.reserve(r.cname_chain.size() + existing_chain.size());
	for(auto &c : existing_chain)
		r.cname_chain.emplace_back(std::move(c));
	notifier(std::move(r));
}

void dns_query_init::ipv6_test()
{
	// test IPv6 support by attempting a query for the 'com' TLD nameservers to the IPv6 root servers
	try {
		domain_name com("com");
		// first try at least connecting a socket, if that fails then no use in going on
		csocket sock(AF_INET6, SOCK_DGRAM);
		ns_track nameservs = get_closest_ns(com, IP_FAMILY::IPV6);
		sockaddrunion addr;
		nameservs.write_next_addr(addr);
		if(addr.s.sa_family != AF_UNSPEC && !is_sock_err(connect(sock.fd(), &addr.s, sizeof(addr.sa6)))) {
			do_query(dns_question(com, dns_type_t::NS, dns_class_t::IN),
							std::bind(&dns_query_init::check_ip_family, this, std::placeholders::_1, IP_FAMILY::IPV6),
							std::move(nameservs),
							0);
		} else {
			dout() << "Could not connect() to IPv6 addr of root server, IPv6 support will not be enabled";
		}
	} catch(const e_check_sock_err &e) {
		eout() << "Error testing IPv6 support: " << e;
	}
}
void dns_query_init::check_ip_family(dns_response &&response, IP_FAMILY family)
{
	// on startup we try a query using only the IPv6 root servers to see if IPv6 is working
	if(response.rcode == dns_rcode_t::DNS_NO_ERROR) {
		dout() << "Address family check succeeded, address family " << family << " enabled";
		use_ip_family |= family;
		if(family == IP_FAMILY::IPV6) {
			// now just make sure IPv4 is working (we could be on the rare machine w/o IPv4)
			domain_name net("net");
			do_query(dns_question(net, dns_type_t::NS, dns_class_t::IN),
								 std::bind(&dns_query_init::check_ip_family, this, std::placeholders::_1, IP_FAMILY::IPV4),
						   get_closest_ns(net, IP_FAMILY::IPV4),
						   0);
		}
	} else {
		dout() << "Address family check failed, address family " << family << " not enabled";
		use_ip_family &= ~family;
	}
}


bool dns_query_init::in_bailiwick(const domain_name &name, const sockaddrunion &fromaddr)
{
	// bailiwick check works as follows: if the server providing data isn't one of the ones we would have asked for that record in the first place, the record is out of bailiwick
	// in particular, you don't want to lookup www.evildoers.com, and evildoers.com NS refers you to 'a.gtld-servers.net' etc. and trust provided IP addr from additional section
	// b/c then you get response from poisoned IP addr claiming to be gtld-servers.net for *this query* which gives "in-baliwick" poisioned additional sec. for GTLD subdomains
		// so IP addr for gtld-servers.net doesn't go into the cache and then response from that IP addr isn't considered in-bailiwick for anything b/c that IP isn't in the cache
		// on the other hand, direct answers always go into the cache because they followed an authoritative chain from the root for the same question
		// which means we don't have to worry about not caching data for www.example.com just because IP addr of ns1.example.com is running a parallel query that isn't complete yet
	
	// TODO: it's probably faster when checking multiple records from a single server to sort them based on domain root
	// and then have this function return true if the server is in bailiwick for that root
	// the common case is that you get a bunch of records with the same TLD from a GTLD server
		// and everything under the TLD is in bailiwick but the records all have different names (e.g. ns[1-N].example.com)

	if(is_key_name(name)) return false; // if configured as a snow resolver, key names are never in bailiwick from internet nameservers
	// first check if there is a forwarder for name, if so then fromaddr must be an address for that forwarder
	const std::vector<sockaddrunion> *forwarder = forwarders.get_forwarder(name);
	if(forwarder != nullptr) {
		for(const sockaddrunion &a : *forwarder)
			if(fromaddr == a) {
				return true;
			}
		dout() << fromaddr << " is not a forwarder for " << name;
		return false;
	}
	// now check all nameservers with cached addrs which are higher in the hierarchy for specified name, and checks if any of them is fromaddr
	return cache.ns_in_bailiwick(name, fromaddr);
}

void dns_query_init::cleanup_query(size_t remove_index)
{
	// queries.back() is about to have its index changed to remove_index
	if(queries.back() != nullptr)
		queries.back()->set_index(remove_index);
	if(queries[remove_index] != nullptr) {
		queries[remove_index]->set_index(SIZE_MAX);
		auto it = query_map.find(queries[remove_index]->question());
		if(it != query_map.end() && it->second.lock() == queries[remove_index])
			query_map.erase(it);
	}
	queries.set_fd(remove_index, INVALID_SOCKET); // dns_socket will close, pollvector should not
}

void dns_query_init::read_static_records()
{
	try {
		cache.read_record_file(sdns::conf[sdns::ROOT_HINTS_FILE].c_str());
		cache.read_record_file(sdns::conf[sdns::STATIC_RECORDS_FILE].c_str());
	} catch(const e_invalid_input &e) {
		eout() << "Error reading static records file, this may cause name resolution failures: " << e;
		// try again later, maybe user will fix it
		timers.add(300, std::bind(&dns_query_init::reread_static_records, this));
	}
	// add static entries for localhost
	ttlexp exp;
	exp.ttl = sdns::conf[sdns::MAX_TTL];
	domain_name localhost("localhost");
	rrset_rdata<a_rdata> ip4_localhost(dns_type_t::A, dns_class_t::IN, exp, a_rdata("127.0.0.1"));
	rrset_rdata<aaaa_rdata> ip6_localhost(dns_type_t::AAAA, dns_class_t::IN, exp, aaaa_rdata("::1"));
	rrset_rdata<ptr_rdata> localhost_ptr(dns_type_t::PTR, dns_class_t::IN, exp, ptr_rdata(localhost));
	cache.cache_rrset_static(localhost, &ip4_localhost);
	cache.cache_rrset_static(localhost, &ip6_localhost);
	cache.cache_rrset_static(domain_name("1.0.0.127.in-addr.arpa"), &localhost_ptr);
	cache.cache_rrset_static(domain_name("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"), &localhost_ptr);
}

void dns_query_init::reread_static_records()
{
	cache.clear_static_records();
	read_static_records();
	forwarders.clear();
	forwarders.configure_forwarders();
}

