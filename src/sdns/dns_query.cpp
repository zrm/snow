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

#include "dns_query.h"
#include "dns_response.h"
#include "eventloop.h"
#include "../common/common.h"
#include "../common/pbind.h"

dns_query_init *dns_query::qinit;
const std::function<void(size_t,pvevent,sock_err)> *dns_query::query_socket_event_function;
pollvector< std::shared_ptr<dns_query> >* dns_query::queries_p(nullptr);

void dns_response_notifier::operator()(dns_response &&r) {
	if(fns != nullptr) {
		if(fns->size() > 0) {
			// create a copy of r to move to all but the last notifier, then move the original to the last one
			for(size_t i=0; i+1 < fns->size(); ++i) {
				dout() << "exec dns_response_notifier " << i;
				(*fns)[i](std::move(*r.clone()));
			}
			dout() << "exec dns_response_notifier " << (fns->size()-1);
			fns->back()(std::move(r));
			fns->clear();
		} else {
			dout() << "[NOOP: fns->size() == 0]";
		}
	} else {
		dout() << "[NOOP: fns == nullptr]";
	}
}

// when a query is sent and times out, it retries to next NS (using same socket type) after retry timeout
// if there is no further NS, and the outstanding NS lookup count is also zero, set a destroy timer to exec the notifier with SERVFAIL if nothing has come in
	// if there is outstanding NS request, wait for it to succeed or fail, then decrement outstanding count and do next query if possible
// when doing a query retry, existing query's socket is moved to new query to wait for slow response and existing query gets new sock to do query retry
	// this is so that the primary/active query (which other things may point to) stays the most recent one and thus the last to time out
	// each query gets shared_ptr to vector containing both as sister queries
	// if any query is successfully answered, that is the answer and every sister query is marked defunct
void dns_query::send_query()
{
	sockaddrunion ns_addr;
	nameservs.write_next_addr(ns_addr);
	if(ns_addr.s.sa_family != AF_UNSPEC) {
		send_query(sdns::conf[sdns::QUERY_RETRY_MS], &ns_addr);
	} else if(flags[PRIMARY] == false) {
		dout() << "send_query() marked query as defunct because it was a retry of a retry";
		mark_defunct();
	} else if(nameservs.queries_pending()){
		dout() << "Requested to send query but still waiting on nameserver addr queries: query will be pending with status AWAIT_NS_ADDR";
		q_status = dns_query::AWAIT_NS_ADDR;
	} else if(sister_queries != nullptr && sister_queries->size() > 1) {
		dout() << "send_query() with no nameservers present or expected, scheduling query SERVFAIL in two seconds if no sister queries succeed";
		qinit->add_timer(2, PBIND(&dns_query::timeout_destroy, queries()[index]));
	} else {
		dout() << "SERVFAIL: send_query has no nameservs remaining or expected";
		if(q_status != dns_query::DEFUNCT)
			notify(dns_response_error(dns_rcode_t::SERVFAIL));
		terminate();
	}
}



void dns_query::send_query(unsigned timeout_ms, const sockaddrunion *ns_addr)
{
	nbo_outgoing_id = getrand<uint16_t>();
	dns_message outgoing(nbo_outgoing_id, false/*qr*/, false/*aa*/, nameservs.is_forwarder()/*rd*/, dns_opcode_t::STANDARD_QUERY, dns_rcode_t::DNS_NO_ERROR, q, flags[EDNS_OPT] || flags[EDNS_TRUNC]);
	sockaddrunion ns;
	try {
		if(ns_addr != nullptr) {
			sock->rebind(ns_addr->s.sa_family);
			sock->setopt_nonblock();
			queries().set_fd(index, sock->fd());
			sock->connect(*ns_addr);
		} else {
			sock->getpeername(ns);
			ns_addr = &ns;
		}
		dout() << "sending query to " << *ns_addr << ": " << outgoing;
		q_status = dns_query::AWAIT_RESPONSE;
		if(sock->send_dnsmsg(outgoing) > 0)
			queries().add_events(index, pvevent::read);
		else 
			queries().add_events(index, pvevent::write);
		timestamp = std::chrono::steady_clock::now();
		++query_retry;
		qinit->add_timer(timestamp + std::chrono::milliseconds(timeout_ms), PBIND(&dns_query::timeout_retry, queries()[index], query_retry));
	} catch(const check_err_exception &e) {
		dout() << "send_query() FAIL for " << q << " to NS " << *ns_addr << ": " << e;
		// try again, maybe a different NS will be better, or we'll run out and the query will die
		// recursion bit is to prevent possible stack overflow: if send fails and recursion is true then we do not call send_query but we set recursion=false
		// this causes the top level caller to call send_query again, until it either succeeds or runs out of nameservers and stops
		static bool recursion = false;
		while(recursion == false) {
			recursion = true;
			send_query();
		}
		recursion = false;
	}
}

void dns_query::retry_query()
{
	if(flags[PRIMARY] == false && flags[EDNS_TRUNC] == false) {
		// already-retried query has explicitly failed and already requested retry (and not because of EDNS failure that TCP might fix), so just remove it
		mark_defunct();
		return;		
	}
	// otherwise the existing socket is moved to a new dns_query to continue to wait while a new query is sent to the next NS using this dns_query object,
		// so that things with a weak_ptr to the dns_query (e.g. NS addr lookup) will continue to point to the primary
	std::unique_ptr<dns_socket> s(sock.release());
	sock.reset(s->get_new());
	queries().set_fd(index, sock->fd());
	csocket::sock_t fd = s->fd();
	queries().emplace_back(fd, pvevent::read, *query_socket_event_function, std::make_shared<dns_query>(s.release(), notifier.share(), q, queries().size(), ns_track(nameservs.is_forwarder()), query_depth));
	dns_query& back = *queries().back();
	back.flags = flags;
	back.flags[PRIMARY] = false;
	back.timestamp = timestamp;
	if(sister_queries == nullptr) {
		sister_queries.reset(new sister_query_set());
		sister_queries->insert(queries()[index]);
	}
	sister_queries->insert(queries().back());
	back.sister_queries = sister_queries;
	std::swap(nbo_outgoing_id, back.nbo_outgoing_id);
	if(flags[EDNS_TRUNC] == false) {
		send_query();
	} else {
		// EDNS retry timed out after non-EDNS query got truncated response; broken firewall may block EDNS so retry to same NS as previous query but with TCP
		retry_tcp(back.sock.get());
	}
}


void dns_query::resend_trunc()
{
	if(sock->is_tcp()) {
		dout() << "SERVFAIL: Got truncated response using TCP";
		notify(dns_response_error(dns_rcode_t::SERVFAIL));
	} else if(flags[EDNS_TRUNC] == false && flags[EDNS_OPT] == false && sdns::conf[sdns::MAX_UDP_SIZE] > 512) {
		flags[EDNS_TRUNC] = true;
		dout() << "retrying truncated query using EDNS to specify larger UDP message size";
		// allow twice duration of actual truncated query duration for EDNS query retry to succeed before retrying with TCP
		// (this allows faster TCP retry in case of firewall that drops EDNS)
		send_query(query_duration()*2, nullptr);
	} else if(flags[PRIMARY]) {
		dout() << "query was truncated even with EDNS, retrying with TCP";
		retry_tcp(sock.get());
	} else {
		dout() << "EDNS query had already timed out and retried with TCP when truncated response was received, marking EDNS query defunct";
		mark_defunct();
	}
}

void dns_query::retry_tcp(dns_socket *ns_sock)
{
	flags[EDNS_TRUNC] = false;
	sockaddrunion ns_addr;
	ns_sock->getpeername(ns_addr);
	queries().set_fd(index, INVALID_SOCKET);
	sock.reset(new dns_tcp_socket());
	send_query(sdns::conf[sdns::QUERY_RETRY_MS], &ns_addr);
}


void dns_query::timeout_retry(uint16_t retry_count)
{
	// if retry count has changed then something triggered a retry before timeout and the new retry will have its own timeout
	if(q_status == dns_query::AWAIT_RESPONSE && query_retry == retry_count) {
		// this is the short timeout, if it expires then we send a retry but keep waiting in case response is just slow
		retry_query();
	}
}

void dns_query::timeout_destroy()
{
	if(q_status != dns_query::DEFUNCT)
		notify(dns_response_error(dns_rcode_t::SERVFAIL));
	terminate();
}

void dns_query::provide_ns_ipaddr(dns_response &&r)
{
	nameservs.queries_pending_dec();
	// can't do anything with NXDOMAIN nameservers etc. other than hope alternative nameserver is correct or wait for timeout
	if(r.rcode != dns_rcode_t::DNS_NO_ERROR || r.nodata()) {
		dout() << "provide_ns_ipaddr: NXDOMAIN/NODATA/error, no address obtained from NS addr query in service of " << q.qname();
		if(!nameservs.queries_pending() && q_status == AWAIT_NS_ADDR)
			qinit->add_timer(2, PBIND(&dns_query::timeout_destroy, queries()[index]));
	} else if(q_status == AWAIT_NS_ADDR) {
		dout() << "Got NS addr for query " << q;
		nameservs.add_ns(r.final_answer()->rrdata.get());
		send_query();
	} else {
		dout() << "Got NS addr for query " << q << " but status was not interested";
		// some other ns query resolved first, still add in case of retries
		nameservs.add_ns(r.final_answer()->rrdata.get());
	}
}

void dns_query::mark_defunct() {
	if(index != SIZE_MAX) {
		if(sister_queries != nullptr)
			sister_queries->erase(queries()[index]);
		queries().mark_defunct(index);
	}
	q_status = dns_query::DEFUNCT;
}

void dns_query::terminate() {
	if(sister_queries == nullptr) {
		mark_defunct();
	} else {
		// swap set so that mark_defunct() doesn't invalidate iterator by removing query from sister_queries
		sister_query_set sqset;
		std::swap(sqset, *sister_queries);
		for(auto &sq : sqset)
			if(auto sqptr = sq.lock())
				sqptr->mark_defunct();
	}
}

