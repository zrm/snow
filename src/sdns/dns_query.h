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

#ifndef DNS_QUERY_H
#define DNS_QUERY_H
#include "../common/network.h"
#include "dns_message.h"
#include "dns_response.h"
#include "dns_socket.h"
#include "ns_track.h"
#include "../common/pollvector.h"

// TODO: (after DNSSEC validation is implemented):
	// validation mode: operate semi-recursively against an upstream cache
	// send all queries to the cache necessary to get the DNSSEC records required to validate the chain from the root
	// that way you get most of the performance benefits of the cache but can still do DNSSEC validation locally
// DNSSEC: NLnet has BSD licensed DNSSEC library (LDNS)

class dns_response_notifier
{
	typedef std::vector< std::function<void(dns_response &&)> > fn_vec;
	std::shared_ptr<fn_vec> fns;
	dns_response_notifier(const std::function<void(dns_response &&)> &f) : fns(std::make_shared<fn_vec>()) { fns->emplace_back(f); }
	dns_response_notifier(const std::shared_ptr<fn_vec>& f) : fns(f) {}
	dns_response_notifier(std::shared_ptr<fn_vec>&& f) : fns(std::move(f)) {}
public:
	dns_response_notifier(std::function<void(dns_response &&)> &&f) : fns(std::make_shared<fn_vec>()) { fns->emplace_back(std::move(f)); }
	void operator()(dns_response &&r);
	dns_response_notifier release() {
		dns_response_notifier rv(std::move(fns));
		fns = nullptr;
		return std::move(rv);
	}
	dns_response_notifier share() {	return dns_response_notifier(fns); }
	void add_notifier(std::function<void(dns_response &&)>&& f) {
		if(fns==nullptr) fns=std::make_shared<fn_vec>();
		fns->emplace_back(std::move(f));
	}
};


class dns_query_init;
class dns_query
{
	static dns_query_init *qinit;
	static const std::function<void(size_t,pvevent,sock_err)> *query_socket_event_function; // ptr to eventloop::query_socket_event()
	std::unique_ptr<dns_socket> sock; // socket for DNS server we're waiting for a response from
	const dns_question q;
	ns_track nameservs; // nameservs to be used for this query
	size_t index;
	std::chrono::time_point<std::chrono::steady_clock> timestamp;
	// query_retry serial: lets timeouts know when they're not wanted; any increment must set a new timeout timer for the new value (timeout_retry()/timeout_destroy())
	size_t query_retry; 
	uint16_t nbo_outgoing_id; // id sent with outgoing question, response must match or be discarded
	uint16_t query_depth; // inhibit recursion/resource exhaustion
	dns_response_notifier notifier;
	typedef std::set< std::weak_ptr<dns_query>, std::owner_less< std::weak_ptr<dns_query> > > sister_query_set;
	std::shared_ptr<sister_query_set> sister_queries;
	enum flags { PRIMARY, // query is primary/original of sister query set
				 EDNS_OPT, // EDNS is used for some specific option (e.g. to set D0 for DNSSEC)
				 EDNS_TRUNC // non-EDNS response was truncated and query has been retried with EDNS to specify larger UDP buf
			   };
	std::bitset<32> flags;
	enum QUERY_STATUS {
		AWAIT_RESPONSE, // query has been sent, waiting for response (if timeout expires then query is retried or deleted)
		AWAIT_NS_ADDR, // query cannot be sent pending query for nameserver IP addr, query will be sent after NS is/are resolved (or deleted if they all fail)
		DEFUNCT // query response has been received or timed out and query is pending deletion
	};
	QUERY_STATUS q_status;
	void mark_defunct();
	void timeout_retry(uint16_t retry_count);
	void timeout_destroy();
	void send_query(unsigned timeout_ms, const sockaddrunion *ns_addr);
	void retry_tcp(dns_socket *ns_sock);
	void handle_write_wouldblock(size_t index);
	// terminate when: a) primary exceeds timeout_destroy w/o remaining retry, b) ANY sister query receives accepted final response, c) notifier is released
		// b and c are respectively satisfied by notify() and release_notifier() which each call terminate()
	void terminate();
	static pollvector< std::shared_ptr<dns_query> >* queries_p;
	static pollvector< std::shared_ptr<dns_query> >& queries() { return *queries_p; } // de-uglify "(*queries)[x]" into at least "queries()[x]"
public:
	static void set_pointers(dns_query_init *i, const std::function<void(size_t,pvevent,sock_err)> *qsef, pollvector< std::shared_ptr<dns_query> >* q)
		{ qinit = i; query_socket_event_function = qsef; queries_p = q;}
	dns_query(dns_socket *s, dns_response_notifier &&n, const dns_question &dq, size_t idx, ns_track &&ns, uint16_t qd = 0)
		: sock(s), q(dq), nameservs(std::move(ns)), index(idx), query_retry(0),
		  nbo_outgoing_id(getrand<uint16_t>()), query_depth(qd), notifier(n.release()), q_status(AWAIT_RESPONSE) { flags[PRIMARY] = true; }
	// send_query vs. retry_query vs. resend_trunc:
		// send_query uses the socket in the query to connect to the next NS with a new query id; an outstanding query response if any will not be received
		// retry_query copies the existing query socket and ID into a new query to continue to wait for a response, then calls send_query to try the next NS
		// resend_trunc resends to the same NS using EDNS to specify larger UDP msg, or using TCP if EDNS was already used
	void send_query();
	void retry_query();
	void resend_trunc();
	void resend_tcp() { retry_tcp(sock.get()); }
	void provide_ns_ipaddr(dns_response &&r);
	bool edns_trunc_retry() { return flags[EDNS_TRUNC]; }
	bool send_buffered() { return sock->send(); }
	dns_message recv_dnsmsg() { return sock->recv_dnsmsg(); }
	uint64_t query_duration() {
		return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - timestamp).count();
	}
	sockaddrunion& getpeername(sockaddrunion &su) { return sock->getpeername(su); }
	uint16_t id() { return nbo_outgoing_id; }
	const dns_question& question() { return q; }
	uint16_t depth() { return query_depth; }
	void set_index(size_t idx) { index = idx; }
	void add_notifier(std::function<void(dns_response &&)>&& f) { notifier.add_notifier(std::move(f)); }	
	bool await_response() const {
		if(q_status == AWAIT_RESPONSE) return true;
		dout() << "Got DNS response against incorrect query status: " << q_status;
		return false;
	}
	bool is_defunct() const { return q_status == DEFUNCT; }
	void notify(dns_response &&r) { notifier(std::move(r)); terminate(); }
	dns_response_notifier release_notifier() { terminate(); return notifier.release(); }
	bool is_forwarder() { return nameservs.is_forwarder(); }
	std::weak_ptr<dns_query> get_ptr() { return queries()[index]; }
	~dns_query() {}
};



#endif // DNS_QUERY_H
