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

#ifndef DNS_QUERY_INIT_H
#define DNS_QUERY_INIT_H
#include<memory>
#include<map>
#include<functional>
#include"../common/network.h"
#include"ns_track.h"
#include"cache.h"

class dns_query;
class dns_response;
class dns_response_notifier;
template<class T> class pollvector;
class pvevent;
class eventloop;
class dns_query_init
{
	pollvector< std::shared_ptr<dns_query> > & queries;
	timer_queue & timers;
	dns_cache cache;
	std::function<void(size_t,pvevent,sock_err)> query_socket_event_function;
	dns_forwarder_map forwarders;
	std::map<dns_question, std::weak_ptr<dns_query>, dns_question::ci_less> query_map;
	unsigned use_ip_family;
	csocket snow_query_socket;
	uint64_t snow_query_serial;
	struct snow_q {
		dns_qtype_t qtype;
		std::function<void(dns_response&&)> notifier;
		snow_q(dns_qtype_t qt, std::function<void(dns_response&&)>&& notif) : qtype(qt), notifier(std::move(notif)) {}
	};
	struct snow_query {
		uint64_t serial;
		std::vector<snow_q> notifiers;
		snow_query(uint64_t ser) : serial(ser) {}
	};
	std::map<domain_name, snow_query> snow_queries;

	class deferred_queries
	{
		std::vector<dns_question> queries;
	public:
		void add(const dns_rrset &record) {
			queries.emplace_back(dns_question(record.get_name(), record.get_type(), record.get_class()));
		}
		void exec(dns_query_init * qinit, uint16_t depth) {
			for(dns_question &q : queries)
				qinit->do_cache_population_query(q, depth);
			queries.clear();
		}
	};
	
	ns_track get_closest_ns(const domain_name &name, unsigned family_mask = 0);
	void process_answer(const dns_message &, const sockaddrunion &fromaddr, dns_query &, deferred_queries &);
	void process_referral(const dns_message &, dns_query &);
	void do_cache_population_query(const dns_question &q, uint16_t depth);
	void do_cache_query(const dns_question &q, std::function<void(dns_response&&)> &&n, uint16_t recursion_depth); // check cache, initiate query if necessary
	dns_query * do_query(const dns_question &q, std::function<void(dns_response&&)> &&n, ns_track &&ns, uint16_t recursion_depth); // initiate outgoing query w/o regard to cache
	void do_snow_query(const dns_question &q, std::function<void(dns_response&&)> &&notifier, size_t depth);
	void send_snow_query(const domain_name & qname, uint32_t addr);
	void snow_query_retry(const domain_name & qname, uint64_t serial, size_t retry);
	void process_snow_response(const domain_name &name, uint32_t addr);
	void notify_nx(dns_query &query, const dns_message &response, std::vector< dns_record<cname_rdata> > && cname_chain, const sockaddrunion &fromaddr);
	void notify_nx(dns_query &query, std::vector< dns_record<cname_rdata> > &&cnames, dns_rcode_t rc, const dns_rrset *soa_rrset, const sockaddrunion &fromaddr);
	void send_client_response(std::function<void(dns_message &&, const edns_options&)> &client, uint16_t id, const dns_question &q, const edns_options &, dns_response &&);
	void resolved_cname_chain(dns_response_notifier &, std::vector< dns_record<cname_rdata> > &existing_chain, dns_response &&);
	void check_ip_family(dns_response &&response, IP_FAMILY family);
	// get_valid_cname_chain(): return CNAME chain such that each returned CNAME record (but not necessarily its final target) is in bailiwick for 'fromaddr'
	std::vector< dns_record<cname_rdata> > get_valid_cname_chain(const dns_question &question, const dns_rr_section &answer, const sockaddrunion &fromaddr);
	bool in_bailiwick(const domain_name &name, const sockaddrunion &fromaddr);
	void cache_answer_record(const dns_rrset &rrset);
	bool cache_other_record(const dns_rrset &rrset, const sockaddrunion &fromaddr);
public:
	dns_query_init(pollvector< std::shared_ptr<dns_query> > & queriesref, timer_queue & timers_ref, void(eventloop::*eventfn)(size_t, pvevent, sock_err), eventloop * eventlp);
	void snow_socket_error();
	void snow_socket_event();
	void process_query(const dns_message &msg, std::function<void(dns_message &&, const edns_options&)> &&client_sender);
	void process_response(const dns_message &msg, const sockaddrunion &fromaddr, dns_query &);
	void cleanup_query(size_t remove_index);
	void read_static_records();
	void reread_static_records();
	csocket::sock_t snow_sock_fd() { return snow_query_socket.fd(); }
	void ipv6_test();
	template<class...Args> void add_timer(Args&&... args) { timers.add(std::forward<Args>(args)...); }
};



#endif // DNS_QUERY_INIT_H
