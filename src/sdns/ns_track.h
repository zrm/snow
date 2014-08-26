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

#ifndef NS_TRACK_H
#define NS_TRACK_H
#include <vector>
#include <fstream>
#include <string>
#include <sstream>

#include "../sdns/dns_message.h"
#include "../sdns/configuration.h"
#include "../common/network.h"

class ns_track
{
	struct nameserver {
		struct ns_addr {
			sockaddrunion su;
			unsigned retries;
			ns_addr(const sockaddrunion &s) : su(s), retries(sdns::conf[sdns::RETRIES_PER_NAMESERVER_ADDR]) {}
			ns_addr() : retries(sdns::conf[sdns::RETRIES_PER_NAMESERVER_ADDR]) {}
		};
		std::vector<ns_addr> addrs;
		nameserver(const rrset_data &rr);
		nameserver(const sockaddrunion &address) {
			addrs.emplace_back(address);
		}
		nameserver() {}
	};
	std::vector<nameserver> nameservers;
	size_t next;
	size_t num_queries_pending; // pending outgoing queries for NS IP addrs not yet received
	bool forwarder; 
public:
	ns_track(bool fwdr) : next(0), num_queries_pending(0), forwarder(fwdr) {}
	void add_ns(const rrset_data *addrs);
	size_t add_ns() {
		nameservers.emplace_back();
		return nameservers.size()-1;
	}
	void add_ns_addr(size_t index, const sockaddrunion & addr) {
		nameservers[index].addrs.emplace_back(addr);
	}

	void re_add_ns(const sockaddrunion &addr) {
		nameservers.emplace_back(addr);
	}
	void write_next_addr(sockaddrunion &address);
	void randomize_order();
	void queries_pending_inc() { ++num_queries_pending; }
	void queries_pending_dec() { --num_queries_pending; }
	bool queries_pending() { return num_queries_pending > 0; }
	bool is_forwarder() { return forwarder; }
};

class dns_forwarder_map
{
public:
	struct forwarder {
		std::vector<sockaddrunion> addrs;
	};
	const std::vector<sockaddrunion> * get_forwarder(const domain_name &name);
	void configure_forwarders();
	void clear() { root_forwarder.addrs.clear(); depths.clear(); }
private:
	struct forwarder_depth {
		std::unordered_map< domain_name, forwarder > forwarders;
	};
	std::vector<forwarder_depth> depths; 
	forwarder root_forwarder;
};

#endif // NS_TRACK_H
