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

#include "ns_track.h"
#include "configuration.h"
#include "../common/directory.h"
#include <algorithm>
#include <fstream>

ns_track::nameserver::nameserver(const rrset_data &rr)
{
	ns_addr template_addr;
	memset(&template_addr.su, 0, sizeof(template_addr.su));
	if(rr.get_type() == dns_type_t::A) {
		template_addr.su.sa.sin_family = AF_INET;
		template_addr.su.sa.sin_port = htons(53);
		addrs = std::vector<ns_addr>(rr.record_count(), template_addr); // fill constructor
		for(size_t i=0; i < rr.record_count(); ++i)
			addrs[i].su.sa.sin_addr.s_addr = rr.get<a_rdata>().rdata[i].address;
	} else if(rr.get_type() == dns_type_t::AAAA) {
		template_addr.su.sa6.sin6_family = AF_INET6;
		template_addr.su.sa6.sin6_port = htons(53);
		addrs = std::vector<ns_addr>(rr.record_count(), template_addr); // fill constructor
		for(size_t i=0; i < rr.record_count(); ++i)
			memcpy(addrs[i].su.sa6.sin6_addr.s6_addr, rr.get<aaaa_rdata>().rdata[i].address, INET6_ADDRLEN);
	}
}

void ns_track::add_ns(const rrset_data * addrs)
{
	if(addrs == nullptr || addrs->record_count() == 0) {
		dout() << "ns_track::add_ns with no address records, ns will not be added";
	} else if(addrs->get_type() == dns_type_t::A || addrs->get_type() == dns_type_t::AAAA) {
		nameservers.emplace_back(*addrs);
	} else {
		dout() << "ns_track::add_ns(" << *addrs << ") with non-IP record type, will not be added";
	}
}

void ns_track::write_next_addr(sockaddrunion &address)
{
	while(nameservers.size() > 0) {
		if(next >= nameservers.size())
			next = 0;
		if(nameservers[next].addrs.size() == 0) {
			nameservers.erase(nameservers.begin() + next);
			continue;
		}
		memcpy(&address, &nameservers[next].addrs.back().su, sizeof(sockaddrunion));
		dout() << "Providing NS at " << address;
		if(nameservers[next].addrs.back().retries == 0)
			nameservers[next].addrs.pop_back();
		else
			nameservers[next].addrs.back().retries--;
		if(nameservers[next].addrs.size() == 0) {
			nameservers.erase(nameservers.begin() + next);
		} else {
			++next;
		}
		return;
	}
	// no addrs left
	memset(&address, 0, sizeof(address));
	address.s.sa_family = AF_UNSPEC;
}

void ns_track::randomize_order()
{
	std::random_shuffle(nameservers.begin(), nameservers.end());
	for(auto &s : nameservers)
		std::random_shuffle(s.addrs.begin(), s.addrs.end());
}

const std::vector<sockaddrunion> * dns_forwarder_map::get_forwarder(const domain_name &name) {
	unsigned depth = name.num_labels();
	if(depth > depths.size()) depth = depths.size();
	while(depth > 0) {
		auto it = depths[depth-1].forwarders.find(name.get_root(depth).name);
		if(it != depths[depth-1].forwarders.end())
			return &it->second.addrs;
		--depth;
	}
	if(root_forwarder.addrs.size()) return &root_forwarder.addrs;
	return nullptr;
}

void dns_forwarder_map::configure_forwarders()
{
	directory forwarders;
	try {
		forwarders = directory(sdns::conf[sdns::DNS_FORWARDERS_DIR]);
	} catch(const check_err_exception &e) {
		dout() << "Opening forwarders directory: " << e;
		return;
	}
	for(const std::string & filename : forwarders.files) {
		if(filename.size() < 1 || filename[0] != '@') continue;
		std::string filepath = forwarders.dirname + '/' + filename;
		dout() << "Got prospective forwarder file: " << filepath;
		domain_name forward_root;
		try {
			forward_root = domain_name(filename.substr(1));
		} catch(const e_invalid_input& e) {
			eout() << "Forwarder root " << filename.substr(1) << " did not parse as domain name from " << filepath << ": " << e;
			abort();
		}
		std::ifstream file(filepath);
		std::string line;
		unsigned nlabels = forward_root.num_labels();
		while(depths.size() <= nlabels) depths.emplace_back();
		forwarder & fwd = (nlabels==0) ? root_forwarder : depths[nlabels-1].forwarders[forward_root];
		while(getline(file, line)) {
			if(line.size() < 1 || line[0] == ';') continue;
			size_t pos=0;
			while(pos < line.size()) {
				std::string addr = next_word(line, &pos);
				if(addr.size() == 0) continue;
				in_port_t port = htons(53);
				size_t ppos = addr.find_last_of('#'); // check for alt port
				if(ppos != std::string::npos) {
					try {
						unsigned long prt = stoul(addr.substr(ppos+1));
						if(prt == 0 || prt > UINT16_MAX) throw std::exception();
						port = htons(prt);
					} catch(const std::exception &) {
						eout() << filepath << ": " << line << ": invalid port \"" << addr.substr(ppos+1) << '\"';
						abort();
					}
					addr.erase(ppos);
				}
				try {
					sockaddrunion su(addr, port);
					fwd.addrs.emplace_back(su);
					dout() << "adding forwarder for " << forward_root << ": " << su;
				} catch(const e_invalid_input&) {
					// TODO: allow forwarders to be key names or any name with a static A/AAAA record
					eout() << filepath << ": forwarder is not an address in a supported address family (" << addr << ")";
					abort();
				}
			}
		}
	}
}

