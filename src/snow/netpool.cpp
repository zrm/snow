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

#include "netpool.h"
#include "configuration.h"
#include "../common/network.h"

address_pool::address_pool(uint32_t natpool_network, uint32_t natpool_netmask) {
	uint32_t hbo_start = ntohl(natpool_network) + 1;
	uint32_t hbo_end = ntohl(natpool_network) + ntohl(~natpool_netmask) - 1;
	pool.insert(address_range(hbo_start, hbo_end));
	dout() << "address pool initialized from " << ss_ipaddr(htonl(hbo_start)) << " to " << ss_ipaddr(htonl(hbo_end));
}
// takes a new address out of the pool and returns it (host byte order)
uint32_t address_pool::get_address() {
	if(pool.size()==0)
		throw e_resource_exhaustion("address_pool::get_address()");
	auto it = pool.begin();
	uint32_t nbo_addr = htonl(it->start);
	++it->start;
	if(it->start > it->last)
		pool.erase(it);
	dout() << "address pool allocated address " << ss_ipaddr(nbo_addr);
	return nbo_addr;
}
void address_pool::reinsert_address(uint32_t addr) {
	dout() << "Reinserting address pool address " << ss_ipaddr(addr);
	addr = ntohl(addr);
	auto after = pool.lower_bound(addr), before = after;
	if(pool.size() > 0 && after != pool.end() && after->start <= addr) {
		dout() << "Attempted to reinsert address already present in address pool: " << ss_ipaddr(htonl(addr));
		return;
	}
	int action = 0;
	if(after != pool.end() && after->start - 1 == addr)
		action |= 1;
	if(after != pool.begin() && (--before)->last + 1 == addr)
		action |= 2;
	switch(action)
	{
	case 0:
		pool.insert(after, addr);
		break;
	case 1:
		after->start = addr;
		break;
	case 2:
		before->last = addr;
		break;
	case 3:
		after->start = before->start;
		pool.erase(before);
		break;
	}
}
void address_pool::remove_address(uint32_t addr) {
	addr = ntohl(addr);
	auto it = pool.lower_bound(addr);
	if(pool.size() == 0 || it == pool.end() || it->start > addr) {
		dout() << "Requested to remove address from pool that was not in pool: " << ss_ipaddr(htonl(addr));
		return;
	}
	dout() << "Removing address " << ss_ipaddr(htonl(addr)) << " from address pool";
	if(it->last == addr) {
		--it->last;
		if(it->start > it->last)
			pool.erase(it);
	} else {
		if(it->start != addr) {
			// split range
			pool.insert(it, address_range(it->start, addr - 1));
		}
		it->start = addr + 1;
	}
}


void address_assignment_map::parse_lease_file(const std::string& fn, uint32_t flags)
{
	std::ifstream infile(fn.c_str(), std::ios::in);
	if(!infile.is_open())
		return;
	std::string str;
	for(size_t linenum = 1; std::getline(infile, str); ++linenum)
	{
		if(str.size()==0 || str[0]=='#')
			continue;
		size_t delim = str.find_first_of(',');
		if(delim == std::string::npos) {
			eout() << "Error on line " << linenum << " of " << fn;
			continue;
		}
		hashkey fingerprint(str.substr(0, delim));
		if(!fingerprint.initialized()) {
			eout() << "Error on line " << linenum << " of " << fn << " : invalid keystring " << str.substr(0,delim);
			continue;
		}
		in_addr addr;
		if(inet_pton(AF_INET, str.substr(delim+1).c_str(), &addr) <= 0) {
			eout() << "Error on line " << linenum << " of " << fn << " : invalid IPv4 addr " << str.substr(delim+1);
			continue;
		}
		dout() << "Got existing natpool address lease: " << ss_ipaddr(addr.s_addr) << " for " << fingerprint;
		assignments.emplace(fingerprint, assignment(addr.s_addr, flags));
		defunct_assignments.emplace(addr.s_addr, std::move(fingerprint));
	}
	infile.close();
}

address_assignment_map::address_assignment_map(worker_thread *io_thread) : io(io_thread)
{
	parse_lease_file(snow::conf[snow::PERMANENT_ADDRESS_ASSIGNMENT_FILE], assignment::PERMANENT);
	parse_lease_file(snow::conf[snow::ADDRESS_ASSIGNMENT_FILE], assignment::GRACE_PERIOD);
}

uint32_t address_assignment_map::assign_address(const hashkey &fingerprint)
{
	auto it = assignments.find(fingerprint);
	if(it == assignments.end()) {
		uint32_t nbo_addr = natpool.get_address();
		assignments.emplace(fingerprint, nbo_addr);
		save_to_disk();
		return nbo_addr;
	}
	it->second.flags |= assignment::ACTIVE;
	return it->second.nbo_nat_ip;
}

void address_assignment_map::unassign_address(const hashkey &fingerprint)
{
	auto it = assignments.find(fingerprint);
	if(it != assignments.end()) {
		it->second.flags &= ~assignment::ACTIVE;
		it->second.flags |= assignment::GRACE_PERIOD;
		defunct_assignments.emplace(it->second.nbo_nat_ip, fingerprint);
	} else {
		dout() << "BUG: peer " << fingerprint << " not found in address assignments when unassignment attempted";
	}
}

const hashkey& address_assignment_map::get_defunct_assignment(uint32_t nbo_nat_ip)
{
	auto defunct_it = defunct_assignments.find(nbo_nat_ip);
	if(defunct_it != defunct_assignments.end()) {
		auto assignment_it = assignments.find(defunct_it->second);
		if(assignment_it != assignments.end())
			assignment_it->second.flags |= assignment::GRACE_PERIOD;
		return defunct_it->second;
	}
	throw e_not_found("address_assignment_map::get_defunct_assignment()");
}

uint32_t address_assignment_map::operator[](const hashkey &fingerprint)
{
	auto it = assignments.find(fingerprint);
	if(it == assignments.end())
		return 0;
	// if anything wants to know this then give it another grace period
	it->second.flags |= assignment::GRACE_PERIOD;
	return it->second.nbo_nat_ip;
}

void address_assignment_map::set_natpool(address_pool&& nat, uint32_t natpool_network, uint32_t natpool_netmask)
{
	natpool = std::move(nat);
	// validate existing and remove from natpool
	for(auto it = defunct_assignments.begin(); it != defunct_assignments.end();) {
		if((it->first & natpool_netmask) != natpool_network) {
			auto assignment_it = assignments.find(it->second);
			if(assignment_it != assignments.end() && assignment_it->second.nbo_nat_ip == it->first)
				assignments.erase(assignment_it);
			iout() << "Rejected address assignment as not in natpool: " << it->second.key_string() << ", " << ss_ipaddr(it->first);
			it = defunct_assignments.erase(it);
		} else {
			natpool.remove_address(it->first);
			++it;
		}
	}
	for(auto it = assignments.begin(); it != assignments.end();) {
		if((it->second.nbo_nat_ip & natpool_netmask) != natpool_network) {
			iout() << "Rejected address assignment as not in natpool: " << it->first.key_string() << ", " << ss_ipaddr(it->second.nbo_nat_ip);
			it = assignments.erase(it);
		} else {
			++it;
		}
	}
}

void address_assignment_map::cleanup()
{
	bool any_removed = false;
	for(auto it = defunct_assignments.begin(); it != defunct_assignments.end();) {
		auto assignment_it = assignments.find(it->second);
		if(assignment_it != assignments.end()) {
			if(assignment_it->second.flags & assignment::PERMANENT) {
				// no cleanup action for permanent addresses
				++it;
			} else if(assignment_it->second.flags & assignment::ACTIVE) {
				// peer has reconnected and address is active again
				it = defunct_assignments.erase(it);
			} else if(assignment_it->second.flags & assignment::GRACE_PERIOD) {
				// grace period is now expired, next cleanup iteration will remove address
				assignment_it->second.flags &= ~assignment::GRACE_PERIOD;
				++it;
			} else {
				// survived an entire grace period without reactivation, address goes back into the pool
				natpool.reinsert_address(assignment_it->second.nbo_nat_ip);
				assignments.erase(assignment_it);
				it = defunct_assignments.erase(it);
				any_removed = true;
			}
		} else {
			dout() << "BUG: defunct_address_assignment without address_assignment: " << ss_ipaddr(it->first) << " for " << it->second;
			it = defunct_assignments.erase(it);
		}
	}
	if(any_removed)
		save_to_disk();
}

// TODO: this has the potential to become a performance issue and it runs in the important thread
// possible solution is to spawn another thread and have it keep a copy of the assignments
// then just send it updates rather than a full copy of the entire list for every change
void address_assignment_map::save_to_disk()
{
	std::string data;
	data.reserve(assignments.size() * 80/*approx chars per line*/);
	in_addr addr;
	char addr_buf[INET_ADDRSTRLEN];
	for(const std::pair<hashkey,assignment> &a : assignments) {
		addr.s_addr = a.second.nbo_nat_ip;
		data += a.first.key_string() + ',' + inet_ntop(AF_INET, &addr, addr_buf, INET_ADDRSTRLEN) + '\n';
	}
	io->add(std::bind(&address_assignment_map::write_to_disk, std::move(data)));
}

void address_assignment_map::write_to_disk(std::string data)
{
	std::string tmpfn = snow::conf[snow::ADDRESS_ASSIGNMENT_FILE] + "~";
	dout() << "Writing address lease file to disk " << tmpfn;
	std::ofstream outfile(tmpfn.c_str(), std::ios::binary | std::ios::out);
	if(!outfile.good()) {
		eout() << "Could not open temporary address lease file for write (" << tmpfn << ")";
		return;
	}
	try {
		outfile.exceptions( std::ofstream::failbit | std::ofstream::badbit );
		if(outfile.tellp() != 0) {
			wout() << "Found non-empty address lease temporary file " << tmpfn << ", contents will be overwritten";
			outfile.seekp(0);
		}
		outfile << "# do not edit this file while the service is running, your changes will be overwritten\n";
		outfile << data;
		outfile.close();
		std::rename(tmpfn.c_str(), snow::conf[snow::ADDRESS_ASSIGNMENT_FILE].c_str());
	} catch(const std::exception& e) {
		eout() << "Got exception writing address lease file: " << e.what();
	}
}
