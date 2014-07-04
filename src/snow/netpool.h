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

#ifndef SNOW_NETPOOL_H
#define SNOW_NETPOOL_H
#include<cstdint>
#include<set>
#include<vector>
#include<memory>
#include<unordered_map>
#include "../common/err_out.h"
#include "crypto.h"


// IPv4 address range
struct address_range
{
	mutable uint32_t start;
	mutable uint32_t last;
	bool operator< (const address_range& range) const {
		return last < range.last;
	}
	bool operator== (const address_range& range) const {
		return last == range.last;
	}
	address_range(uint32_t begin, uint32_t end) : start(begin), last(end) {}
	address_range(uint32_t addr) : start(addr), last(addr) {}
};
class address_pool
{
private:
	std::set<address_range> pool;
public:
	address_pool() {}
	address_pool(uint32_t natpool_network, uint32_t natpool_netmask);
	address_pool(address_pool&& rval) : pool(std::move(rval.pool)) {}
	address_pool& operator=(address_pool&& rval) { std::swap(pool, rval.pool); return *this; }
	uint32_t get_address(); // remove next address from available pool and return it (network byte order)
	void remove_address(uint32_t nbo_addr); // remove specified address from pool
	void reinsert_address(uint32_t nbo_addr); // reinsert address removed by get_address/remove_address
};

class address_assignment_map
{
	struct assignment
	{
		uint32_t nbo_nat_ip;
		uint32_t flags;
		enum FLAGS : uint32_t { ACTIVE = 1, PERMANENT = 2, GRACE_PERIOD = 4};
		assignment(uint32_t nbo_ip, uint32_t flgs = ACTIVE) : nbo_nat_ip(nbo_ip), flags(flgs) {}
	};
	std::unordered_map<hashkey, assignment> assignments; // maps hashkeys to NBO NAT IP addrs (including disconnected peers during address grace period)
	std::unordered_map<uint32_t, hashkey> defunct_assignments; // maps NBO NAT IP to hashkey for defunct assignments in grace period
	address_pool natpool;
	worker_thread *io;
	void save_to_disk();
	static void write_to_disk(std::string data);
	void parse_lease_file(const std::string& fn, uint32_t flags);
public:
	address_assignment_map(worker_thread *io_thread);
	uint32_t assign_address(const hashkey &fingerprint); // throws invalid_input_exception if fp is ACTIVE, resource_exhaustion_exception if no pool addrs
	void unassign_address(const hashkey &fingerprint); 
	const hashkey& get_defunct_assignment(uint32_t nbo_nat_ip); // throws not_found_exception

	uint32_t operator[](const hashkey &fingerprint); // returns 0 if not found

	void set_natpool(address_pool&& nat, uint32_t natpool_network, uint32_t natpool_netmask);
	void cleanup();
};


#endif // SNOW_NETPOOL_H
