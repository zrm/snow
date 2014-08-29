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

#ifndef CONFIGURATION_H
#define CONFIGURATION_H
#include<string>
#include<vector>
#include "../common/configuration_base.h"

namespace sdns
{

MAKE_CONF_TYPE(conf_string, std::string, ss_convert<std::string>, CONFIG_FILE, ROOT_HINTS_FILE, STATIC_RECORDS_FILE, DNS_FORWARDERS_DIR, SDNS_USER)
MAKE_CONF_TYPE(conf_unsigned, size_t, ss_convert<size_t>, RETRIES_PER_NAMESERVER_ADDR, MAX_DNS_QUERY_DEPTH, MAX_UDP_SIZE, MAX_CLIENT_UDP_RESPONSE, \
			   QUERY_RETRY_MS, DNS_PORT, SNOW_NAMESERV_PORT, SNOW_NAMESERV_TIMEOUT_SECS, SNOW_NAMESERV_TIMEOUT_RETRIES, CACHE_SIZE, MAX_TTL, DEFAULT_STATIC_TTL, MAX_TCP_CLIENTS)
MAKE_CONF_TYPE(conf_bool, bool, ss_convert<bool>, SNOW)
MAKE_CONF_TYPE(conf_ipv4addrs, std::vector<uint32_t>, ipv4_convert, BIND4_ADDRS)
MAKE_CONF_TYPE(conf_ipv6addrs, std::vector<in6_addr>, ipv6_convert, BIND6_ADDRS)

class configuration : public configuration_base<conf_string, conf_unsigned, conf_bool, conf_ipv4addrs, conf_ipv6addrs>
{
	virtual void sanity_check_values();
public:
	configuration();
	void set_config_file(const std::string& fn) { assign_value(CONFIG_FILE, fn); }
	void read_config() { read_config_file((*this)[CONFIG_FILE]); }
};

extern configuration conf;

} // namespace sdns

#endif // CONFIGURATION_H
	
