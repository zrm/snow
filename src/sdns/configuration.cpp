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

#include "configuration.h"
#include "../common/configuration_base.tpp"
#include"../common/network.h"

std::string get_env_var(const char *variable_name); // definition is in common.cpp (don't need all of common.h here just for this)

namespace sdns {


configuration::configuration()
{
	// set defaults
#ifdef WINDOWS
	assign_value(CONFIG_FILE, get_env_var("PROGRAMFILES") + "\\sdns\\sdns.conf");
	assign_value(ROOT_HINTS_FILE, get_env_var("PROGRAMFILES") + "\\sdns\\root.names");
	assign_value(STATIC_RECORDS_FILE, get_env_var("PROGRAMFILES") + "\\sdns\\local.names");
	assign_value(DNS_FORWARDERS_DIR, get_env_var("PROGRAMFILES") + "\\sdns\\forwarders");
#else
	assign_value(CONFIG_FILE, "/etc/sdns/sdns.conf");
	assign_value(ROOT_HINTS_FILE, "/etc/sdns/root.names");
	assign_value(STATIC_RECORDS_FILE, "/etc/sdns/local.names");
	assign_value(DNS_FORWARDERS_DIR, "/etc/sdns/forwarders");
#endif
	assign_value(BIND4_ADDRS, std::vector<uint32_t>(1, htonl(INADDR_LOOPBACK)));
	assign_value(BIND6_ADDRS, std::vector<in6_addr>(1, in6addr_loopback));
	assign_value(RETRIES_PER_NAMESERVER_ADDR, 4);
	// had tried setting max depth at 10 and download.windowsupdate.com could not resolve first try with empty cache because it has five (5) chained CNAMEs
		// which exceeded depth 10 between following CNAMEs and following referrals
	assign_value(MAX_DNS_QUERY_DEPTH, 25);
	assign_value(MAX_UDP_SIZE, 65535);
	assign_value(MAX_CLIENT_UDP_RESPONSE, 8192);
	assign_value(QUERY_RETRY_MS, 500);
	assign_value(DNS_PORT, 53);
	assign_value(SNOW_NAMESERV_PORT, 8);
	assign_value(SNOW_NAMESERV_TIMEOUT_SECS, 1);
	assign_value(SNOW_NAMESERV_TIMEOUT_RETRIES, 8);
	assign_value(CACHE_SIZE, 1024*1024);
	assign_value(MAX_TTL, 86400);
	assign_value(DEFAULT_STATIC_TTL, 1800);
	assign_value(MAX_TCP_CLIENTS, 250);
	assign_value(SNOW, true);
	
}


void configuration::sanity_check_values()
{
	if(conf[MAX_UDP_SIZE] > UINT16_MAX || conf[MAX_UDP_SIZE] < 512) {
		wout() << "Invalid max UDP bufsize (" << conf[MAX_UDP_SIZE] << "), reverting to default (65535)";
		assign_value(MAX_UDP_SIZE, UINT16_MAX);
	}
	if(conf[MAX_CLIENT_UDP_RESPONSE] > UINT16_MAX || conf[MAX_CLIENT_UDP_RESPONSE] < 512) {
		wout() << "Invalid max client UDP response size (" << conf[MAX_CLIENT_UDP_RESPONSE] << "), reverting to default value (8192)";
		assign_value(MAX_CLIENT_UDP_RESPONSE, 8192);
	}
	if(conf[QUERY_RETRY_MS] > 5000 || conf[QUERY_RETRY_MS] < 10) {
		wout() << "Invalid query retry timeout (" << conf[QUERY_RETRY_MS] << " ms), reverting to default (500 ms)";
		assign_value(QUERY_RETRY_MS, 500);
	}
	if(conf[DNS_PORT] > UINT16_MAX || conf[DNS_PORT] == 0) {
		wout() << "Invalid DNS port (" << conf[DNS_PORT] << "), reverting to default port (53)";
		assign_value(DNS_PORT, 53);
	}
	if(conf[SNOW_NAMESERV_PORT] > UINT16_MAX || conf[SNOW_NAMESERV_PORT] == 0) {
		wout() << "Invalid snow nameserv port (" << conf[SNOW_NAMESERV_PORT] << "), reverting to default port (8)";
		assign_value(SNOW_NAMESERV_PORT, 8);
	}
	if(conf[MAX_TTL] > 604800)
		assign_value(MAX_TTL, 604800);
	if(conf[DEFAULT_STATIC_TTL] > conf[MAX_TTL])
		assign_value(DEFAULT_STATIC_TTL, conf[MAX_TTL]);
	if(conf[CACHE_SIZE] < 1024)
		assign_value(CACHE_SIZE, 1024);
	if(conf[CACHE_SIZE] > 1024*1024*1024)
		assign_value(CACHE_SIZE, 1024*1024*1024);
}

configuration conf;

} // namespace dnsrcd
