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

#include<algorithm>
#include<fstream>
#include<sstream>
#include"configuration.h"
#include"../common/err_out.h"
#include"../common/configuration_base.tpp"
#include"../common/network.h"

std::string get_env_var(const char *variable_name); // for windows; definition is in common.cpp (don't need all of common.h here just for this)

namespace snow {

void assign_ip4addrs(const std::string &line, std::vector<uint32_t> &addrs)
{
	size_t pos = 0;
	uint32_t addr;
	while(pos < line.size()) {
		std::string addrstr = next_word(line, &pos);
		if(inet_pton(AF_INET, addrstr.c_str(), &addr) == 1) {
			addrs.push_back(addr);
		} else {
			wout() << "\"" << addrstr << "\" in configuration is not a valid IPv4 address";
		}
	}
}

configuration::configuration()
{
	// set defaults
	// strings
#ifdef WINDOWS
	//std::string programdata = get_env_var("PROGRAMDATA"); // [new ALLUSERSPROFILE, doesn't exist on XP/2003]
	std::string programdata = get_env_var("ALLUSERSPROFILE");
	assign_value(CONFIG_FILE, programdata+"/Application Data/snow/snow.conf");
	assign_value(KEY_FILE, programdata+"/Application Data/snow/key.pem");
	assign_value(CERT_FILE, programdata+"/Application Data/snow/cert.pem");
	assign_value(KNOWN_PEERS_FILE, programdata+"/Application Data/snow/known_peers");
	assign_value(DH_PARAMS_FILE, programdata+"/Application Data/snow/DH_params");
	assign_value(CLONE_DEVICE, "/dev/net/tun"); // (not used on windows)
	assign_value(VIRTUAL_INTERFACE, "auto"); // in config file, "{[GUID]}" of the interface; auto means try to find in registry
	assign_value(ADDRESS_ASSIGNMENT_FILE, programdata+"/Application Data/snow/address_assignments");
	assign_value(PERMANENT_ADDRESS_ASSIGNMENT_FILE, programdata+"/Application Data/snow/permanent_address_assignments");
	#else
	assign_value(CONFIG_FILE, "/etc/snow/snow.conf");
	assign_value(KEY_FILE, "/etc/snow/key.pem");
	assign_value(CERT_FILE, "/etc/snow/cert.pem");
	assign_value(KNOWN_PEERS_FILE, "/var/lib/snow/known_peers");
	assign_value(DH_PARAMS_FILE, "/etc/snow/DH_params");
	assign_value(CLONE_DEVICE, "/dev/net/tun");
	assign_value(VIRTUAL_INTERFACE, "snow0");
	assign_value(ADDRESS_ASSIGNMENT_FILE, "/var/lib/snow/address_assignments");
	assign_value(PERMANENT_ADDRESS_ASSIGNMENT_FILE, "/etc/snow/permanent_address_assignments");
#endif
	assign_value(NATPOOL_NETWORK, "172.16.0.0");
	assign_value(PUBLIC_IPV4_ADDRS, std::vector<uint32_t>());
	// unsigned integers
	assign_value(DTLS_BIND_PORT, 0); // 0 is not valid, must set an arbitrary value in the configuration file
	assign_value(DTLS_BIND6_PORT, 8); 
	assign_value(DTLS_OUTGOING_PORT, 0); // 0 is not valid, must set an arbitrary value in the configuration file
	assign_value(DHT_PORT, 8);
	assign_value(NAMESERV_PORT, 8);
	assign_value(NAMESERV_TIMEOUT_SECS, 6);
	assign_value(DTLS_IDLE_TIMEOUT_SECS, 4000);
	assign_value(HEARTBEAT_SECONDS, 115);
	assign_value(HEARTBEAT_RETRIES, 5);
	assign_value(NAT_IP_GRACE_PERIOD_SECONDS, 7200);
	assign_value(DHT_BOOTSTRAP_TARGET, 6);
	assign_value(DHT_MAX_PEERS, 99);
	assign_value(NATPOOL_NETMASK_BITS, 12);
	assign_value(VIRTUAL_INTERFACE_MTU, 1419);
	// boolean values
	assign_value(DHT_RFC1918_ADDRESSES, true);
	assign_value(NEVER_TRUST_PEER_VISIBLE_IPADDRS, false);
}

void check_port(size_t port, std::string str)
{
	if(port == 0 || port > 65535) {
		eout() << str << " set to invalid value in configuration, a port value must be 1-65535";
		abort();
	}
}
void check_nonzero(size_t val, std::string str)
{
	if(val==0) {
		eout() << str << " cannot be zero";
		abort();
	}
}
uint16_t get_random_port()
{
	try {
		csocket sock(AF_INET, SOCK_DGRAM);
		sockaddrunion su;
		memset(&su, 0, sizeof(su));
		su.sa.sin_family = AF_INET;
		sock.bind(su);
		sock.getsockname(su);
		return su.sa.sin_port;
	} catch(const e_check_sock_err& e) {
		eout() << __FILE__ << ":" << __LINE__ << ": Failed to bind port for get_random_port(): " << e;
		abort();
	}
	return 0;
}
void configuration::sanity_check_values()
{
	if(conf[DTLS_BIND_PORT] == 0 || conf[DTLS_OUTGOING_PORT] == 0) {
		// use random but persistent ports for these
		std::ofstream conffile(conf[CONFIG_FILE], std::ios_base::out | std::ios_base::binary | std::ios_base::app);
		if(conf[DTLS_BIND_PORT] == 0) {
			uint16_t port = ntohs(get_random_port());
			iout() << "Assigned DTLS_BIND_PORT random port " << port;
			conffile << "\nDTLS_BIND_PORT=" << port;
			assign_value(DTLS_BIND_PORT, port);
		}
		if(conf[DTLS_OUTGOING_PORT] == 0) {
			uint16_t port = ntohs(get_random_port());
			iout() << "Assigned DTLS_OUTGOING_PORT random port " << port;
			conffile << "\nDTLS_OUTGOING_PORT=" << port;
			assign_value(DTLS_OUTGOING_PORT, port);
		}
	}
	if(conf[DTLS_BIND_PORT] == conf[DTLS_OUTGOING_PORT] || conf[DTLS_BIND6_PORT] == conf[DTLS_OUTGOING_PORT]) {
		eout() << "DTLS_BIND_PORT or DTLS_OUTGOING_PORT not initialized to separate valid ports, these should have been set to random ports during installation."
			<< " You must set DTLS_BIND_PORT and DTLS_OUTGOING_PORT to separate port numbers in the snow configuration file."
			   << " If you have more than one device try to choose different ports for each device.";
		abort();
	}
	check_port(conf[DTLS_OUTGOING_PORT], "DTLS_OUTGOING_PORT");
	check_port(conf[DTLS_BIND_PORT], "DTLS_BIND_PORT");
	check_port(conf[DTLS_BIND6_PORT], "DTLS_BIND6_PORT");
	check_port(conf[DHT_PORT], "DHT_PORT");
	check_port(conf[NAMESERV_PORT], "NAMESERV_PORT");
	check_nonzero(conf[NAMESERV_TIMEOUT_SECS], "NAMESERV_TIMEOUT_SECS");
	check_nonzero(conf[DTLS_IDLE_TIMEOUT_SECS], "DTLS_IDLE_TIMEOUT_SECS");
	check_nonzero(conf[HEARTBEAT_SECONDS], "HEARTBEAT_SECONDS");
	check_nonzero(conf[HEARTBEAT_RETRIES], "HEARTBEAT_RETRIES");
	if(conf[NAT_IP_GRACE_PERIOD_SECONDS] < 1800) {
		wout() << "NAT IP grace period of " << conf[NAT_IP_GRACE_PERIOD_SECONDS] << " from configuration file is too short, using minimum grace period of 1800 seconds";
		assign_value(NAT_IP_GRACE_PERIOD_SECONDS, 1800);
	}
	if(conf[DHT_BOOTSTRAP_TARGET]==0) {
		wout() << "DHT_BOOTSTRAP_TARGET cannot be zero, using default value";
		assign_value(DHT_BOOTSTRAP_TARGET, 6);
	}
	if(conf[DHT_MAX_PEERS] <= 3) {
		wout() << "DHT_MAX_PEERS cannot be " << conf[DHT_MAX_PEERS] << ", must be at least 4, using default value of 99";
		assign_value(DHT_MAX_PEERS, 99);
	}
	if(conf[NATPOOL_NETMASK_BITS] > 20 || conf[NATPOOL_NETMASK_BITS] < 4) {
		eout() << "NATPOOL_NETMASK_BITS must be between 4 and 20";
		abort();
	}
	uint32_t addr, netmask = ~htonl((1 << (32 - conf[NATPOOL_NETMASK_BITS])) - 1);
	if(inet_pton(AF_INET, conf[NATPOOL_NETWORK].c_str(), &addr) != 1 || (addr & ~netmask) != 0) {
		eout() << "NATPOOL_NETWORK/NATPOOL_NETMASK_BITS as " << conf[NATPOOL_NETWORK] << "/" << conf[NATPOOL_NETMASK_BITS] << " is not a valid subnet.";
		abort();
	}
	if(conf[VIRTUAL_INTERFACE_MTU] > 65535 || conf[VIRTUAL_INTERFACE_MTU] < 576) {
		eout() << "VIRTUAL_INTERFACE_MTU cannot be " << conf[VIRTUAL_INTERFACE_MTU];
		abort();
	}
}

configuration conf;

} // namespace snow
