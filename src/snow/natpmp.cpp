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

#include "natpmp.h"
#include "../common/network.h"
#ifndef NO_UPNP
#include<miniupnpc/miniupnpc.h>
#include<miniupnpc/upnpcommands.h>
#include<miniupnpc/upnperrors.h>
#endif
#ifndef NO_NATPMP
#define ENABLE_STRNATPMPERR
#include<natpmp.h>
#endif
#include<unordered_set>
#include"../common/err_out.h"
#include"configuration.h"
#include<thread>

// NAT-PMP gateway discovery: use traceroute method: send ICMP echo request with TTL=0 and see who responds
	// this especially works when the "gateway" isn't the NAT-PMP device, e.g. core switch is default gateway but NAT-PMP runs on router
	// because if you try NAT-PMP with the TTL=0 device and it isn't supported, you can try with the TTL=1 and TTL=2 devices as well
	// but careful for the security issue: those devices could be outside of local control, so trusting them to provide public addr could be problematic

// conflicts: try to figure out how to detect the difference between 'conflict' = this peer was assigned a new DHCP lease and 'conflict' = separate active peer exists using same port
	// in the first case just unmapping the existing port and remapping it is obviously the thing to do (if permitted)
	// in the second case, taking the port from a device that thought it had it is Bad: it will be sending the wrong port and we'll get peers expecting its hashkey (or it could be some entirely different program)
	// you would think UPNP gateways wouldn't allow you to unmap another device's port, but UPNP isn't exactly known for its security record (and maybe it's at least smart enough to check MAC? maybe? as if that stops anyone)
	// TODO: figure out something sane to do about this, maybe map different port?
	// note possible stupidity: if port is mapped to old DHCP IP addr then even holepunch is going to fail because at best NAT will NAPT the local port to something else

void natpmp_map_port(uint32_t* addr, in_port_t& port)
{
	// TODO: NAT-PMP is extremely easy to implement and it may not make sense to depend on an external library for it
		// (the hardest part seems to be discovering the IP address of the default gateway, which is likely to be platform-dependent) [but possible solution is to use ICMP TTL=0 with ICMP raw sock]
		// in a possible implementation, you bind two permanent sockets (one unicast, one multicast) with separate callbacks
		// the multicast read callback updates the external IP address and determines whether the gateway has rebooted and ports need re-mapped
			// (this is something the existing NAT-PMP library apparently doesn't expose)
		// the unicast read callback takes responses to mapping requests which provide current external IP and port on startup and renewal
		// then you just need a timer that runs every hour and re-maps the ports for two hours
	// also consider supporting Port Control Protocol: https://tools.ietf.org/html/rfc6887
		// (this appears to be a superset/successor of NAT-PMP, so the question is whether it adds anything we need; probably worth doing)
	*addr = 0;
#ifndef NO_NATPMP
	natpmp_t natpmp;
	natpmpresp_t resp;
	dout() << "detect_ipaddr_natpmp";
	if(initnatpmp(&natpmp, 0, 0) == 0/* OK is 0 here */) {
		// try to get publicly visible IP addr
		dout() << "natpmp init";
		if(sendpublicaddressrequest(&natpmp)==2/* OK is 2 here (because it sends 2 bytes) */) {
			dout() << "natpmp public address request";
			int rv = readnatpmpresponseorretry(&natpmp, &resp);
			while(rv == NATPMP_TRYAGAIN) {
				dout() << "natpmp try again";
				fd_set fds;
				timeval tv;
				FD_ZERO(&fds);
				FD_SET(natpmp.s, &fds);
				getnatpmprequesttimeout(&natpmp, &tv);
				if(select(natpmp.s+1, &fds, nullptr, nullptr, &tv) <= 0) {
					// timeout or error
					rv = NATPMP_ERR_UNDEFINEDERROR;
					break;
				}
				rv = readnatpmpresponseorretry(&natpmp, &resp);
			}
			if(rv > 0) {
				iout() << "natpmp provides public address " << ss_ipaddr(resp.pnu.publicaddress.addr.s_addr);
				*addr = resp.pnu.publicaddress.addr.s_addr;
			} else {
				iout() << "natpmp provides no public address: " << strnatpmperr(rv);
			}
		}
		// try to map port
			if(sendnewportmappingrequest(&natpmp, NATPMP_PROTOCOL_UDP, port, port, 8*60*60/*map for 8 hrs*/)==12/*OK is 12 here*/) {
			int rv = readnatpmpresponseorretry(&natpmp, &resp);
			while(rv == NATPMP_TRYAGAIN) {
				fd_set fds;
				timeval tv;
				FD_ZERO(&fds);
				FD_SET(natpmp.s, &fds);
				getnatpmprequesttimeout(&natpmp, &tv);
				if(select(natpmp.s+1, &fds, nullptr, nullptr, &tv) <= 0) {
					// timeout or error
					rv = NATPMP_ERR_UNDEFINEDERROR;
					break;
				}
				rv = readnatpmpresponseorretry(&natpmp, &resp);
			}
			if(rv > 0) {
				iout() << "natpmp mapped snow port " << ntohs(port);
			} else {
				dout() << "Failed to map port with natpmp: " << strnatpmperr(rv);
				port = 0;
			}
		}
	}
	closenatpmp(&natpmp);
#endif
}


void upnp_map_port(uint32_t* addr, in_port_t& port)
{
	// TODO: theoretically this works on windows but having downloaded the latest version of libupnpc, the functions take different args (sig changed in new version)
		// should use the same version on all platforms, so have to decide whether to keep using Debian-packaged older version or use new version on all platforms
	*addr = 0;
#ifndef NO_UPNP
	UPNPDev *devlist = upnpDiscover(2000/*response timeout (milliseconds)*/, nullptr, nullptr, 0);
	if(devlist != nullptr) {
		UPNPUrls urls;
		IGDdatas data;
		char lan_addr[INET6_ADDRSTRLEN], ext_addr[INET6_ADDRSTRLEN];
		if(UPNP_GetValidIGD(devlist, &urls, &data, lan_addr, INET6_ADDRSTRLEN) == 1 /* valid and connected IGD */) {
			if(UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype, ext_addr) == UPNPCOMMAND_SUCCESS) {
				iout() << "Got UPNP external IP: " << ext_addr;
				if(inet_pton(AF_INET, ext_addr, addr) == 1) {
					dout() << "Converted UPNP external IP: " << inet_ntop(AF_INET, addr, ext_addr, INET6_ADDRSTRLEN);
				} else {
					dout() << "UPNP external IP did not parse";
				}
			}
			// try to do port map(s)
			std::string portstr = std::to_string(ntohs(port));
			int rv;
			if((rv = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype, portstr.c_str(), portstr.c_str(), lan_addr, "snow", "UDP", nullptr)) == UPNPCOMMAND_SUCCESS) {
				iout() << "Successfully added UPNP port mapping for snow port " << portstr;
			} else {
				dout() << "Failed to add UPNP port mapping for snow port " << portstr << " : " << strupnperror(rv);
				if(rv == 718 /* conflict */ && UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, portstr.c_str(), "UDP", nullptr) == UPNPCOMMAND_SUCCESS) {
					dout() << "Successfully removed existing UPNP port mapping, trying again";
					if((rv = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype, portstr.c_str(), portstr.c_str(), lan_addr, "snow", "UDP", nullptr)) == UPNPCOMMAND_SUCCESS) {
						iout() << "Successfully added UPNP port mapping for snow port " << portstr;
					} else {
						dout() << "Failed to add UPNP port mapping for snow port " << portstr << " : " << strupnperror(rv);
						port = 0;
					}
				} else {
					port = 0;
				}
				// TODO: there are two main causes of mapping failures: either this device's local IP has changed and old mapping is there, or some other device has the port
				// right now we just try to unmap the port and map it again
				// but it might be better to actually check, e.g. use UPNP_GetSpecificPortMappingEntry and see if the old IP pings or gives REFUSED on the port in question
					// then if the alt device isn't there or is but refuses connections, take the port, but not otherwise
				// also, some gateways may be stupid and return error if the port is already mapped to the same address you asked to map it to
					// so checking that the existing mapping doesn't just point to the local device may also be in order before concluding that there is "another" device with the port
			}
		} else {
			// no gateway device
			dout() << "No UPNP gateway device, not doing UPNP";
		}
		freeUPNPDevlist(devlist);
	} else {
		dout() << "No UPNP device list, not doing UPNP";
	}
#endif
}

void do_map_natpmpupnp_port(in_port_t prt, const std::function<void(uint32_t,uint16_t)>& callback)
{
	uint32_t addr = 0;
	in_port_t port = prt;
	natpmp_map_port(&addr, port);
	if(port != 0)
		callback(addr, port);
	if(addr != 0)
		callback(addr, 0);
	port = prt;
	upnp_map_port(&addr, port);
	if(port != 0)
		callback(addr, port);
	if(addr != 0)
		callback(addr, 0);
}


void map_natpmpupnp_port(in_port_t port, const std::function<void(uint32_t,uint16_t)>& callback)
{
	std::thread th([port, callback]() { do_map_natpmpupnp_port(port, callback); });
	th.detach();
}


void remove_natpmpupnp_mappings(in_port_t port)
{
#ifndef NO_NATPMP
	natpmp_t natpmp;
	natpmpresp_t resp;
	dout() << "detect_ipaddr_natpmp";
	if(port != 0 && initnatpmp(&natpmp, 0, 0) == 0/* OK is 0 here */) {
		// try to unmap port (zero lifetime)
		if(sendnewportmappingrequest(&natpmp, NATPMP_PROTOCOL_UDP, port, port, 0)==12/*OK is 12 here*/) {
			int rv = readnatpmpresponseorretry(&natpmp, &resp);
			while(rv == NATPMP_TRYAGAIN) {
				fd_set fds;
				timeval tv;
				FD_ZERO(&fds);
				FD_SET(natpmp.s, &fds);
				getnatpmprequesttimeout(&natpmp, &tv);
				if(select(natpmp.s+1, &fds, nullptr, nullptr, &tv) <= 0) {
					// timeout or error
					rv = NATPMP_ERR_UNDEFINEDERROR;
					break;
				}
				rv = readnatpmpresponseorretry(&natpmp, &resp);
			}
			if(rv > 0) {
				iout() << "natpmp unmapped snow port " << ntohs(port);
			}
		}
	}
	closenatpmp(&natpmp);
#endif
#ifndef NO_UPNP
	UPNPDev *devlist = upnpDiscover(2000/*response timeout (milliseconds)*/, nullptr, nullptr, 0);
	if(devlist != nullptr) {
		UPNPUrls urls;
		IGDdatas data;
		char lan_addr[INET6_ADDRSTRLEN];
		if(UPNP_GetValidIGD(devlist, &urls, &data, lan_addr, INET6_ADDRSTRLEN) == 1 /* valid and connected IGD */) {
			// try to undo port map
			int rv;
			if(port != 0) {
				std::string portstr = std::to_string(ntohs(port));
				if((rv = UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, portstr.c_str(), "UDP", nullptr)) == UPNPCOMMAND_SUCCESS) 
					iout() << "Successfully removed UPNP port mapping for snow port " << portstr;
			}
		}
		freeUPNPDevlist(devlist);
	}
#endif
}

