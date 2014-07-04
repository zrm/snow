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

#include "ip_packet.h"



std::ostream& operator<<(std::ostream& out, const tcpudp_port_header& header)
{
	out << "tcp/udp src port:" << ntohs(header.src) << " dst port:" << ntohs(header.dst);
	return out;
}

std::ostream& operator<<(std::ostream& out, const udp_header& header)
{
	out << "udp header: src port:" << ntohs(header.src_port) << " dst port:" << ntohs(header.dst_port)
		   << " len:" << ntohs(header.len) << " checksum:" << std::hex << ntohs(header.checksum) << std::dec;
	return out;
}

std::ostream& operator<<(std::ostream& out, const tcp_header& header)
{
	out << "tdp header: src port:" << ntohs(header.src_port) << " dst port:" << ntohs(header.dst_port)
		<< " seq:" << ntohl(header.seq) << " ack:" << ntohl(header.ack) << " offset_ns:" << (unsigned)header.offset_ns
		<< " flags:" << (unsigned)header.flags << " window size:" << ntohs(header.window_size)
		<< " checksum:" << std::hex << ntohs(header.checksum) << std::dec << " urg:" << header.urg;
	return out;
}

const char* icmp_header::icmp_type_name[] = {
	"Echo Reply", "Reserved (1)", "Reserved (2)", "Dest Unreachable", "Source Quench",
	"Redirect", "Alternative Host Address", "Reserved (7)", "Echo Request", "Router Advertisement",
	"Router Solicitation", "Time Exceeded", "Bad IP Header", "Timestamp", "Timestamp Reply",
	"Information Request", "Information Reply", "Address Mask Request", "Address Mask Reply" };
const char* icmp_header::icmp_unreach_code[] = {
	"Dest Net Unreachable", "Dest Host Unreachable", "Dest proto unreachable", "Dest port unreachable", "Frag Required and DF set",
	"Source Route Failed", "Dest Net Unknown", "Dest host unknown", "Source host isolated", "Net admin. prohibited",
	"Host admin. prohibited", "Net unreachable for TOS", "Host unreachable for TOS", "Comm admin. prohibited", "Host precedence violation",
	"Precedence cutoff in effect"};

std::ostream& operator<<(std::ostream& out, const icmp_header& header)
{
	out << "icmp header: ";
	if(header.icmp_type < 20)
		out << "type:" << icmp_header::icmp_type_name[header.icmp_type];
	else 
		out << "type:" << (int)header.icmp_type;
	if(header.icmp_type == icmp_header::DEST_UNREACHABLE && header.code < 16)
		out << " code:" << icmp_header::icmp_unreach_code[header.code];
	else
		out << " code:" << (int)header.code;
	out << " checksum:" << std::hex << ntohs(header.checksum) << std::dec << " header data:" << ntohl(header.header_data);
	return out;
}

std::ostream& operator<<(std::ostream& out, const icmp6_header& header)
{
	out << "icmp header: type:";
	switch(header.icmp_type) {
	case icmp6_header::DEST_UNREACHABLE:
		out << "Dest Unreachable"; break;
	case icmp6_header::PACKET_TOO_BIG:
		out << "Packet Too Big"; break;
	case icmp6_header::TIME_EXCEEDED:
		out << "Time Exceeded"; break;
	case icmp6_header::PARAMETER_PROBLEM:
		out << "Param Prob"; break;
	case icmp6_header::ECHO_REQUEST:
		out << "Echo Req"; break;
	case icmp6_header::ECHO_REPLY:
		out << "Echo Reply"; break;
	default:
		out << (int)header.icmp_type; break;
	}
	out << " code:" << (int)header.code << " checksum:" << std::hex << ntohs(header.checksum)
		<< std::dec << " header data:" << ntohl(header.header_data);;
	return out;
}

std::ostream& operator<<(std::ostream& out, const ipv4_header& header)
{
	out << "ipv4 header src addr: " << ss_ipaddr(header.src_addr) << ", dst addr: " << ss_ipaddr(header.dst_addr);
	out << ", version:" << (int)(header.version_ihl >> 4) << ", IHL:" << (int)(header.version_ihl&0xf) << ", dscp_ecn:" << (int)header.dscp_ecn;
	out << ", total length:" << ntohs(header.total_length) << ", ident:" << std::hex << header.identification << ", flags:" << (ntohs(header.flags_fragmentoffset)>> 13);
	out << ", fragmentoffset:" << std::dec << (ntohs(header.flags_fragmentoffset) & 0x1fff) << ", ttl:" << (int)header.ttl << ", proto:" << (int)header.protocol;
	out << ", header checksum:" << std::hex << ntohs(header.header_checksum) << std::dec;
	return out;
}

std::ostream& operator<<(std::ostream& out, const ipv6_header& header)
{
	out << "ipv6 header src addr: " << ss_ip6addr(header.src_addr) << ", dst addr: " << ss_ip6addr(header.dst_addr);
	out << ", version " << header.version() << ", traffic class " << header.traffic_class() << ", flow label " << header.flow();
	out << ", payload length " << ntohs(header.payload_length) << ", next_header " << (int)header.next_header << ", hop limit (TTL) " << (int)header.hop_limit;
	return out;
}

std::ostream& operator<<(std::ostream& out, const snow_packet& packet)
{
	switch(packet.version_header.version()) {
	case 4:
		out << packet.header;
		switch(packet.header.protocol) {
		case 0x01: {
			const icmp_header& icmp = packet.header.transport_header().icmp;
			out << " " << icmp;
			if(icmp.contains_inner_packet()) {
				const ipv4_header& inner_packet_header = icmp.payload()->header;
				out << " " << inner_packet_header;
				if(inner_packet_header.protocol == ipv4_header::TCP || inner_packet_header.protocol == ipv4_header::UDP)
					out << " " << inner_packet_header.transport_header().tcpudp;
			}
			break;
		}
		case 0x06:
			out << " " << packet.header.transport_header().tcp;
			break;
		case 0x11:
			out << " " << packet.header.transport_header().udp;
			break;
		}
		break;
	case 6:
		out << packet.header6;
		// TODO: print transport header once transport_header() is implemented for ipv6
		break;
	default:
		out << "[invalid ip header version " << packet.version_header.version() << "]";
		break;
	}

	return out;
}

bool validate_ipv4_header(const snow_packet*const packet, size_t packetsize)
{
	if(packetsize == 0) {
		dout() << "Dropped empty packet";
		return false;
	}
	// TOOD: some of these should get an ICMP response
	if(packet->version_header.version() != 4/*IPv4*/) {
		dout() << "Dropped packet with unsupported IP version " << packet->version_header.version();
		return false;
	}
	if(packetsize < packet->header.ihl()) {
		dout() << "Dropped packet with size less than IHL field";
		return false;
	}
	return true;
}

bool validate_icmp4_inner_length(const snow_packet*const packet, size_t packetsize)
{
	if(validate_ipv4_header(packet, packetsize) == false) {
		dout() << "ICMP inner packet header failed length validation";
		return false;
	}
	if(packetsize < packet->header.ihl() + 8) {
		dout() << "ICMP inner packet failed to include transport header stub";
		return false;
	}
	return true;
}

bool validate_packet4_length(const snow_packet*const packet, size_t packetsize)
{
	if(validate_ipv4_header(packet, packetsize) == false) {
		dout() << "ipv4 header failed length validation";
		return false;
	}
	if(packetsize < ntohs(packet->header.total_length)) {
		dout() << "Dropped packet with size less than total length field";
		return false;
	}
	unsigned ihl = packet->header.ihl();
	switch(packet->header.protocol) {
	case 0x01/*ICMP*/:
		if(packetsize < ihl + sizeof(icmp_header) ||
				(packet->header.transport_header().icmp.contains_inner_packet() &&
				 validate_icmp4_inner_length(packet->header.transport_header().icmp.payload(), packetsize - ihl - sizeof(icmp_header)) == false)) {
			dout() << "Dropped incomplete ICMP packet";
			return false;
		}
		break;
	case 0x06/*TCP*/:
		if(packetsize < ihl + sizeof(tcp_header) || packetsize < ihl + ((packet->header.transport_header().tcp.offset_ns & 0xf0)>>2)) {
			dout() << "Dropped packet with incomplete TCP header";
			return false;
		}
		break;
	case 0x11/*UDP*/:
		if(packetsize < ihl + sizeof(udp_header)) {
			dout() << "Dropped packet with incomplete UDP header";
			return false;
		}
		break;
	default:
		dout() << "IP packet had unusual transport protocol (" << packet->header.protocol << ")";
		// packets with unusual protocols (which don't have ports) can be forwarded without modification
		break;
	}
	return true;
}

// TODO: all of this is assuming no extension headers, which is broken (currently all packets with extension headers are discarded before this)
bool validate_ipv6_icmp(const icmp6_header* packet, size_t packetsize)
{
	if(packetsize < sizeof(icmp6_header)) {
		dout() << "Dropped ICMP6 packet with size less than ICMP header length";
		return false;
	}
	// check that inner packet contains IPv6 header and at least 8 bytes of payload
	// (IPv6 actually requires as much of the packet as will fit in the min MTU of 1280 bytes
		// but all we care about is enough to read the ports out of the transport header)
		// ** obviously this will have to be updated to support extension headers **
	if(packet->contains_inner_packet() && packetsize < sizeof(icmp6_header) + sizeof(ipv6_header) + 8) {
		dout() << "Dropped ICMP6 packet with truncated inner packet";
		return false;
	}
	return true;
}

