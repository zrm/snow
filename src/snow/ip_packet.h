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

#ifndef IP_PACKET_H
#define IP_PACKET_H
#include<iostream>
#include "../common/common.h"
#include "../common/network.h"
#include"../common/err_out.h"

struct tcpudp_port_header
{
	uint16_t src;
	uint16_t dst;
};
std::ostream& operator<<(std::ostream& out, const tcpudp_port_header& header);

struct udp_header
{
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t len;
	uint16_t checksum;
};
std::ostream& operator<<(std::ostream& out, const udp_header& header);

struct tcp_header
{
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq;
	uint32_t ack;
	uint8_t offset_ns;
	uint8_t flags;
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urg;
	// [options if data offset > 5]
};
std::ostream& operator<<(std::ostream& out, const tcp_header& header);

union snow_packet;
struct icmp_header
{
	uint8_t icmp_type;
	uint8_t code;
	uint16_t checksum;
	uint32_t header_data; // contents specific to type/code
	enum ICMP_TYPE { ECHO_REPLY, RESERVED1, RESERVED2, DEST_UNREACHABLE, SOURCE_QUENCH, REDIRECT, ALT_HOST, RESERVED7, ECHO_REQUEST,
				   ROUTER_ADVERT, ROUTER_SOLICITATION, TIME_EXCEEDED, PARAMETER_PROBLEM, TIMESTAMP, TIMESTAMP_REPLY,
					 INFORMATION_REQ, INFORMATION_REPLY, ADDR_MASK_REQ, ADDR_MASK_REPLY, TRACEROUTE = 30 /* etc, others not yet needed */ };
	enum DEST_UNREACH { NET_UNREACH, HOST_UNREACH, PROTO_UNREACH, PORT_UNREACH, PACKET_TOO_BIG, SOURCE_RT_FAILED, DEST_NET_UNKNOWN, DEST_HOST_UNKNOWN,
					  SRC_HOST_ISOLATED, NET_ADMIN_PROHIBITED, HOST_ADMIN_PROHIBITED, NET_UNREACH_TOS, HOST_UNREACH_TOS, COMM_ADMIN_PROHIBITED,
					  HOST_PRECEDENCE_VIOLATION, PRECEDENCE_CUTOFF };
	static const char* icmp_type_name[20];
	static const char* icmp_unreach_code[16];
	bool contains_inner_packet() const {
		switch(icmp_type) {
		case icmp_header::DEST_UNREACHABLE:
		case icmp_header::SOURCE_QUENCH: // (deprecated)
		case icmp_header::REDIRECT: // TODO: probably want to dump these entirely (or at least NAT the gateway)
		case icmp_header::TIME_EXCEEDED:
		case icmp_header::PARAMETER_PROBLEM: {
			return true;
		}
		default:
			break;
		}
		return false;
	}
	snow_packet* payload() { return reinterpret_cast<snow_packet*>(reinterpret_cast<uint8_t*>(this) + sizeof(icmp_header)); }
	const snow_packet* payload() const { return reinterpret_cast<const snow_packet*>(reinterpret_cast<const uint8_t*>(this) + sizeof(icmp_header)); }
	icmp_header() {}
	icmp_header(uint8_t tp, uint8_t cd, uint32_t data=0, uint16_t cksum=0) : icmp_type(tp), code(cd), checksum(cksum), header_data(data) {}
};
static_assert(sizeof(icmp_header) == 8, "icmp_header size wrong");
std::ostream& operator<<(std::ostream& out, const icmp_header& header);



// ICMP6 header structure is identical to ICMP4 header, but types/codes are different
struct icmp6_header
{
	uint8_t icmp_type;
	uint8_t code;
	uint16_t checksum;
	uint32_t header_data; // contents specific to type/code
	enum ICMP_TYPE { DEST_UNREACHABLE=1, PACKET_TOO_BIG, TIME_EXCEEDED, PARAMETER_PROBLEM, ECHO_REQUEST=128, ECHO_REPLY /*others not currently required here*/};
	enum DEST_UNREACH { NO_ROUTE, COMM_ADMIN_PROHIBITED, SRC_ADDR_BEYOND_SCOPE, ADDR_UNREACH, PORT_UNREACH, SRC_FAILED_POLICY, REJECT_ROUTE, SRC_RT_HDR_ERROR };
	bool contains_inner_packet() const { return icmp_type < 128; }
	snow_packet* payload() { return reinterpret_cast<snow_packet*>(reinterpret_cast<uint8_t*>(this) + sizeof(icmp6_header)); }
	const snow_packet* payload() const { return reinterpret_cast<const snow_packet*>(reinterpret_cast<const uint8_t*>(this) + sizeof(icmp6_header)); }
	icmp6_header() {}
	icmp6_header(uint8_t tp, uint8_t cd, uint32_t data=0, uint16_t cksum=0) : icmp_type(tp), code(cd), checksum(cksum), header_data(data) {}
};
static_assert(sizeof(icmp6_header) == 8, "icmp6_header size wrong");
std::ostream& operator<<(std::ostream& out, const icmp6_header& header);

union ip_transport_header
{
	uint8_t raw[1]; // variable size
	uint16_t raw16[1]; // variable size, for checksum
	tcp_header tcp;
	udp_header udp;
	tcpudp_port_header tcpudp;
	icmp_header icmp;
	icmp6_header icmp6;
};


struct packet_version_header
{
	uint8_t version_byte; // most significant four bits specify IP version, least significant bits are version-specific
	unsigned version() const { return (version_byte >> 4); }
};


struct ipv4_header
{
	enum { ICMP=0x01, TCP=0x06, UDP=0x11 };
	uint8_t version_ihl; // 4-bits version, 4-bits internet header length
	uint8_t dscp_ecn; // 6-bits differentiated services code point, 2-bits explicit congestion notif.
	uint16_t total_length;
	uint16_t identification;
	uint16_t flags_fragmentoffset; // 3-bits flags, 13-bits fragment offset
	uint8_t ttl;
	uint8_t protocol; // e.g. tcp/udp/icmp
	uint16_t header_checksum;
	uint32_t src_addr;
	uint32_t dst_addr;
	unsigned version() const { return (version_ihl >> 4); }
	// [options if ihl > 5]
	// internet header length in bytes
	unsigned ihl() const { return (version_ihl & 0xf) * 4; }
	const ip_transport_header& transport_header() const {
		return *reinterpret_cast<const ip_transport_header*>( reinterpret_cast<const uint8_t*>(this) + ihl() );
	}
	ip_transport_header& transport_header() {
		return *reinterpret_cast<ip_transport_header*>( reinterpret_cast<uint8_t*>(this) + ihl() );
	}
	ipv4_header() {}
	ipv4_header(uint16_t tlen, uint16_t ffo, uint8_t hops, uint8_t proto, uint32_t src, uint32_t dst)
		: version_ihl(0x45), dscp_ecn(0), total_length(tlen), identification(getrand<uint16_t>()), flags_fragmentoffset(ffo), ttl(hops), protocol(proto),
		  header_checksum(0), src_addr(src), dst_addr(dst) {}
};
// Can't have alignment padding in these data structures since they get cast from raw wire data
// and sizeof is used to validate received data
static_assert(sizeof(ipv4_header)==2*sizeof(uint32_t)+4*sizeof(uint16_t)+4*sizeof(uint8_t),"unexpected padding in ipv4_header");

std::ostream& operator<<(std::ostream& out, const ipv4_header& header);

struct ipv6_header
{
	uint8_t version_class;
	uint8_t class_flow;
	uint16_t flow_label;
	uint16_t payload_length;
	uint8_t next_header; // this is equivalent to IPv4 'protocol' unless there is an extension header
	uint8_t hop_limit; // (TTL)
	uint8_t src_addr[16];
	uint8_t dst_addr[16];
	unsigned version() const { return (version_class >> 4); }
	unsigned traffic_class() const { return (version_class << 4) | (class_flow >> 4); }
	unsigned flow() const { return ((class_flow & 0xf) << 16) | (ntohs(flow_label)); }
	// TOOD: make transport_header() work properly in presence of extension headers
		// doing that will require updating the IPv6 ICMP validation function to the same end
	const ip_transport_header& transport_header() const {
		return *reinterpret_cast<const ip_transport_header*>( reinterpret_cast<const uint8_t*>(this) + sizeof(ipv6_header) );
	}
	ip_transport_header& transport_header() {
		return *reinterpret_cast<ip_transport_header*>( reinterpret_cast<uint8_t*>(this) + sizeof(ipv6_header) );
	}
};
static_assert(sizeof(ipv6_header)==40, "ipv6 header size wrong");

std::ostream& operator<<(std::ostream& out, const ipv6_header& header);

// packet type enum specifies high order nibble of a packet as identifying what sort of packet it is
	// first nibble is the IP version field for IP packets, so '4' or '6' identifies IPv4 or IPv6
	// IP versions 0 and 1 are "reserved" (http://www.iana.org/assignments/version-numbers) so zero is used here to identify hello and control packet types
enum PACKET_TYPE { SNOW_PACKET=0x00, IPV4_PACKET=0x40, IPV6_PACKET=0x60 };
enum SNOW_PACKET_TYPE { SNOW_HELLO_PACKET, SNOW_CONTROL_PACKET };
enum SNOW_CONTROL_SUBTYPE { SNOW_CONTROL_ECHO, SNOW_CONTROL_PORT_DETECT };

// echo packet type is used as a keepalive and for path mtu discovery
struct snow_echo
{
	uint8_t pkttype;
	uint8_t reserved; // sender must set to zero, receiver must ignore
	uint16_t subtype; // SNOW_CONTROL_ECHO
	uint16_t ack; // acknowledge receiving packet of this size, zero indicates request to acknowledge this packet
	// [...] (padding of arbitrary length)
	snow_echo(uint16_t hbo_ack)
		: pkttype(PACKET_TYPE::SNOW_PACKET|SNOW_PACKET_TYPE::SNOW_CONTROL_PACKET), reserved(0),
		  subtype(htons(SNOW_CONTROL_SUBTYPE::SNOW_CONTROL_ECHO)), ack(htons(hbo_ack)) {}
};

// snow port detect allows an outgoing connection to ask the peer what its NAPT-mapped incoming port would be
// listen peer sends msg with nonce, client peer sends nonce over UDP from its own listen port, listen peer sends msg with recvd ipaddr+port
struct snow_port_detect
{
	uint8_t pkttype;
	uint8_t reserved; // sender must set to zero, receiver must ignore
	uint16_t subtype; // SNOW_CONTROL_PORT_DETECT
	uint8_t data[16]; // nonce or ipaddr
	uint16_t port; // NBO, zero if 'data' is nonce rather than ipaddr
	snow_port_detect(const uint8_t* d, uint16_t p = 0)
		: pkttype(PACKET_TYPE::SNOW_PACKET|SNOW_PACKET_TYPE::SNOW_CONTROL_PACKET), reserved(0),
		  subtype(htons(SNOW_CONTROL_SUBTYPE::SNOW_CONTROL_PORT_DETECT)), port(p) {
		memcpy(data, d, sizeof(data));
	}
};
static_assert(sizeof(snow_port_detect)==22, "unexpected padding in snow_port_detect structure");

union snow_packet
{
	uint8_t raw[1]; // (variable length)
	uint16_t raw16[1]; // (variable length; for calculating checksum)
	packet_version_header version_header;
	ipv4_header header;
	ipv6_header header6;
};

std::ostream& operator<<(std::ostream& out, const snow_packet& packet);

bool validate_ipv4_header(const snow_packet*const packet, size_t packetsize);

bool validate_icmp4_inner_length(const snow_packet*const packet, size_t packetsize);

bool validate_packet4_length(const snow_packet*const packet, size_t packetsize);


bool validate_ipv6_icmp(const icmp6_header* packet, size_t packetsize);

#endif // IP_PACKET_H
