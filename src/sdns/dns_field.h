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

#ifndef DNS_FIELD_H
#define DNS_FIELD_H
#include<cstdint>
#include"../common/err_out.h"

class dns_opcode_t
{
protected:
	uint8_t opcode;
public:
	dns_opcode_t() {}
	dns_opcode_t(uint8_t op) : opcode(op) {
		if(opcode >= RESERVED)
			dout() << "dns opcode value (" << (unsigned)opcode << ") invalid or not implemented";
	}
	dns_opcode_t &operator=(uint8_t v) {
		*this=dns_opcode_t(v);
		return *this;
	}
	enum {
		STANDARD_QUERY = 0,
		INVERSE_QUERY = 1,
		SERVER_STATUS = 2,
		RESERVED = 3
	};
	operator uint8_t() const { return opcode; }
};

std::ostream &operator<<(std::ostream &out, const dns_opcode_t &op);

// TODO: EDNS extended rcodes
// probably the thing to do here is to create a separate class for full rcodes which is constructed from a message when requested
// then its constructor takes both the "original" rcode below and the EDNS extended bits and creates a single rcode
// and the new rcode can then be returned by dns_message 
class dns_rcode_t
{
protected:
	uint8_t rcode;
public:
	dns_rcode_t() {}
	dns_rcode_t(uint8_t r) : rcode(r) {
		if(rcode >= RESERVED)
			dout() << "dns rcode value (" << (int)rcode << ") invalid or not implemented";
	}
	dns_rcode_t &operator=(uint8_t v) {
		*this=dns_rcode_t(v);
		return *this;
	}
	enum {
		DNS_NO_ERROR = 0,
		FORMAT_ERROR = 1,
		SERVFAIL = 2,
		NAME_ERROR = 3,
		NOT_IMPLEMENTED = 4,
		REFUSED = 5,
		RESERVED = 6
	};
	operator uint8_t() const { return rcode; }
};

std::ostream &operator<<(std::ostream &out, const dns_rcode_t &r);


class dns_type_t
{
protected:
	uint16_t val;
public:
	dns_type_t() {}
	dns_type_t(uint16_t v) : val(v) {}
	dns_type_t &operator=(uint16_t v) {
		*this=dns_type_t(v);
		return *this;
	}
	enum {
		INVALID = 0, // [not a real type; uninitialized or empty]
		A		= 1, // IPv4 addr
		NS		= 2, // authoritative name server
		MD		= 3, // mail destination (obsolete - use MX)
		MF		= 4, // mail forwarder (obsolete - use MX)
		CNAME	= 5, // canonical name for an alias
		SOA		= 6, // start of a zone of authority
		MB		= 7, // mailbox domain name
		MG		= 8, // mail group member
		MR		= 9, // mail rename domain name
		NULL_RR	= 10, // NULL RR
		WKS		= 11, // well known service description
		PTR		= 12, // domain name pointer
		HINFO	= 13, // host information
		MINFO	= 14, // mailbox or mail list information
		MX		= 15, // mail exchange
		TXT		= 16, // text strings
		// end of RFC 1035 types [subsequent types MUST NOT use DNS label compression]
		RP		= 17,
		AFSDB	= 18,
		X25		= 19,
		ISDN	= 20,
		RT		= 21,
		NSAP	= 22,
		NSAP_PTR = 23,
		SIG		= 24,
		KEY		= 25,
		PX		= 26,
		GPOS	= 27,
		AAAA	= 28,
		LOC		= 29,
		NXT		= 30,
		EID		= 31,
		NIMLOC	= 32,
		SRV		= 33,
		ATMA	= 34,
		NAPTR	= 35,
		KX		= 36,
		CERT	= 37,
		A6		= 38,
		DNAME	= 39,
		SINK	= 40,
		OPT		= 41,
		APL		= 42,
		DS		= 43,
		SSHFP	= 44,
		IPSECKEY= 45,
		RRSIG	= 46,
		NSEC	= 47,
		DNSKEY	= 48,
		DHCID	= 49,
		NSEC3	= 50,
		NSEC3PARAM = 51,
		TLSA	= 52
	};
	operator uint16_t() const { return val; }
	// will only cache known cachable record types
	static bool is_cachable(dns_type_t tp) { return tp > 0 && tp <= 52 && tp != dns_type_t::OPT; }
	bool is_cachable() const { return is_cachable(*this); }
};

std::ostream &operator<<(std::ostream &out, const dns_type_t &q);

class dns_qtype_t : public dns_type_t
{
public:
	dns_qtype_t() {}
	dns_qtype_t(uint16_t v) : dns_type_t(v) {}
	dns_qtype_t(dns_type_t v) : dns_type_t(v) {}
	dns_qtype_t &operator=(uint16_t v) {
		*this=dns_qtype_t(v);
		return *this;
	}
	enum {
		MIN_QTYPE = 250, // [not a real known record type]
		IXFR	= 251, // request for incremental zone transfer (RFC 1996)
		AXFR	= 252, // request for zone transfer
		MAILB	= 253, // request for mailbox-related records (MB, MG or MR)
		MAILA	= 254, // request for mail agent RRs (obsolete - see MX)
		ANY = 255 // request for all records
	};
	operator uint16_t() const { return val; }
	static bool is_qtype(uint16_t v) { return v > MIN_QTYPE && v < ANY; }
};

std::ostream &operator<<(std::ostream &out, const dns_qtype_t &q);

class dns_class_t
{
protected:
	uint16_t val;
public:
	dns_class_t() {}
	dns_class_t(uint16_t v) : val(v) {}
	dns_class_t &operator=(uint16_t v) {
		*this=dns_class_t(v);
		return *this;
	}
	enum {
		INVALID = 0, // [not a real class; indicates uninitialized]
		IN		= 1, // The Internet
		CS		= 2, // CSNET (obsolete)
		CH		= 3, // CHAOS
		HS		= 4  // Hesiod
	};
	operator uint16_t() const { return val; }
};

std::ostream &operator<<(std::ostream &out, const dns_class_t &c);

class dns_qclass_t : public dns_class_t
{
public:
	dns_qclass_t() {}
	dns_qclass_t(uint16_t v) : dns_class_t(v) {}
	dns_qclass_t(dns_class_t v) : dns_class_t(v) {}
	dns_qclass_t &operator=(uint16_t v) {
		*this=dns_qclass_t(v);
		return *this;
	}
	enum {
		ANY = 255
	};
	operator uint16_t() const { return val; }
};

std::ostream &operator<<(std::ostream &out, const dns_qclass_t &c);

#endif // DNS_FIELD_H
