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

#include "dns_field.h"


std::ostream &operator<<(std::ostream &out, const dns_opcode_t &op)
{
	switch(op.operator uint8_t()) {
	case dns_opcode_t::STANDARD_QUERY:
		out << "Standard Query"; break;
	case dns_opcode_t::INVERSE_QUERY:
		out << "Inverse Query"; break;
	case dns_opcode_t::SERVER_STATUS:
		out << "Server Status"; break;
	default:
		out << "[unknown opcode] (" << (int)op.operator uint8_t() << ")";
	}
		return out;
}

std::ostream &operator<<(std::ostream &out, const dns_rcode_t &r)
{
	switch(r.operator uint8_t()) {
	case dns_rcode_t::DNS_NO_ERROR:
		out << "NO_ERROR"; break;
	case dns_rcode_t::FORMAT_ERROR:
		out << "FORMAT_ERROR"; break;
	case dns_rcode_t::SERVFAIL:
		out << "SERVFAIL"; break;
	case dns_rcode_t::NAME_ERROR:
		out << "NXDOMAIN"; break;
	case dns_rcode_t::NOT_IMPLEMENTED:
		out << "NOT_IMPLEMENTED"; break;
	case dns_rcode_t::REFUSED:
		out << "REFUSED"; break;
	default:
		out << "[unknown rcode] (" << (int)r.operator uint8_t() << ")";
	}
		return out;
}


std::ostream &operator<<(std::ostream &out, const dns_type_t &q)
{
	switch(q.operator uint16_t()) {
	case 0: out << "INVALID"; break;
	case 1: out << "A"; break;
	case 2: out << "NS"; break;
	case 3: out << "MD"; break;
	case 4: out << "MF"; break;
	case 5: out << "CNAME"; break;
	case 6: out << "SOA"; break;
	case 7: out << "MB"; break;
	case 8: out << "MG"; break;
	case 9: out << "MR"; break;
	case 10: out << "NULL"; break;
	case 11: out << "WKS"; break;
	case 12: out << "PTR"; break;
	case 13: out << "HINFO"; break;
	case 14: out << "MINFO"; break;
	case 15: out << "MX"; break;
	case 16: out << "TXT"; break;
	case 17: out << "RP"; break;
	case 18: out << "AFSDB"; break;
	case 19: out << "X25"; break;
	case 20: out << "ISDN"; break;
	case 21: out << "RT"; break;
	case 22: out << "NSAP"; break;
	case 23: out << "NSAP_PTR"; break;
	case 24: out << "SIG"; break;
	case 25: out << "KEY"; break;
	case 26: out << "PX"; break;
	case 27: out << "GPOS"; break;
	case 28: out << "AAAA"; break;
	case 29: out << "LOC"; break;
	case 30: out << "NXT"; break;
	case 31: out << "EID"; break;
	case 32: out << "NIMLOC"; break;
	case 33: out << "SRV"; break;
	case 34: out << "ATMA"; break;
	case 35: out << "NAPTR"; break;
	case 36: out << "KX"; break;
	case 37: out << "CERT"; break;
	case 38: out << "A6"; break;
	case 39: out << "DNAME"; break;
	case 40: out << "SINK"; break;
	case 41: out << "OPT"; break;
	case 42: out << "APL"; break;
	case 43: out << "DS"; break;
	case 44: out << "SSHFP"; break;
	case 45: out << "IPSECKEY"; break;
	case 46: out << "RRSIG"; break;
	case 47: out << "NSEC"; break;
	case 48: out << "DNSKEY"; break;
	case 49: out << "DHCID"; break;
	case 50: out << "NSEC3"; break;
	case 51: out << "NSEC3PARAM"; break;
	case 52: out << "TLSA"; break;
	default:
		out << "[unknown type (" << q.operator uint16_t() << ")]";
	}
		return out;
}


std::ostream &operator<<(std::ostream &out, const dns_qtype_t &q)
{
	switch(q.operator uint16_t()) {
	case 251:
		out << "IXFR"; break;
	case 252:
		out << "AXFR"; break;
	case 253:
		out << "MAILB"; break;
	case 254:
		out << "MAILA"; break;
	case 255:
		out << "ANY"; break;
	default:
		out << dns_type_t(q.operator uint16_t());
	}
	return out;
}

std::ostream &operator<<(std::ostream &out, const dns_class_t &c)
{
	switch(c.operator uint16_t()) {
	case 0 :
		out << "INVALID"; break;
	case 1 :
		out << "IN"; break;
	case 2 :
		out << "CS"; break;
	case 3 :
		out << "CH"; break;
	case 4 :
		out << "HS"; break;
	default:
		out << "[unknown class (" << c.operator uint16_t() << ")]";
	}
	return out;
}


std::ostream &operator<<(std::ostream &out, const dns_qclass_t &c)
{
	switch(c.operator uint16_t()) {
	case 255:
		out << "ANY"; break;
	default:
		out << dns_class_t(c.operator uint16_t());
	}
	return out;
}
