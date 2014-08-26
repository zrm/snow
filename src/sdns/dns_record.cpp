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

#include "dns_record.h"

void soa_rdata::read_fields(const uint8_t * data, size_t len)
{
	if(len < 5*sizeof(uint32_t))
		throw e_invalid_input("truncated data in soa_data");
	serial = read_hbo<uint32_t>(data);
	data += sizeof(uint32_t);
	refresh = read_hbo<uint32_t>(data);
	data += sizeof(uint32_t);
	retry = read_hbo<uint32_t>(data);
	data += sizeof(uint32_t);
	expire = read_hbo<uint32_t>(data);
	data += sizeof(uint32_t);
	minimum = read_hbo<uint32_t>(data);
}

void soa_rdata::write_fields(uint8_t * data) const
{
	write_hbo<uint32_t>(serial, data);
	data += sizeof(uint32_t);
	write_hbo<uint32_t>(refresh, data);
	data += sizeof(uint32_t);
	write_hbo<uint32_t>(retry, data);
	data += sizeof(uint32_t);
	write_hbo<uint32_t>(expire, data);
	data += sizeof(uint32_t);
	write_hbo<uint32_t>(minimum, data);
}


std::unique_ptr<rrset_data> rrset_data::get_rrset_data(dns_type_t rdata_type, dns_class_t rdata_class, ttlexp ttl)
{
	switch(rdata_type) {
	case dns_type_t::MB:
	case dns_type_t::MD:
	case dns_type_t::MF:
	case dns_type_t::MG:
	case dns_type_t::MR:
		// ^ these are all generic RFC1035 domain name types
		return std::unique_ptr<rrset_data>(new rrset_rdata<domain_name_rdata>(rdata_type, rdata_class, ttl));
	case dns_type_t::PTR:
		return std::unique_ptr<rrset_data>(new rrset_rdata<ptr_rdata>(rdata_type, rdata_class, ttl));
	case dns_type_t::NS:
		return std::unique_ptr<rrset_data>(new rrset_rdata<ns_rdata>(rdata_type, rdata_class, ttl));
	case dns_type_t::CNAME:
		return std::unique_ptr<rrset_data>(new rrset_rdata<cname_rdata>(rdata_type, rdata_class, ttl));
	case dns_type_t::SOA:
		return std::unique_ptr<rrset_data>(new rrset_rdata<soa_rdata>(rdata_type, rdata_class, ttl));
	case dns_type_t::MINFO:
		return std::unique_ptr<rrset_data>(new rrset_rdata<minfo_rdata>(rdata_type, rdata_class, ttl));
	case dns_type_t::MX:
		return std::unique_ptr<rrset_data>(new rrset_rdata<mx_rdata>(rdata_type, rdata_class, ttl));
	case dns_type_t::A:
		return std::unique_ptr<rrset_data>(new rrset_rdata<a_rdata>(rdata_type, rdata_class, ttl));
	case dns_type_t::AAAA:
		return std::unique_ptr<rrset_data>(new rrset_rdata<aaaa_rdata>(rdata_type, rdata_class, ttl));
	case dns_type_t::NULL_RR:
	case dns_type_t::WKS:
	case dns_type_t::HINFO:
	case dns_type_t::TXT:
	default:
		break;
	}
	return std::unique_ptr<rrset_data>(new rrset_rdata<default_rdata>(rdata_type, rdata_class, ttl));
}

std::ostream &operator<<(std::ostream &out, const rrset_data &rr)
{
	out << rr.RR_type << " " << rr.RR_class << " ttl: " << rr.expire.rel();
	rr.print_rdata(out);
	return out;
}

const rrset_rdata<default_rdata> dns_rrset::empty_rrset(dns_type_t::INVALID, dns_class_t::INVALID, ttlexp());

