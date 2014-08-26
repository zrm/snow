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

#ifndef DNS_MESSAGE_H
#define DNS_MESSAGE_H
#include<iostream>
#include<cstdint>
#include<vector>
#include<bitset>
#include<memory>
#include<string>
#include<random>
#include<stdexcept>
#include<chrono>
#include<set>
#include<unordered_map>
#include"../common/err_out.h"
#include"../common/common.h"
#include"configuration.h"
#include"domain_name.h"
#include"dns_record.h"
#include"dns_field.h"


enum IP_FAMILY { IPV4 = 1, IPV6 = 2 };

struct dns_header
{
	uint16_t id; // identifier to match queries with replies (NBO)
	bool qr, aa, tc, rd, ra; // query, authoritative answer, truncated, recursion desired, recursion available
	dns_opcode_t opcode;
	uint8_t z; // reserved/zero
	dns_rcode_t rcode;
	uint16_t qdcount; // # question RRs
	uint16_t ancount; // # answer RRs
	uint16_t nscount; // # name server RRs [in authority section]
	uint16_t arcount; // # additional RRs
	static size_t size() { return 12; }
	dns_header(uint16_t h_id, bool h_qr, bool h_aa, bool h_tc, bool h_rd, bool h_ra, uint8_t h_opcode, uint8_t h_rcode, uint16_t qdc, uint16_t anc, uint16_t nsc, uint16_t arc)
		: id(h_id), qr(h_qr), aa(h_aa), tc(h_tc), rd(h_rd), ra(h_ra), opcode(h_opcode), z(0), rcode(h_rcode), qdcount(qdc), ancount(anc), nscount(nsc), arcount(arc) {}
	dns_header(const uint8_t *header, size_t sz);
	size_t write(uint8_t *header) const;
};

std::ostream &operator<<(std::ostream & out, const dns_header &hdr);


class dns_question
{
	domain_name_qs q_name;
	dns_qtype_t q_type;
	dns_qclass_t q_class;
public:
	dns_question(const uint8_t *msg, size_t *offset, size_t msg_size);
	// must be explicit, some functions may take either a dns_question or the same args as this constructor
	explicit dns_question(const domain_name &qn, dns_qtype_t qt, dns_qclass_t qc) : q_name(qn), q_type(qt), q_class(qc) {}
	size_t maxsize() const { return q_name.maxsize() + sizeof(q_type) + sizeof(q_class); }
	uint16_t write(uint8_t *msg, uint16_t msg_offset, dns_compression_node &dcn) const;
	bool operator==(const dns_question &q) const { return q_name == q.q_name && q_type == q.q_type && q_class == q.q_class; }
	bool operator!=(const dns_question &q) const { return !(*this == q); }
	// case-insensitive less
	struct ci_less {
		bool operator() (const dns_question& x, const dns_question& y) const {
			if(x.q_type != y.q_type)
				return x.q_type < y.q_type;
			if(x.q_class != y.q_class)
				return x.q_class < y.q_class;
			return x.q_name.get_name() < y.q_name.get_name();
		}
	};
	dns_qtype_t qtype() const { return q_type; }
	dns_qclass_t qclass() const { return q_class; }
	const domain_name_qs & qname() const { return q_name; }
};

std::ostream &operator<<(std::ostream &out, const dns_question &q);


class edns_options
{
	std::bitset<32> flags;
	uint16_t udp_bufsize;
	uint8_t e_rcode; // extended rcode
	uint8_t version;
	uint16_t rdata_len;
	enum FLAGS { D0 /*DNSSEC OK*/, RESERVED1, RESERVED2, RESERVED3, RESERVED4, RESERVED5, RESERVED6, RESERVED7, RESERVED8,
				 RESERVED9, RESERVED10, RESERVED11, RESERVED12, RESERVED13, RESERVED14, RESERVED15, /*meta flags:*/ EDNS_PRESENT, INVALID_DUPLICATE};
public:
	edns_options(const uint8_t *msg, size_t *off, size_t msglen);
	edns_options() : udp_bufsize(512), e_rcode(0), version(0), rdata_len(0) {}
	edns_options(uint16_t udp_size, uint8_t rc, uint8_t vers) : udp_bufsize(udp_size), e_rcode(rc), version(vers), rdata_len(0) { flags[EDNS_PRESENT] = true; }
	size_t maxsize() const { return 11; } // size is fixed, TODO: update this when any options are actually implemented
	size_t write(uint8_t *msg, size_t offset) const;

	bool dnssec_ok() const { return flags[D0]; }
	uint8_t edns_version() const { return version; }
	uint16_t extended_rcode(uint16_t rcode) const { return (e_rcode << 4) + rcode; }
	uint16_t get_udp_bufsize() const { return (udp_bufsize < 512) ? 512 : udp_bufsize; }
	bool edns_present() const { return flags[EDNS_PRESENT]; }
	void mark_duplicate() { flags[INVALID_DUPLICATE] = true; }
	bool duplicate_exists() const { return flags[INVALID_DUPLICATE]; }
	void print(std::ostream &out) const;
};

inline std::ostream &operator<<(std::ostream &out, const edns_options &o)
{
	o.print(out);
	return out;
}

class dns_rr_section
{
protected:
	std::vector<dns_rrset> rrsets;
	edns_options options;
	size_t parse_edns_options(const uint8_t *msg, size_t offset, size_t msglen);
public:
	dns_rr_section(const uint8_t *msg, size_t *off, size_t msglen, size_t rr_count);
	dns_rr_section() {}
	size_t maxsize() const;
	size_t write(uint8_t *msg, size_t offset, dns_compression_node &dcn) const;
	const rrset_data &get_rrset(const domain_name &name, dns_type_t tp, dns_class_t cl) const;
	bool rrset_exists(const domain_name &name, dns_class_t cl) const;
	// get SOA record from authority section for use with NXDOMAIN/NODATA
	const dns_rrset *get_authority_soa(const domain_name &qname) const;
	const edns_options &get_edns_options() const { return options; }
	void set_edns_options(const edns_options &o) { options = o; }
	bool nodata() const;

	// follows a CNAME record [chain] to the end in the given section, returns the CNAME chain in chain order
	// this works differently for CNAME loops than dns_cache_node::follow_cname():
		// in follow_cname() a CNAME loop is detected and an exception is thrown
		// here the full chain is returned up to the point where it would loop
		// because in this context the loop is not necessarily authoritative,
		// e.g. one of the CNAME records could be from the wrong NS or forwarder, so when the authoritative server is queried the records might not loop
	// args: name: cname record name, cname: cname record rrset_data, type: target type
	std::vector< dns_record<cname_rdata> > get_cname_chain(const domain_name& name, const rrset_data &cname, dns_type_t qtype) const;
	std::vector< dns_record<cname_rdata> > get_cname_chain(const dns_question &q) const {
		return get_cname_chain(q.qname(), get_rrset(q.qname(), dns_type_t::CNAME, q.qclass()), q.qtype());
	}
	void clear() { rrsets.clear(); }
	void print(std::ostream &out) const;
	std::vector<dns_rrset>::const_iterator begin() const { return rrsets.begin(); }
	std::vector<dns_rrset>::const_iterator end() const { return rrsets.end(); }
	size_t rrset_count() const { return rrsets.size(); }
	template<class...RR_ARGS> size_t emplace_rrset(RR_ARGS &&...r) {
		rrsets.emplace_back(std::forward<RR_ARGS>(r)...);
		rrsets.back().rrdata->randomize_rdata_order();
		return rrsets.back().rrdata->record_count();
	}
};

inline std::ostream &operator<<(std::ostream &out, const dns_rr_section &s)
{
	s.print(out);
	return out;
}

class dns_message
{
	dns_header hdr; // header
	std::vector<dns_question> qs; // question section
	dns_rr_section an; // answer section
	dns_rr_section ns; // authority section
	dns_rr_section ar; // additional section
public:
	dns_message() :hdr(0, false, false, false, false, false, 0, 0, 0, 0, 0, 0) {}
	dns_message(const uint8_t *msg, size_t msglen);
	dns_message(uint16_t id, bool qr, bool aa, bool rd, dns_opcode_t opcode, dns_rcode_t rcode, std::vector<dns_question> q, bool edns_opt);
	dns_message(uint16_t id, bool qr, bool aa, bool rd, dns_opcode_t opcode, dns_rcode_t rcode, const dns_question &q, bool edns_opt)
		: dns_message(id, qr, aa, rd, opcode, rcode, std::vector<dns_question>(1, q), edns_opt) {}

	void print(std::ostream &out) const;
	size_t maxsize() const;
	size_t write(uint8_t *buf) const;
	const dns_header &header() const { return hdr; }
	const std::vector<dns_question>& question() const { return qs; }
	const dns_rr_section &answer() const { return an; }
	const dns_rr_section &authority() const { return ns; }
	const dns_rr_section &additional() const { return ar; }
	template<class...RR> void emplace_answer(RR &&...r) { hdr.ancount += an.emplace_rrset(std::forward<RR>(r)...); }
	template<class...RR> void emplace_authority(RR &&...r) { hdr.nscount += ns.emplace_rrset(std::forward<RR>(r)...); }
	template<class...RR> void emplace_additional(RR &&...r) { hdr.arcount += ar.emplace_rrset(std::forward<RR>(r)...); }
	void set_id(uint16_t id) { hdr.id = id; }
	void truncate();
};

inline std::ostream &operator<<(std::ostream &out, const dns_message &m)
{
	m.print(out);
	return out;
}


#endif // DNS_MESSAGE_H
