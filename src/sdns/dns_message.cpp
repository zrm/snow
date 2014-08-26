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

#include "../sdns/dns_message.h"
#include "../sdns/configuration.h"
#include<sstream>
#include<algorithm>



dns_header::dns_header(const uint8_t *header, size_t sz)
{
	if(sz < size())
		throw e_invalid_input("dns_header: incomplete header");
	id = read_nbo<uint16_t>(header);
	header += sizeof(id);
	read_bits(*header, &rd, 1, &tc, 1, &aa, 1, &opcode, 4, &qr, 1);
	header += 1;
	read_bits(*header, &rcode, 4, &z, 3, &ra, 1);
	header += 1;
	qdcount = read_hbo<uint16_t>(header);
	header += sizeof(qdcount);
	ancount = read_hbo<uint16_t>(header);
	header += sizeof(ancount);
	nscount = read_hbo<uint16_t>(header);
	header += sizeof(nscount);
	arcount = read_hbo<uint16_t>(header);
	header += sizeof(arcount);
}

size_t dns_header::write(uint8_t *header) const
{
	write_nbo<uint16_t>(id, header);
	header += sizeof(id);
	write_bits(*header, qr, 1, opcode, 4, aa, 1, tc, 1, rd, 1);
	header += 1;
	write_bits(*header, ra, 1, z, 3, rcode, 4);
	header += 1;
	write_hbo<uint16_t>(qdcount, header);
	header += sizeof(qdcount);
	write_hbo<uint16_t>(ancount, header);
	header += sizeof(ancount);
	write_hbo<uint16_t>(nscount, header);
	header += sizeof(nscount);
	write_hbo<uint16_t>(arcount, header);
	header += sizeof(arcount);
	return size();
}

std::ostream &operator<<(std::ostream & out, const dns_header &hdr)
{
	out << " [ id: " << ntohs(hdr.id) << " qr:" << hdr.qr << " authoritative answer: " << hdr.aa << " truncated: " << hdr.tc
		<< " recursion desired: " << hdr.rd << " recursion available: " << hdr.ra << " opcode: " << dns_opcode_t(hdr.opcode) << " z: " << (int)hdr.z << " rcode: " << dns_rcode_t(hdr.rcode)
		<< " qd: " << hdr.qdcount << " an: " << hdr.ancount << " ns: " << hdr.nscount << " ar: " << hdr.arcount << " ] ";
	return out;
}


dns_question::dns_question(const uint8_t *msg, size_t *offset, size_t msg_size) : q_name(dns_raw_msg(msg, msg_size), offset)
{
	if(msg_size - *offset < sizeof(q_type) + sizeof(q_class))
		throw e_invalid_input("no qtype/qclass in dns question");
	const uint8_t *data = msg + *offset;
	q_type = read_hbo<uint16_t>(data);
	data += sizeof(uint16_t);
	q_class = read_hbo<uint16_t>(data);
	*offset += sizeof(q_type) + sizeof(q_class);
}

uint16_t dns_question::write(uint8_t *msg, uint16_t msg_offset, dns_compression_node &dcn) const
{
	msg_offset = q_name.write_qname(msg, msg_offset, dcn);
	write_hbo<uint16_t>(q_type, msg+msg_offset);
	write_hbo<uint16_t>(q_class, msg+msg_offset+sizeof(q_type));
	return msg_offset + sizeof(q_type) + sizeof(q_class);
}

std::ostream &operator<<(std::ostream &out, const dns_question &q)
{
	out << q.qname() << ", qtype: " << q.qtype() << " , qclass: " << q.qclass();
	return out;
}


edns_options::edns_options(const uint8_t *msg, size_t *off, size_t msglen)
{
	// this starts after reading the (blank) domain name and type of the record, so the first field is the "class" / UDP size
	flags[EDNS_PRESENT] = true;
	size_t offset = *off;
	udp_bufsize = read_hbo<uint16_t>(msg + offset);
	offset += sizeof(udp_bufsize);
	e_rcode = msg[offset++];
	version = msg[offset++];
	flags[D0] = msg[offset++] & 0x80; // D0: "DNSSEC OK" bit
	offset++; // last byte of "TTL" field ("Z") is ignored per RFC6891 Sec. 6.1.3
	rdata_len = read_hbo<uint16_t>(msg + offset);
	offset += sizeof(rdata_len);
	if(offset + rdata_len > msglen)
		throw e_invalid_input("truncated rdata in EDNS0 OPT record");
	// [rdata is currently ignored since none of the options are implemented; key:value pairs should be read here, RFC6891 Sec. 6.1.2]
	*off = offset + rdata_len;
}

size_t edns_options::write(uint8_t *msg, size_t offset) const {
	offset = domain_name::root.write(msg, offset);
	write_hbo<uint16_t>(dns_type_t::OPT, msg+offset);
	offset += sizeof(uint16_t);
	write_hbo<uint16_t>(udp_bufsize, msg+offset);
	offset += sizeof(udp_bufsize);
	msg[offset++] = e_rcode;
	msg[offset++] = version;
	msg[offset++] = flags[D0] ? 0x80 : 0x00;
	msg[offset++] = 0x00; // Z
	write_hbo<uint16_t>(0, msg+offset); // rdata_len
	return offset + sizeof(uint16_t);
}

void edns_options::print(std::ostream &out) const
{
	out << "EDNS OPT pseudo-RR: UDP size: " << udp_bufsize << " extended rcode: " << (int)e_rcode
		   << " version: " << (int)version << " D0 flag: " << flags[D0] << " rdata_len: " << rdata_len;
}

size_t dns_rr_section::parse_edns_options(const uint8_t *msg, size_t offset, size_t msglen)
{
	if(options.edns_present()) {
		options.mark_duplicate();
		uint16_t rdata_len = read_hbo<uint16_t>(msg + offset + 6/* sizeof(class) + sizeof(ttl)*/);
		return offset + 8/* sizeof(ttl+class+rdata_len) */ + rdata_len;
	}
	options = edns_options(msg, &offset, msglen);
	return offset;
}

dns_rr_section::dns_rr_section(const uint8_t *msg, size_t *off, size_t msglen, size_t rr_count)
{
	uint16_t rdata_len;
	dns_type_t rr_type;
	dns_class_t rr_class;
	uint32_t ttl;
	size_t offset = *off;
	const size_t fixedfield_size = sizeof(rr_type) + sizeof(rr_class) + sizeof(ttl) + sizeof(rdata_len);
	for(size_t i=0; i < rr_count; ++i) {
		domain_name name = domain_name(dns_raw_msg(msg, msglen), &offset);
		if(msglen - offset < fixedfield_size)
			throw e_invalid_input("got truncated data reading rrset_data");
		rr_type = read_hbo<uint16_t>(msg + offset);
		offset += sizeof(rr_type);
		if(rr_type == dns_type_t::OPT) {
			offset = parse_edns_options(msg, offset, msglen);
			continue;
		}
		rr_class = read_hbo<uint16_t>(msg + offset);
		offset += sizeof(rr_class);
		if(dns_qtype_t::is_qtype(rr_type) || rr_type == dns_type_t::INVALID || rr_class == dns_qclass_t::ANY || rr_class == dns_class_t::INVALID)
			throw e_invalid_input("dns_rr_section got invalid type or class in record");
		ttl = read_hbo<uint32_t>(msg + offset);
		offset += sizeof(ttl);
		rdata_len = read_hbo<uint16_t>(msg + offset);
		offset += sizeof(rdata_len);
		if(msglen - offset < rdata_len)
			throw e_invalid_input("got truncated rdata reading rrset_data");
		// check for correct rrset to add to, or create a new one
		size_t idx = 0;
		while(idx < rrsets.size() && (rrsets[idx].get_type() != rr_type || rrsets[idx].get_class() != rr_class || rrsets[idx].get_name() != name))
			++idx;
		if(idx == rrsets.size())
			rrsets.emplace_back(std::move(name), rr_type, rr_class, ttlexp(ttl));
		rrsets[idx].add_record(dns_raw_msg(msg, offset + rdata_len), offset);
		offset += rdata_len;
	}
	*off = offset;
}

size_t dns_rr_section::maxsize() const
{
	size_t sz=0;
	for(const dns_rrset &r : rrsets)
		sz += r.maxsize();
	if(options.edns_present())
		sz += options.maxsize();
	return sz;
}

size_t dns_rr_section::write(uint8_t *msg, size_t offset, dns_compression_node &dcn) const
{
	if(options.edns_present())
		offset = options.write(msg, offset);
	for(const dns_rrset &r : rrsets)
		offset = r.write(msg, offset, dcn);
	return offset;
}

const rrset_data &dns_rr_section::get_rrset(const domain_name &name, dns_type_t tp, dns_class_t cl) const
{
	for(const dns_rrset &r : rrsets)
		if(r.get_name() == name && r.get_type() == tp && r.get_class() == cl)
			return *r.rrdata;
	return dns_rrset::empty_rrset;
}

bool dns_rr_section::rrset_exists(const domain_name &name, dns_class_t cl) const
{
	for(const dns_rrset &r : rrsets)
		if(r.get_name() == name && r.get_class() == cl)
			return true;
	return false;
}

const dns_rrset *dns_rr_section::get_authority_soa(const domain_name &qname) const
{
	// this is different than get_rrset(): needs to get SOA with same name root rather than same entire name
	for(const dns_rrset &rr : rrsets) {
		if(rr.rrdata->get_type() == dns_type_t::SOA && rr.rrdata->record_count() == 1 /*(should never be more than one SOA record)*/) {
			const domain_name &name = rr.get_name();
			if(name.num_labels() <= qname.num_labels() && qname.get_root(name.num_labels()).name == name) {
				return &rr;
			}
		}
	}
	return nullptr;
}

bool dns_rr_section::nodata() const
{
	// a response is NODATA if the authority section contains an SOA record or contains no NS record (and the answer section does not contain the answer)
	bool rv = true;
	for(const dns_rrset &r : rrsets) {
		if(r.get_type() == dns_type_t::NS) {
			rv = false;
		} else if(r.get_type() == dns_type_t::SOA && r.rrdata->record_count() == 1/*(should only be one SOA record)*/) {
			return true;
		}
	}
	return rv;
}

std::vector< dns_record<cname_rdata> > dns_rr_section::get_cname_chain(const domain_name& name, const rrset_data &cname, dns_type_t qtype) const
{
	// multiple CNAME records are not allowed (RFC1912 Sec. 2.4), if we get one from a non-compliant server we just pick one and ignore the other(s)
		// TODO: maybe SERVFAIL instead?
	if(qtype == dns_type_t::CNAME || cname.get_type() != dns_type_t::CNAME || cname.record_count() == 0)
		return std::vector< dns_record<cname_rdata> >();
	std::vector< dns_record<cname_rdata> > cname_chain;
	cname_chain.emplace_back(name, cname.get_type(), cname.get_class(), cname.expire, cname.get<cname_rdata>().rdata.front());
	std::vector<bool> rrset_used(rrsets.size(), false); // keep track of which rrsets have been followed to avoid loops
	bool check_again;
	do {
		const dns_record<cname_rdata> *target = &cname_chain.back();
		check_again = false;
		for(size_t i=0; i < rrsets.size(); ++i) {
			const dns_rrset &r = rrsets[i];
			if(rrset_used[i] == false && target->rdata.name == r.get_name()) {
				if(r.get_type() == dns_type_t::CNAME && r.rrdata->record_count() > 0 && r.get_class() == target->get_class()) {
					cname_chain.emplace_back(r.name, r.get_type(), r.get_class(), r.rrdata->expire, r.rrdata->get<cname_rdata>().rdata.back());
					target = &cname_chain.back();
					check_again = true;
					rrset_used[i] = true;
				} else if(r.get_type() == qtype && r.get_class() == target->get_class()) {
					check_again = false;
					break;
				}
			}
		}
	} while(check_again);
	return std::move(cname_chain);
}

void dns_rr_section::print(std::ostream &out) const
{
	if(options.edns_present())
		out << " " << options << "\n";
	for(const dns_rrset &r : rrsets)
		out << " " << r << "\n";
}

dns_message::dns_message(const uint8_t *msg, size_t msglen) : hdr(msg, msglen)
{
	size_t offset = dns_header::size();
	for(size_t i=0; i < hdr.qdcount; ++i)
		qs.emplace_back(msg, &offset, msglen);
	an = dns_rr_section(msg, &offset, msglen, hdr.ancount);
	ns = dns_rr_section(msg, &offset, msglen, hdr.nscount);
	ar = dns_rr_section(msg, &offset, msglen, hdr.arcount);
}

dns_message::dns_message(uint16_t id, bool qr, bool aa, bool rd, dns_opcode_t opcode, dns_rcode_t rcode, std::vector<dns_question> q, bool edns_opt)
	: hdr(id, qr, aa, false/*not truncated (yet)*/, rd, qr/*ra is true for responses*/, opcode, rcode, q.size()/*qdcount*/, 0/*ancount*/, 0/*nscount*/, edns_opt ? 1 : 0/*arcount*/),
	  qs(std::move(q))
{
	if(edns_opt)
		ar.set_edns_options(edns_options(sdns::conf[sdns::MAX_UDP_SIZE], 0/*extended rcode*/, 0/*version*/));
}

void dns_message::print(std::ostream &out) const
{
	out << "header: " << hdr << "\n question: ";
	for(size_t i=0; i < qs.size(); ++i)
		out << qs[i] << " ";
	out << "\n answer:\n" << an;
	out << " authority:\n" << ns;
	out << " additional:\n" << ar;
}

size_t dns_message::maxsize() const
{
	size_t sz = dns_header::size();
	for(const dns_question &q : qs)
		sz += q.maxsize();
	sz += an.maxsize();
	sz += ns.maxsize();
	sz += ar.maxsize();
	return sz;
}

size_t dns_message::write(uint8_t *buf) const
{
	dns_compression_node root;
	size_t offset = hdr.write(buf);
	for(const dns_question &q : qs)
		offset = q.write(buf, offset, root);
	offset = an.write(buf, offset, root);
	offset = ns.write(buf, offset, root);
	offset = ar.write(buf, offset, root);
	return offset;
}

void dns_message::truncate()
{
	// discard everything but the header, question section and OPT record (if present [according to RFC6891 Sec. 7]),
	// the client is only going to ignore it and retry with EDNS or TCP anyway
	hdr.tc = true;
	an.clear();
	hdr.ancount = 0;
	ns.clear();
	hdr.nscount = 0;
	ar.clear();
	hdr.arcount = (ar.get_edns_options().edns_present() ? 1 : 0);
}



