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

#include<memory>
#include "domain_name.h"
#include "../common/err_out.h"

const uint8_t domain_label::root(0);
const uint8_t domain_label::invalid[9] = "\7invalid";

void domain_label::validate() const
{
	if(label==nullptr)
		throw e_invalid_input("nullptr domain_label");
	if(label[0] == 0)
		throw e_invalid_input("empty domain_label");
	if(label[0] > 63)
		throw e_invalid_input("domain_label too long");
	// RFC 2181 (and others) say that a DNS label can contain arbitrary binary data,
	// but DNS labels are required to be compared 'case insensitive' (i.e. example.com is equivalent to EXAMPLE.COM) according to RFC1035,
		// which makes full binary encoding impossible because it makes e.g. 0x41 equivalent to 0x61
	// moreover, this implies that you could have a DNS label containing characters such as '.' or '\0' and no good can possibly come of that
		// so we reject anything other than  [a-zA-Z0-9], '-' and '_'
	const char* lbl = (const char*)(label+1);
	for(unsigned i=0; i < label[0]; ++i)
		if(!isalnum(lbl[i]) && lbl[i] != '-' && lbl[i] != '_') {
			std::string errorstr("Invalid character in domain_label: ?");
			errorstr.back() = lbl[i];
			throw e_invalid_input(errorstr);
		}
}

const domain_name domain_name::root(&domain_label::root);

domain_name::domain_name(const std::string &dname) /* throws e_invalid_input */
{
	size_t size = (dname.size() == 0 || dname.back() != '.') ? dname.size() : dname.size() - 1;
	if(size > 253)
		throw e_invalid_input("domain_name(string): domain name exceeded maximum length");
	if(size == 0) {
		name = &domain_label::root;
		return;
	}
	unsigned nlabels = 0;
	std::unique_ptr<uint8_t[]> ptr(new uint8_t[size+4]);
	memcpy(ptr.get()+3, dname.c_str(), size);
	size_t pos = 0, next_pos;
	do {
		next_pos = dname.find_first_of('.', pos);
		ptr[pos+2] = (next_pos < size) ? (next_pos - pos) : (size - pos);
		domain_label(ptr.get() + pos + 2).validate(); // throws e_invalid_input
		++nlabels;
		pos = next_pos + 1;
	} while(next_pos < size);
	ptr[0] = (0x80 | nlabels);
	ptr[1] = size + 2;
	ptr[size+3] = 0;
	make_lowercase(ptr.get() + 2);
	name = ptr.release();
}


domain_name::domain_name(dns_raw_msg dnsmsg, size_t *off, std::vector<bool> *case_bitmask)
{
	size_t offset = *off;
	size_t start_jump = offset;
	if(dnsmsg.len <= offset)
		throw e_invalid_input("domain_name(dnsmsg): no bytes where domain name expected");
	size_t total_length = 0; // sum of the lengths of each label including each label length byte
	size_t nlabels = 0;
	unsigned label_offsets[128];
	uint8_t label_lengths[128];
	uint8_t nextsize = dnsmsg.msg[offset];
	while(nextsize) {
		switch(nextsize & 0xc0) {
		case 0xc0:
			// ptr (two bytes)
			if(dnsmsg.len < offset + sizeof(uint16_t))
				throw e_invalid_input("domain_name(dnsmsg): truncated DNS label compression pointer in domain_name");
			if(off != nullptr) {
				*off = offset + sizeof(uint16_t); // domain_name data has ended, set end offset before following ptr
				off = nullptr;
			}
			offset = ((nextsize & 0x3f) << 8) + dnsmsg.msg[offset+1];
			// check offset against start_jump because a jump to anywhere at or past the point of the last jump could create a loop
			// this also verifies that ptr is less than dnsmsg.len since start_jump is always less than dnsmsg.len
			if(start_jump <= offset)
				throw e_invalid_input("domain_name(dnsmsg): invalid jump in domain_name label pointer");
			start_jump = offset;
			nextsize = dnsmsg.msg[offset];
			continue;
		case 0x00:
			++nextsize; // label length, add one for length byte itself
			break;
		default:
			throw e_invalid_input("domain_name(dnsmsg): domain name label length field contained reserved/unimplemented value");
		}
		if(offset + nextsize >= dnsmsg.len)
			throw e_invalid_input("domain_name(dnsmsg): truncated data while parsing domain name");
		total_length += nextsize;
		if(total_length > 254)
			throw e_invalid_input("domain_name(dnsmsg): domain name exceeded maximum length");
		domain_label(dnsmsg.msg + offset).validate(); // throws e_invalid_input
		label_offsets[nlabels] = offset;
		label_lengths[nlabels] = nextsize;
		++nlabels;
		offset += nextsize;
		nextsize = dnsmsg.msg[offset];
	}
	if(off != nullptr) // *off was assigned and then ptr set to nullptr above if following a label compression jump
		*off = offset + 1; // +1 for '\0' root label
	++total_length; // root label
	std::unique_ptr<uint8_t[]> ptr(new uint8_t[total_length + 2]); // +2 for num labels and total length bytes
	ptr[0] = (0x80 | nlabels); // set high bit, indicates pointer ownership
	ptr[1] = total_length;
	offset = 2;	
	for(size_t i=0; i < nlabels; ++i) {
		memcpy(ptr.get() + offset, dnsmsg.msg + label_offsets[i], label_lengths[i]);
		offset += label_lengths[i];
	}
	ptr[total_length + 1] = 0; // root label
	if(case_bitmask != nullptr) {
		*case_bitmask = std::vector<bool>(total_length);
		set_case_bitmask(ptr.get() + 2, *case_bitmask);
	}
	make_lowercase(ptr.get() + 2);
	name = ptr.release();
}

domain_name::domain_name(const uint8_t ** cache_data, size_t * datalen) {
	const uint8_t* data = *cache_data;
	size_t len = *datalen, namelen = 0, nlabels = 0;
	if(len == 0) throw e_invalid_input("no data provided to domain_name cache constructor");
	if(data[0] == 0) {
		namelen = 1;
		name = &domain_label::root;
	} else {
		while(data[namelen] != 0) {
			namelen += data[namelen] + 1;
			++nlabels;
			if(namelen >= len || namelen > 254) throw e_invalid_input("invalid or truncated data in domain_name cache constructor");
		}
		++namelen; // root
		std::unique_ptr<uint8_t[]> dname(new uint8_t[namelen + 2]);
		dname[0] = (0x80 | nlabels);
		dname[1] = namelen;
		memcpy(dname.get() + 2, data, namelen);
		name = dname.release();
	}
	*datalen -= namelen;
	*cache_data += namelen;
}

domain_name &domain_name::operator=(domain_name &&dn)
{
	// only move if there is actually something that can be moved, otherwise copy
	if(dn.name[0] & 0x80)
		std::swap(name, dn.name);
	else
		*this = dn;
	return *this;
}

domain_name &domain_name::operator=(const domain_name &dn) {
	if(&dn == this) return *this;
	if(name[0] & 0x80) delete[] name;
	if(dn.name == &domain_label::root || dn.name == domain_label::invalid) {
		name = dn.name;
	} else {
		size_t len = dn.wire_len();
		std::unique_ptr<uint8_t[]> dname(new uint8_t[len+2]);
		dname[0] = (0x80 | dn.num_labels());
		dname[1] = len;
		memcpy(dname.get()+2, dn.wire_start(), len);
		name = dname.release();
	}
	return *this;
}

void domain_name::make_lowercase(uint8_t * name)
{
	for(int i=0, next_label = -1; name[i] != 0; ++i)
		if(i <= next_label)
			name[i] = ::tolower(name[i]);
		else
			next_label += 1 + name[i];
}

void domain_name::set_case_bitmask(const uint8_t * name, std::vector<bool>& bitmask) {
	for(int i=0, next_label = -1; name[i] != 0; ++i)
		if(i <= next_label)
			bitmask[i] = isupper(name[i]);
		else
			next_label += 1 + name[i];
}

unsigned domain_name::wire_len() const {
	if(name[0] & 0x80) return name[1];
	unsigned len = 0;
	while(name[len] != 0) len += 1 + name[len];
	return len + 1;
}

unsigned domain_name::num_labels() const {
	if(name[0] & 0x80) return (name[0] & 0x7f);
	unsigned nlabels = 0;
	const uint8_t * label = name;
	while(label[0] != 0) {
		++nlabels;
		label += label[0] + 1;
	}
	return nlabels;
}

// get_root returns a domain_name which is in reality a pointer to the interior of this name
	// it is returned as a const member of a private structure, requiring it to be copy constructed into new memory if not used as a temporary
domain_name::domain_name_root domain_name::get_root(size_t depth) const
{
	unsigned labels = num_labels();
	if(depth >= labels)	return wire_start();
	labels -= depth;
	if(labels == 0) return &domain_label::root;
	const uint8_t * start = wire_start();
	while(labels) {
		start += 1 + start[0];
		--labels;
	}
	return start;
}

domain_label domain_name::from_root(size_t num) const {
	unsigned labels = num_labels();
	if(num >= labels) return domain_label(domain_label::invalid);
	return from_leaf(labels - 1 - num);
}
domain_label domain_name::from_leaf(size_t num) const {
	if(num >= num_labels()) return domain_label(&domain_label::root);
	unsigned label = (name[0] & 0x80) ? 2 : 0;
	for(; num; --num)
		label += 1 + name[label];
	return domain_label(name+label);
}


bool domain_name::operator==(const domain_name &dn) const {
	unsigned len = wire_len(), dlen = dn.wire_len();
	if(len != dlen) return false;
	return memcmp(wire_start(), dn.wire_start(), len-1) == 0;
}
bool domain_name::operator<(const domain_name &dn) const {
	unsigned len = wire_len(), dlen = dn.wire_len();
	if(len != dlen) return len < dlen;
	return memcmp(wire_start(), dn.wire_start(), len) < 0;
}
std::string domain_name::to_string() const {
	unsigned labels = num_labels();
	if(labels == 0) return ".";
	std::string rv;
	for(size_t i=0; i < labels; ++i) {
		rv += from_leaf(i).get_string();
		rv += ".";
	}
	return rv;
}
std::string domain_name::to_lstring() const {
	unsigned labels = num_labels();
	std::string rv;
	rv += '(' + std::to_string(wire_len()) + ')';
	rv += '(' + std::to_string(labels) + ") ";
	if(labels == 0) return rv + "[0]";
	for(size_t i=0; i < labels; ++i) {
		rv += '['+ std::to_string(from_leaf(i).len()) + ']' + from_leaf(i).get_string();
	}
	return rv + '[' + std::to_string(*(wire_start()+wire_len()-1)) + ']';
}
size_t domain_name::hash() const {
	// djb's hash again, this one for std::hash
	size_t result = 5381, len = wire_len();
	const uint8_t * key = wire_start();
	while (len) {
		result = (result << 5) + result;
		result ^= *key;
		++key;
		--len;
	}
	return result;
}

/*
Interaction between domain_name::write() and domain_name_qs::write():
	domain_name_qs::write() calls domain_name::write(uint8_t *buf, size_t offset, dns_compression_node::compression_match cmatch)
	where the domain_name is not necessarily all lowercase (as it normally is)
	so be aware with regard to case sensitivity
*/
size_t domain_name::write(uint8_t *msg, size_t offset, dns_compression_node &compression_root) const 
{
	dns_compression_node::compression_match cmatch = compression_root.find_match(*this);
	compression_root.add_name(*this, offset);
	return write(msg, offset, cmatch.offset, cmatch.depth);
}
size_t domain_name::write(uint8_t *msg, size_t offset, size_t cmatch_offset, size_t cmatch_depth) const
{
	size_t labels_needed = num_labels() - cmatch_depth;
	for(size_t i=0; i < labels_needed; ++i) {
		domain_label label = from_leaf(i);
		label.write(msg+offset);
		offset += label.raw_len();
	}
	if(cmatch_depth == 0) {
		// no jump, just terminate name
		msg[offset++] = 0;
	} else {
		msg[offset++] = 0xc0 | (cmatch_offset >> 8);
		msg[offset++] = cmatch_offset & 0xff;
	}
	return offset;
}
size_t domain_name::write(uint8_t *msg, size_t offset) const 
{
	unsigned len = wire_len();
	memcpy(msg + offset, wire_start(), len);
	return offset + len;
}
uint8_t * domain_name::cache_write(uint8_t * data) const {
	unsigned len = wire_len();
	memcpy(data, wire_start(), len);
	return data + len;
}

size_t domain_name_qs::write_qname(uint8_t *msg, size_t offset, dns_compression_node &compression_root) const
{
	// qname is always the first domain_name in a message so it cannot find any compression match
	compression_root.add_name(name, offset);
	return write(msg, offset);
}
size_t domain_name_qs::write(uint8_t *msg, size_t offset) const 
{
	size_t rv = name.write(msg, offset);
	if(rv-offset != case_bitmask.size()) abort();
	for(size_t i=1; i < rv-offset; ++i)
		if(case_bitmask[i])
			msg[offset+i] = toupper(msg[offset+i]);
	return rv;
}

void domain_name_qs::print_name(std::ostream &out) const
{
	std::string namestr = name.to_string();
	for(size_t i=1; i < case_bitmask.size(); ++i)
		if(case_bitmask[i])
			namestr[i-1] = toupper(namestr[i-1]);
	out << namestr;
}


void dns_compression_node::add_name(const domain_name &name, size_t offset)
{
	unsigned nlabels = name.num_labels();
	while(nlabels) {
		if(offset >= 0x4000) break; // two high bits are reserved for flags
		first_match & match = name_map[name.get_root(nlabels).name];
		if(match.offset == 0)
			match.offset = offset;
		--nlabels;
		offset += name.from_root(nlabels).raw_len();
	}
}

dns_compression_node::compression_match dns_compression_node::find_match(const domain_name &name) {
	unsigned nlabels = name.num_labels();
	while(nlabels) {
		auto it = name_map.find(name.get_root(nlabels).name);
		if(it != name_map.end())
			return compression_match(it->second.offset, nlabels);
		--nlabels;
	}
	return compression_match(0, 0);
}
