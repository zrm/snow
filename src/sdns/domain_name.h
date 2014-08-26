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

#ifndef DOMAIN_NAME_H
#define DOMAIN_NAME_H
#include<cstdint>
#include<vector>
#include<string>
#include<cstring>
#include<unordered_map>

struct dns_raw_msg
{
	const uint8_t* msg;
	const std::size_t len;
	dns_raw_msg(const uint8_t* m, std::size_t l) : msg(m), len(l) {}
};

// labels are iterator-like pointers to the interior of a domain_name
class domain_label
{
	const uint8_t* label;
public:
	static const uint8_t root; // root label, single byte with value zero
	static const uint8_t invalid[9]; // the label "invalid", terminated by root label
	domain_label(const uint8_t *l) : label(l ? l : invalid) {}
	domain_label() : label(invalid) {}
	std::string get_string() const { return std::string((const char*)(label+1), label[0]); }
	bool operator==(const char * s) const { return label[0]==strlen(s) && memcmp(label+1, s, label[0]) == 0; }
	bool operator==(const std::string& s) const { return label[0]==s.size() && memcmp(label+1, s.c_str(), label[0]) == 0; }
	bool operator==(domain_label l) const { return label[0]==l.label[0] && memcmp(label+1, l.label+1, label[0]) == 0; }
	template<class T> bool operator!=(const T& t) const { return !(*this == t); }
	bool operator<(domain_label l) const {
		if(label[0] != l.label[0]) return label[0] < l.label[0];
		return memcmp(label+1, l.label+1, label[0]) < 0;
	}
	unsigned len() const { return label[0]; }
	unsigned raw_len() const { return label[0]+1; } // length including size byte
	void write(uint8_t* to) const { memcpy(to, label, label[0]+1); } // writes "raw_len()" byte label (including size header) to "to"
	void validate() const; // throws e_invalid_input
};

// domain name compression:
	// domain_name objects have to interact with one another within a message to do archaic dns compression, so every root of a domain name gets put into a container
	// first to be written writes its offset to the container, copies use ptr to that offset
		// just pass ref to container on write: name adds itself to the container or uses pre-existing copy if it exists
class dns_compression_node;
class domain_name
{
	friend class domain_name_qs;
	// domain_name format is the same as the uncompressed wire format
	// with the exception that, for names owned by the surrounding object, the first byte is (0x80 | num labels) and the second byte is len of wire format, followed by wire format
	// domain_name class stores all names in lowercase, use domain_name_qs if case preservation is required
	const uint8_t * name;
	static void set_case_bitmask(const uint8_t * ptr, std::vector<bool>& bitmask);
	static void make_lowercase(uint8_t * ptr);
	size_t write(uint8_t *buf, size_t offset, size_t cmatch_offset, size_t cmatch_depth) const;
	domain_name(const uint8_t * dname) : name(dname) {}
	unsigned wire_len() const;
	const uint8_t * wire_start() const { return (name[0] & 0x80) ? (name + 2) : name; }
	struct domain_name_root;
public:
	static const domain_name root;
	domain_name() : name(domain_label::invalid) {}
	domain_name(const std::string &dname); // throws e_invalid_input 
	// DNS message constructor: constructs domain_name at *off from DNS message starting at *message
	domain_name(dns_raw_msg msg, size_t *off, std::vector<bool> *case_bitmask = nullptr); // throws e_invalid_input
	// cache constructor: reads from cache_data, advances cache_data and reduces len
		// input format is from output of domain_name::cache_write()
	domain_name(const uint8_t ** cache_data, size_t * datalen);
	domain_name(domain_name &&dn) : name(domain_label::invalid) { *this = std::move(dn); }
	domain_name(const domain_name &dn) : name(domain_label::invalid) { *this = dn; }
	~domain_name() { if(name[0] & 0x80) delete[] name; }
	domain_name &operator=(domain_name &&dn);
	domain_name &operator=(const domain_name &dn);
	unsigned num_labels() const;
	domain_name_root get_root(size_t depth) const;
	domain_label from_root(size_t num) const;
	domain_label from_leaf(size_t num) const;
	bool operator==(const domain_name &dn) const;
	bool operator!=(const domain_name &dn) const { return !(*this==dn); }
	bool operator<(const domain_name &dn) const;
	std::string to_string() const;
	std::string to_lstring() const;
	size_t hash() const;
	// maxsize(): max (uncompressed) wire size; actual wire size may be smaller after label compression
	size_t maxsize() const { return wire_len(); }
	// domain_name has two write functions depending on whether the dns_type_t of the record is listed in RFC1035
		// those listed SHOULD provide dns_compression_node to do dns compression; those not listed MUST NOT
	size_t write(uint8_t *buf, size_t msg_offset, dns_compression_node &compression_root) const;
	size_t write(uint8_t *buf, size_t msg_offset) const;
	size_t cache_size() const { return wire_len(); }
	// cache_write() writes cache_size() bytes to 'data' in cache format suitable to pass to domain_name cache constructor, returns ptr to byte after data written
	uint8_t * cache_write(uint8_t * data) const;
	const uint8_t * cache_get() const { return wire_start(); } // returns raw data suitable for cache key, of size cache_size()
};

struct domain_name::domain_name_root
{
	const domain_name name;
	domain_name_root(const uint8_t * p) : name(p) {}
};

// std::hash specialization for domain_name
namespace std
{
template<> struct hash<domain_name>
{
	size_t operator()(const domain_name& dn) const { return dn.hash(); }
};
}

inline std::ostream &operator<<(std::ostream &out, const domain_name &n)
{
	out << n.to_string();
	return out;
}

// domain name for question section: case sensitive
class domain_name_qs
{
	// case_bitmask must be before name so that it is initialized before name and can be passed to name constructor
	std::vector<bool> case_bitmask; // zero = lowercase or nonalpha, one = uppercase, one bit per byte of name
	domain_name name;
public:
	domain_name_qs(dns_raw_msg msg, size_t * off) : name(msg, off, &case_bitmask) {}
	domain_name_qs(const domain_name &dn) : case_bitmask(dn.wire_len()), name(dn) {} // case bitmask all lowercase
	size_t maxsize() const { return name.maxsize(); }
	// write_qname: specifically for qname, fixes case and adds to dcn but assumes there is no existing match
	size_t write_qname(uint8_t *buf, size_t msg_offset, dns_compression_node &compression_root) const;
	size_t write(uint8_t *buf, size_t msg_offset) const;
	bool operator==(const domain_name_qs &dn) const {
		if(name != dn.name) return false;
		return case_bitmask == dn.case_bitmask;
	}
	bool operator!=(const domain_name_qs &dn) const { return !(*this==dn); }
	operator const domain_name&() const { return name; }
	const domain_name& get_name() const { return name; }
	void print_name(std::ostream &out) const;
};

inline std::ostream &operator<<(std::ostream &out, const domain_name_qs &n)
{
	n.print_name(out);
	return out;
}

class dns_compression_node
{
	struct first_match {
		unsigned offset;
	};
	std::unordered_map<domain_name, first_match> name_map;
public:
	dns_compression_node() {}
	struct compression_match {
		uint16_t offset;
		uint16_t depth;
		compression_match(uint16_t o, uint16_t d) : offset(o), depth(d) {}
	};
	compression_match find_match(const domain_name &name);
	void add_name(const domain_name &name, size_t offset);
};


#endif // DOMAIN_NAME_H
