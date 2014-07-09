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

#ifndef DBUF_H
#define DBUF_H
#include<cstdlib>
#include<cstdint>
#include<cstring>
#include<string>
#include<memory>
#include<stack>

class dbuf
{
        uint8_t* buf;
        size_t bufsize;
public:
        operator uint8_t*()
                { return buf; }
        operator const uint8_t*() const
                { return buf; }
        uint8_t* data() { return buf; }
		const uint8_t* data() const { return buf; }
		uint8_t& operator[](size_t idx)
                { return buf[idx]; }
		const uint8_t& operator[](size_t idx) const
                { return buf[idx]; }
        std::string get_string() const
			{ return std::string((char*)buf, bufsize); }
        size_t size() const
                { return bufsize; }
        void resize(size_t sz)
                { bufsize = sz; buf = (uint8_t*) realloc(buf, bufsize); if(bufsize && !buf) throw std::bad_alloc(); }
		void free() { ::free(buf); buf = nullptr; bufsize = 0; }
        dbuf() : buf(nullptr), bufsize(0) {}
		explicit dbuf(size_t sz) : buf(nullptr) { resize(sz); }
        dbuf(const dbuf &d) : buf(nullptr)
                { resize(d.bufsize); memcpy(buf, d.buf, d.bufsize); }
        dbuf(dbuf &&d) : buf(d.buf), bufsize(d.bufsize)
                { d.buf=nullptr; d.bufsize = 0; }
        dbuf(const uint8_t *b, size_t sz) : buf(nullptr)
                { resize(sz); memcpy(buf, b, bufsize); }
        explicit dbuf(const std::string &str) : buf(nullptr)
                { resize(str.size()); memcpy(buf, str.c_str(), bufsize); }
        dbuf &operator=(dbuf &&d)
                { std::swap(buf, d.buf); std::swap(bufsize, d.bufsize); return *this; }
		dbuf &operator=(const dbuf &d) {
			if(buf!=d.buf)
				{ resize(d.bufsize); memcpy(buf, d.buf, d.bufsize); }
			return *this;
		}
        ~dbuf() { ::free(buf); }
        bool operator==(const dbuf &d) const
                { return bufsize == d.bufsize && memcmp(buf, d.buf, bufsize) == 0; }
        bool operator!=(const dbuf &d) const
                { return !(*this==d); }
};

class buffer_list
{
	std::stack<dbuf> buffers;
	size_t bufsize;
public:
	explicit buffer_list(size_t default_bufsize) : bufsize(default_bufsize) {}
	dbuf get() {
		while(buffers.size() > 0 && buffers.top().size() != bufsize)
			buffers.pop();
		if(buffers.size() == 0)
			return dbuf(bufsize);
		dbuf rv = std::move(buffers.top());
		buffers.pop();
		return std::move(rv);
	}
	void recover(dbuf &&buf) {
		if(buffers.size() < 25)
			buffers.push(std::move(buf));
	}
	void set_bufsize(size_t bsz) { bufsize = bsz; }
};

#endif // DBUF_H
