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

#ifdef WINDOWS
#ifndef WINDOWS_REGISTRY_H
#define WINDOWS_REGISTRY_H
#include<windows.h>
#include<cstdint>
#include<string>
#include<vector>
#include<iostream>

struct registry_exception
{
	DWORD return_value;
	std::string str;
	registry_exception(DWORD rv, const char *s) : return_value(rv), str(s) {}
};

std::ostream& operator<<(std::ostream &out, const registry_exception &re);

class registry_key
{
	HKEY key;
	// iterators are somewhat irritating here because number of subkeys/values can change asynchronously
	template<class T>
	class registry_iterator {
	protected:
		HKEY parent;
		size_t index;
	public:
		registry_iterator(HKEY p, size_t idx) : parent(p), index(idx) {}
		T operator++(int) { return T(parent, index++); }
		T& operator++() { ++index; return *static_cast<T*>(this); }
		T operator--(int) { return T(parent, index--); }
		T& operator--() { --index; return *static_cast<T*>(this); }
		bool operator==(const T &r) const {
			if(parent != r.parent)
				return false;
			if(index == r.index)
				return true;
			// end() iterator has index SIZE_MAX, but this should compare equal to any iterator past the end
			// note: this has slightly strange behavior: if two elements have different index but are both past the end, both will compare equal to end() but not to each other
			if(index == SIZE_MAX)
				return r.exists() == false;
			if(r.index == SIZE_MAX)
				return static_cast<const T*>(this)->exists() == false;
			return false;
		}
		bool operator!=(const T &r) const { return !(*this==r); }
		// there is not any good default dereferece for these, but having one is useful for e.g. range-based for, so operator* returns self
		T& operator*() { return *static_cast<T*>(this); }
		const T& operator*() const { return *static_cast<T*>(this); }
	};
public:
	// constructor params:
		// hkey: an existing key, may be a predefined key (see http://msdn.microsoft.com/en-us/library/windows/desktop/ms724836(v=vs.85).aspx)
		// subkey: name of the subkey
		// sam: requested access rights (see http://msdn.microsoft.com/en-us/library/windows/desktop/ms724878(v=vs.85).aspx)
	// example: registry_key(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows", KEY_READ)
	// open constructor:
	registry_key(HKEY hkey, const char *subkey, REGSAM sam);
	registry_key(const registry_key &k, const char *subkey, REGSAM sam) : registry_key(k.key, subkey, sam) {}
	
	// create constructor:
	registry_key(HKEY hkey, const char *subkey, DWORD options, REGSAM sam);
	registry_key(const registry_key &k, const char *subkey, DWORD options, REGSAM sam) : registry_key(k.key, subkey, options, sam) {}

	registry_key(registry_key &&rval) { key = rval.key; rval.key = nullptr; }
	registry_key& operator=(registry_key &&rval) { std::swap(key, rval.key); return *this; }
	
	~registry_key() {
		if(key != nullptr)
			RegCloseKey(key);
	}
	

	class registry_values
	{
		HKEY key;
	public:
		registry_values(HKEY k) : key(k) {}
		registry_values(registry_key &k) : key(k.key) {}
		bool value_exists(const char *value_name) { return RegQueryValueEx(key, value_name, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS; }
		DWORD value_type(const char *value_name) const;
		// REG_BINARY
		//smartbuf get_value_binary(const char *value_name) {
		// REG_DWORD
		DWORD get_value_dword(const char *value_name) const;
		// REG_QWORD
		uint64_t get_value_qword(const char *value_name) const;
		// REG_SZ or REG_EXPAND_SZ,  TODO: expand variables in REG_EXPAND_SZ
		std::string get_value_string(const char *value_name) const;
		std::vector<std::string> get_value_multi_string(const char *value_name) const;
	
		struct registry_value_iterator : public registry_iterator<registry_value_iterator> {
			registry_value_iterator(HKEY p, size_t idx) : registry_iterator(p, idx) {}
			bool exists() const;
			std::string get_name() const;
			// convenience functions, equivalent to calling equivalent function on registry_values object with get_name() rv as arg:
			DWORD value_type() const { return registry_values(parent).value_type(get_name().c_str());	}
			DWORD get_value_dword() const { return registry_values(parent).get_value_dword(get_name().c_str()); }
			uint64_t get_value_qword() const { return registry_values(parent).get_value_qword(get_name().c_str()); }
			std::string get_value_string() const { return registry_values(parent).get_value_string(get_name().c_str()); }
			std::vector<std::string> get_value_multi_string() const { return registry_values(parent).get_value_multi_string(get_name().c_str()); }
		};
		registry_value_iterator begin() const { return registry_value_iterator(key, 0); }
		registry_value_iterator end() const { return registry_value_iterator(key, SIZE_MAX); }
	};
	registry_values values() { return registry_values(key); }
	const registry_values values() const { return registry_values(key); }
	
	class registry_subkeys {
		HKEY key;
	public:
		registry_subkeys(HKEY k) : key(k) {}
		registry_key get_subkey(size_t index, REGSAM sam) const;
		registry_key get_subkey(const char *subname, REGSAM sam) const { return registry_key(key, subname, sam); }
		
		struct registry_subkeys_iterator : public registry_iterator<registry_subkeys_iterator> {
			registry_subkeys_iterator(HKEY p, size_t idx) : registry_iterator(p, idx) {}
			bool exists() const;
			std::string get_name() const;
			registry_key get(REGSAM sam) const { return registry_subkeys(parent).get_subkey(index, sam); }
		};
		
		registry_subkeys_iterator begin() const { return registry_subkeys_iterator(key, 0); }
		registry_subkeys_iterator end() const { return registry_subkeys_iterator(key, SIZE_MAX); }
	};
	registry_subkeys subkeys() { return registry_subkeys(key); }
	const registry_subkeys subkeys() const { return registry_subkeys(key); }
	registry_key get_subkey(const char *name, REGSAM sam) { return registry_key(key, name, sam); }
	void print(std::ostream &out, size_t depth = 0) const;
};


std::ostream &operator<<(std::ostream &out, const registry_key::registry_values::registry_value_iterator &it);
std::ostream &operator<<(std::ostream &out, const registry_key::registry_subkeys::registry_subkeys_iterator &it);
std::ostream &operator<<(std::ostream &out, const registry_key &k);

#endif // WINDOWS_REGISTRY_H
#endif // ifdef WINDOWS
