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
#include "windows_registry.h"
#include "err_out.h"


std::ostream& operator<<(std::ostream &out, const registry_exception &re)
{
	out << re.str;
	if(re.return_value != ERROR_SUCCESS)
		out << ": " << strerror_rp(re.return_value);
	return out;
}

registry_key::registry_key(HKEY hkey, const char *subkey, REGSAM sam)
{
	DWORD rv = RegOpenKeyExA(hkey, subkey, 0, sam, &key);
	if(rv != ERROR_SUCCESS) {
		// (this could be access denied, or key doesn't exist, etc.)
		throw registry_exception(rv, "Error opening registry key");
	}
}

registry_key::registry_key(HKEY hkey, const char *subkey, DWORD options, REGSAM sam)
{
	DWORD rv = RegCreateKeyExA(hkey, subkey, 0, nullptr, options, sam, nullptr, &key, nullptr);
	if(rv != ERROR_SUCCESS)
		throw registry_exception(rv, "Error creating registry key");
}

DWORD registry_key::registry_values::value_type(const char *value_name) const
{
	DWORD valtype;
	LONG rv = RegQueryValueEx(key, value_name, nullptr, &valtype, nullptr, nullptr);
	if(rv != ERROR_SUCCESS)
		throw registry_exception(rv, "Error querying registry value");
	return valtype;
}

DWORD registry_key::registry_values::get_value_dword(const char *value_name) const
{
	DWORD value, vsz = sizeof(DWORD), regtype;
	DWORD rv = RegQueryValueEx(key, value_name, nullptr, &regtype, reinterpret_cast<LPBYTE>(&value), &vsz);
	if(rv != ERROR_SUCCESS)
		throw registry_exception(rv, "Error querying registry value");
	if(regtype != REG_DWORD && regtype != REG_BINARY)
		throw registry_exception(ERROR_SUCCESS, "Registry value was not a REG_DWORD");
	return value;
}

uint64_t registry_key::registry_values::get_value_qword(const char *value_name) const
{
	uint64_t value;
	DWORD vsz = sizeof(value), regtype;
	DWORD rv = RegQueryValueEx(key, value_name, nullptr, &regtype, reinterpret_cast<LPBYTE>(&value), &vsz);
	if(rv != ERROR_SUCCESS)
		throw registry_exception(rv, "Error querying registry value");
	if(regtype != REG_QWORD && regtype != REG_BINARY)
		throw registry_exception(ERROR_SUCCESS, "Registry value was not a REG_QWORD");
	return value;
}


std::string registry_key::registry_values::get_value_string(const char *value_name) const
{
	DWORD len = 0, regtype;
	DWORD rv = RegQueryValueExA(key, value_name, nullptr, &regtype, nullptr, &len);
	if(rv != ERROR_SUCCESS)
		throw registry_exception(rv, "Error querying registry value size");
	std::string value(len, '\0');
	rv = RegQueryValueExA(key, value_name, nullptr, &regtype, reinterpret_cast<LPBYTE>(&value[0]), &len);
	if(rv != ERROR_SUCCESS)
		throw registry_exception(rv, "Error querying registry value");
	if(len != value.size())
		throw registry_exception(ERROR_SUCCESS, "Retreived value size did not match queried value size");
	if(regtype != REG_SZ && regtype != REG_EXPAND_SZ)
		throw registry_exception(ERROR_SUCCESS, "Registry value was not a string (REG_SZ or REG_EXPAND_SZ)");
	if(value.back() == '\0')
		value.pop_back(); // remove duplicate null terminator if data was stored with one [as it should be but is not always]
	return std::move(value);
}

std::vector<std::string> registry_key::registry_values::get_value_multi_string(const char *value_name) const
{
	DWORD len = 0, regtype;
	DWORD rv = RegQueryValueExA(key, value_name, nullptr, &regtype, nullptr, &len);
	if(rv != ERROR_SUCCESS)
		throw registry_exception(rv, "Error querying registry value size");
	std::vector<char> value(len, '\0');
	rv = RegQueryValueExA(key, value_name, nullptr, &regtype, reinterpret_cast<LPBYTE>(&value[0]), &len);
	if(rv != ERROR_SUCCESS)
		throw registry_exception(rv, "Error querying registry value");
	if(regtype != REG_MULTI_SZ)
		throw registry_exception(ERROR_SUCCESS, "Registry value was not a multi string (REG_MULTI_SZ)");
	if(len != value.size())
		throw registry_exception(ERROR_SUCCESS, "Retreived value size did not match queried value size");
	std::vector<std::string> strings;
	for(size_t i=0, last=0; i+1 < value.size(); ++i) {
		if(value[i] == '\0') {
			strings.push_back(std::string(&value[last], i-last));
			last = i+1;
		}
	}
	return std::move(strings);
}

bool registry_key::registry_values::registry_value_iterator::exists() const
{
	char ignored[256];
	DWORD isz = sizeof(ignored);
	return RegEnumValue(parent, index, ignored, &isz, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS;
}

std::string registry_key::registry_values::registry_value_iterator::get_name() const
{
	char name[256];
	DWORD nsz = sizeof(name);
	DWORD rv = RegEnumValue(parent, index, name, &nsz, nullptr, nullptr, nullptr, nullptr);
	if(rv != ERROR_SUCCESS)
		throw registry_exception(rv, "Error enumerating value name");
	if(nsz > 0 && name[nsz-1] == '\0')
		--nsz;
	return std::string(name, nsz);
}

bool registry_key::registry_subkeys::registry_subkeys_iterator::exists() const
{
	char ignored[256];
	DWORD isz = sizeof(ignored);
	return RegEnumKeyEx(parent, index, ignored, &isz, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS;
}

std::string registry_key::registry_subkeys::registry_subkeys_iterator::get_name() const
{
	char name[256];
	DWORD nsz = sizeof(name);
	DWORD rv = RegEnumKeyEx(parent, index, name, &nsz, nullptr, nullptr, nullptr, nullptr);
	if(rv != ERROR_SUCCESS)
		throw registry_exception(rv, "Error enumerating subkey name");
	if(nsz > 0 && name[nsz-1] == '\0')
		--nsz;
	return std::string(name, nsz);
}

registry_key registry_key::registry_subkeys::get_subkey(size_t index, REGSAM sam) const
{
	char subname[256];
	DWORD namesz = sizeof(subname);
	LONG rv = RegEnumKeyEx(key, index, subname, &namesz, nullptr, nullptr, nullptr, nullptr);
	if(rv != ERROR_SUCCESS)
		throw registry_exception(rv, "Error enumerating subkey");
	return registry_key(key, subname, sam);
}

std::ostream &operator<<(std::ostream &out, const registry_key::registry_values::registry_value_iterator &it)
{
	switch(it.value_type()) {
		case REG_DWORD:
			out << it.get_value_dword() << " (DWORD)";
			break;
		case REG_QWORD:
			out << it.get_value_qword() << " (QWORD)";
			break;
		case REG_SZ:
		case REG_EXPAND_SZ:
			out << it.get_value_string() << " (STRING)";
			break;
		case REG_MULTI_SZ:
			for(auto &s : it.get_value_multi_string())
				out << "[" << s << "] ";
			out << "(MULTI STRING)";
			break;
		default:
			out << "(UNKNOWN [" << it.value_type() << "])";
			break;
	}
	return out;
}

std::ostream &operator<<(std::ostream &out, const registry_key::registry_subkeys::registry_subkeys_iterator &it)
{
	out << it.get_name();
	return out;	
}

std::ostream &operator<<(std::ostream &out, const registry_key &k)
{
	k.print(out);
	return out;
}


void registry_key::print(std::ostream &out, size_t depth) const
{
   std::string tab(depth, '\t');
   for(auto &it : values()) {
	   try {
		   out << tab << it.get_name() << ": " << it << std::endl;
	   } catch(const registry_exception &e) {
		   out << tab << "error: " << e.str << " with rv " << e.return_value << std::endl;
	   }
   }
   for(auto &it : subkeys()) {
	   try {
		   out << tab << "Subkey " << it.get_name() << ":" << std::endl;
		   it.get(KEY_READ).print(out, depth + 1);
	   } catch(const registry_exception &e) {
		   out << tab << "\tCaught: " << e.str << " with rv " << e.return_value << std::endl;
	   }
   }
}

#endif
