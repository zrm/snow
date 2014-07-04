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

#include<algorithm>
#include<functional>
#include<unordered_map>
#include<iostream>
#include<fstream>
#include<string>
#include<sstream>
#include<vector>
#include<cstring>
#include<stdexcept>
#include"err_out.h"

template<class T>
void ss_convert(const std::string &s, T &val)
{
    std::stringstream ss(s);
	ss.exceptions( std::ios_base::failbit | std::ios_base::badbit );
    T v; // use temporary in case of some error, not sure if sstream could corrupt existing (check?)
    ss >> v;
    val = std::move(v);
}

// bool specialization to use 'true/false' for bool instead of '0/1' (i.e. std::boolalpha)
template<>
void ss_convert(const std::string &s, bool &val)
{
	std::string bs(s);
	std::transform(bs.begin(), bs.end(), bs.begin(), ::tolower);
	std::stringstream ss(std::move(bs));
	ss.exceptions( std::ios_base::failbit | std::ios_base::badbit );
    bool v;
    ss >> std::boolalpha >> v;
    val = v;
}

std::string next_word(const std::string &line, size_t *startpos)
{
	size_t start = *startpos;
	while(start < line.size() && isspace(line[start]))
		++start;
	size_t end = start+1;
	while(end < line.size() && !isspace(line[end]))
		++end;
	std::string rv = line.substr(start, end-start);
	*startpos = end+1;
	return std::move(rv);
}


template<class T, class...ARGS>
void configuration_base<T, ARGS...>::check_initialization() {
	for(size_t i=0; i < T::num_enums(); ++i) {
		if(!initialized[i]) {
			std::string enum_string = T::enum_string();
			size_t start=0;
			for(size_t j=0; j < i; ++j)
				start = enum_string.find_first_of(',', start) + 1;
			while(start < enum_string.size() && isspace(enum_string[start]))
				++start;
			size_t end = enum_string.find(',', start);
			std::cerr << "No default value set for configuration option: " << enum_string.substr(start, end-start) << std::endl;
			abort();
		}
	}
	configuration_base<ARGS...>::check_initialization();
}

template<class T, class...ARGS>
configuration_base<T, ARGS...>::configuration_base()
{
	this->get_data()->populate_value_assignments(T::enum_string(), std::bind(&configuration_base<T, ARGS...>::assign_string_value, this, std::placeholders::_1, std::placeholders::_2));
	memset(initialized, 0, sizeof(initialized)); // for all values, set initialized = false (implementation must supply defaults)
}

struct configuration_base_data
{
	// value assignment map: maps value names to a std::function that will take string arg, parse it and assign the result to that value
	std::unordered_map< std::string, std::function<void(const std::string &)> >  value_assignment_map;
	void populate_value_assignments(const std::string &enum_string, const std::function<void(const std::string&, size_t)> &assignment_fn);
	static std::string normalize(std::string &&str) {
		while(str.size() > 0 && ::isspace(str.back()))
			str.pop_back(); // remove space at the end
		str.erase(0, str.find_first_not_of(" \t")); // remove space at the start
		std::replace_if(str.begin(), str.end(), ::isspace, '_'); // replace all interior spaces with '_'
		std::transform(str.begin(), str.end(), str.begin(), ::toupper); // make uppercase
		return std::move(str);
	}
};

void configuration_base_data::populate_value_assignments(const std::string &enum_string, const std::function<void(const std::string&, size_t)> &assignment_fn)
{
	// value_assignment_map maps a value string to a function that takes the value in string format, converts it to the correct type and assigns it
	// this creates value_assignment_map from the respective value type enum strings (which are indexes into the respective arrays)
	size_t index = 0, start = 0;
	do {
		size_t end = enum_string.find_first_of(',', start);
		std::string str = normalize(enum_string.substr(start, end-start));
		value_assignment_map.insert(std::make_pair(str, std::bind(assignment_fn, std::placeholders::_1, index)));
		index++;
		start = end+1;
	} while(start != 0);
}

configuration_base<>::configuration_base() : data(new configuration_base_data()) {}
configuration_base<>::~configuration_base()
{
	if(data != nullptr)
		delete data;
}


void configuration_base<>::read_config_file(const std::string &fn)
{
	check_initialization();
	dout() << "Reading configuration file " << fn;
	std::ifstream infile(fn, std::ios_base::in | std::ios_base::binary);
	if(!infile.is_open()) {
		wout() << "Could not open configuration file " << fn << ", default options will be used";
		sanity_check_values();
		return;
	}
	std::string line;
	for(size_t linenum = 1; std::getline(infile, line); ++linenum) {
		if(line.size() == 0 || line[0] == '#')
			continue;
		size_t eq = line.find_first_of('=');
		if(eq == std::string::npos) {
			eout() << "Error reading configuration file " << fn << " line " << linenum << ": line must be of the form \"OPTION=VALUE\"";
			continue;
		}
		std::string keyname = configuration_base_data::normalize(line.substr(0, eq));
		auto it = data->value_assignment_map.find(keyname);
		if(it == data->value_assignment_map.end()) {
			eout() << "Error reading configuration file " << fn << " line " << linenum << ": no known option " << keyname;
			dout() << "Value assignment map entries:";
			for(auto &x : data->value_assignment_map)
				dout() << x.first;
			continue;
		}
		try {
			// call assign_string_value function:
			it->second(line.substr(eq+1));
			dout() << "read_config_file parsed line: " << line;
		} catch(const std::ios_base::failure& e) {
			eout() << "Error reading configuration file " << fn << " line " << linenum << ": invalid value";
		}
	}
	infile.close();
	sanity_check_values();
}
