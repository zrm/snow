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

#ifndef CONFIGURATION_BASE_H
#define CONFIGURATION_BASE_H
#include<string>
#include<vector>

/*
How to use configuration:
First, create a header file (e.g. configuration.h) which will include configuration_base.h and define a subclass of configuration_base
In that file, use MAKE_CONF_TYPE to create however many types of configuration options you like (e.g. bool, size_t, string, double) and list every option name for each type:
MAKE_CONF_TYPE(conf_string, std::string, ss_convert<std::string>, SOME_FILENAME, SOME_SERVICE_NAME)
MAKE_CONF_TYPE(conf_bool, bool, ss_convert<bool>, DO_THAT_THING)
The first argument is a name for the type, this can be any unique name, and these names collectively are the template args to configuration_base below
The second argument is the type to be used for the ensuing list of configuration options
The third argument is the conversion function which takes a std::string read from the configuration file and a reference to the value variable and makes the conversion and assignment
	a templated function ss_convert<T> can be used for any T that a std::stringstream can convert, or you can supply your own with signature "void fn(const std::string&, T& value)"
The subsequent arguments are the names of all configuration options which have that type

Then declare a subclass of configuration_base, supplying all of the configuration types as template arguments, and declare an instance of it extern:
class configuration : public configuration_base<conf_string, conf_bool>
{
protected:
	virtual void sanity_check_values();
public:
	configuration();
};
extern configuration conf;

It may be wise to make the MAKE_CONF_TYPE calls and declare the extern instance inside of a namespace.

The subclass constructor should assign default values for each option, using assign_value(option_name, option_value)
The subclass must define sanity_check_values() which should verify that options read from the configuration file are sane
	This function can then e.g. terminate the program or throw exception on failure, or log some error, or reset options to defaults etc.
	If an exception is thrown, it will be thrown through read_config_file, and you can catch it from there
	
The implementation file for this class (e.g. configuration.cpp) must #include "configuration_base.tpp" after including your "configuration.h",
	which instantiates all the necessary template functions and classes in one location for the configuration options specified with MAKE_CONF_TYPE
	
At this point you can call read_config_file() on startup, passing the name of the config file as the argument,
and access configuration values through anything that includes your configuration.h by specifying 'namespace::conf[namespace::option_name]'
*/

template<class T>
void ss_convert(const std::string &s, T &val);

// bool specialization to use 'true/false' for bool instead of '1/0'
template<>
void ss_convert(const std::string &s, bool &val);

// string specialization: no conversion necessary, value is already a string
template<>
inline void ss_convert(const std::string &s, std::string &val) { val = s; }

struct in6_addr;
void ipv4_convert(const std::string &s, std::vector<uint32_t>& val);
void ipv6_convert(const std::string &s, std::vector<in6_addr>& val);

// split line on spaces, advance startpos to end of next word+1
std::string next_word(const std::string &line, size_t *startpos);

// [TODO: implement this: parse by delimiter, call CONV for each element, return vector]
//template< class T, T (*CONV)(const std::string &) = ss_convert<T> >
//std::vector<T> ss_convert_vector(const std::string &s);

#define MAKE_CONF_TYPE(classname, typ, assign_fn, ...) \
enum classname ## _enum { __VA_ARGS__, classname ## _num_enums };\
class classname \
{\
public:\
    typedef typ TP;\
    typedef classname ## _enum ENUM;\
    static void assign(const std::string &s, typ &v) { assign_fn(s, v); }\
    static const char* enum_string() { return #__VA_ARGS__; }\
	static constexpr size_t num_enums() { return classname ## _num_enums; }\
};


template<class...ARGS> class configuration_base;

template<class T, class...ARGS>
class configuration_base<T, ARGS...> : public configuration_base<ARGS...>
{
	bool initialized[T::num_enums()];
	typename T::TP values[T::num_enums()];
	void assign_string_value(const std::string &valuestr, size_t index) { T::assign(valuestr, values[index]); }
protected:
	virtual void check_initialization();

public:
	using configuration_base<ARGS...>::operator[];
	const typename T::TP& operator[](typename T::ENUM val) { return values[val]; }
	using configuration_base<ARGS...>::assign_value;
	void assign_value(typename T::ENUM index, const typename T::TP &value) { values[index] = value; initialized[index] = true; } // note: this is not thread safe
	configuration_base();
};


struct configuration_base_data;
	
template<>
class configuration_base<>
{
	configuration_base_data *data;
protected:
	virtual configuration_base_data *get_data() { return data; }
	// using declaration in other specialization wants to see some operator[]() and assign_value() here:
	struct nxtype;
	void operator[](nxtype&) {}
	void assign_value() {}
	virtual void check_initialization() {}
	virtual void sanity_check_values() = 0;
public:
	void read_config_file(const std::string &filename);
	configuration_base();
	~configuration_base();
};

#endif // CONFIGURATION_BASE_H
