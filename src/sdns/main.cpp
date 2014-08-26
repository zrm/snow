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

#include <iostream>
#include <thread>
#include "../sdns/eventloop.h"
#include "../sdns/tcp_thread.h"
#include "../sdns/configuration.h"
#include "../common/err_out.h"
#include "../common/daemon.h"

int daemon_main()
{
	network_init(); // (WSAStartup())
	register_signals();
	sdns::conf.read_config();
	try {
		tcp_thread tcp;
		eventloop eloop(&tcp);
		tcp.set_pointers(&eloop);
		std::thread eventloop_th(std::ref(eloop));
		std::thread tcp_th(std::ref(tcp));
		while(true) {
			os_event event = wait_for_os_event();
			if(event == os_event::shutdown) break;
			if(event == os_event::reload) eloop.reread_static_records();
		}
		eloop.stop();
		tcp.stop();
		eventloop_th.join();
		tcp_th.join();
	} catch(const e_exception &e) {
		eout() << "Error at main(): " << e << " errno was: " << strerror_rp(errno);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	std::string config_filename = sdns::conf[sdns::CONFIG_FILE], daemon_name = "sdns";
	bool daemonize = false;
#ifndef WINDOWS
	srandom((size_t)(&sdns::conf) + time(nullptr));
	for(int opt; (opt = getopt(argc, argv, "c:ds:")) != -1;) {
		switch(opt) {
		case 'c': // config filename
			config_filename = optarg;
			break;
		case 'd': // daemonize
			daemonize = true;
			break;
		case 's': // syslog daemon name
			daemon_name = optarg;
		default: // '?'
			std::cerr << "Usage: " << argv[0] << " [-c config_filename] [-d (daemonize)] [-s syslog_daemon_name]" << std::endl;
			exit(EXIT_FAILURE);
		}
	}
	if(optind < argc) {
		eout() << "Unexpected argument: " << argv[optind];
		exit(EXIT_FAILURE);
	}
#endif
	sdns::conf.set_config_file(config_filename);
	try {
		if(daemonize)
			return daemon_start(&daemon_main, daemon_name.c_str());
		else
			return daemon_main();
	} catch(const e_exception &e) {
		eout() << "main() caught fatal or unhandled error: " << e;
		std::cerr << daemon_name << " main() caught fatal or unhandled error: " << e << std::endl;
	}
	return EXIT_FAILURE;
}

