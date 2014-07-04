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

#include<iostream>

#include <sys/types.h>
#include <cstdlib>
#include <string>
#include <thread>

#include "../common/err_out.h"
#include "configuration.h"
#include "vnet.h"
#include "tls.h"
#include "peer_init.h"
#include "nameserv.h"
#include "../common/network.h"
#include "../common/daemon.h"
#include "dht.h"
#include "dtls_dispatch.h"


// TODO: audit error and exception handling everywhere


int daemon_main()
{
	network_init();
	
	snow::conf.read_config();
	csocket nameserv_sock;
	try {
		sockaddrunion su;
		su.sa.sin_family = AF_INET;
		su.sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		su.sa.sin_port = htons(snow::conf[snow::NAMESERV_PORT]);
		nameserv_sock = csocket(AF_INET, SOCK_DGRAM);
		nameserv_sock.bind(su);
		nameserv_sock.setopt_exclusiveaddruse();
	} catch(const check_err_exception &e) {
		eout() << "Failed to set up nameserv listen socket: " << e;
		return EXIT_FAILURE;
	}
	// TODO: privilege separation
	// (set up any other sockets or anything needing privs)
	// (drop privileges here)

	try { tls_conn::tlsInit();	}
	catch(const e_not_found &e) {
		eout() << "Caught: " << e;
		return EXIT_FAILURE;
	} catch(const e_invalid_input &e) {
		eout() << "Caught: " << e;
		return EXIT_FAILURE;
	}

	worker_thread io; // general slow IO thread (for e.g. async writing to filesystem)
	dtls_dispatch_thread dispatch(&io);
	dht d_h_t(&dispatch, &io);
	nameserv ns(std::move(nameserv_sock), &d_h_t, &dispatch);
	d_h_t.set_pointers(&ns);
	dispatch.set_pointers(&d_h_t, &ns);
	
	// do all the things!
	std::thread io_thread(std::ref(io));
	std::thread dht_thread(std::ref(d_h_t));
	std::thread dispatch_thread(std::ref(dispatch));
	std::thread nameserv_thread(std::ref(ns));
	
	while(true) {
		/*os_event event = */ wait_for_os_event();
		// handle next event: right now all events mean "do shutdown" so just break and shutdown
		break;
		// TODO: implement os_event::reload as reread config file?
			// that's going to be a lot of work
	}
	dout() << "nameserv shutdown";
	ns.shutdown_thread();
	dout() << "dispatch shutdown pending";
	dispatch.shutdown_thread_pending();
	dout() << "DHT shutdown";
	d_h_t.shutdown_thread();
	dout() << "DHT join";
	dht_thread.join();
	dout() << "dispatch shutdown";
	dispatch.shutdown_thread();
	dout() << "dispatch join";
	dispatch_thread.join();
	dout() << "nameserv join";
	nameserv_thread.join();
	dout() << "io stop";
	io.stop();
	dout() << "io join";
	io_thread.join();
	iout() << "service has stopped";
	return EXIT_SUCCESS;
}

int main(int argc, char** argv)
{
	std::string config_filename = snow::conf[snow::CONFIG_FILE], daemon_name = "snow";
	bool daemonize = false;
#ifndef WINDOWS
	srandom((size_t)(&snow::conf) + time(nullptr));
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
	snow::conf.set_config_file(config_filename);
	try {
		if(daemonize)
			return daemon_start(&daemon_main, daemon_name.c_str());
		else
			return daemon_main();
	} catch(const e_exception &e) {
		eout() << "main() caught fatal or unhandled error: " << e;
		std::cout << "main() caught fatal or unhandled error: " << e << std::endl;
	}
	return EXIT_FAILURE;
}



