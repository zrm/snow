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

#include "daemon.h"
#include<mutex>
#include<condition_variable>
#include<queue>
#include<cstring>
#include"err_out.h"
#ifdef WINDOWS
#include<windows.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#endif




struct os_event_wait
{
	std::mutex mtx;
	std::condition_variable cond;
	std::queue<os_event> event_queue;
};

static os_event_wait os_event_wait_obj;

#ifdef WINDOWS
static int (*smain)();
static char *service_name;
static SERVICE_STATUS service_status;
static SERVICE_STATUS_HANDLE status_handle;
void WINAPI ServiceCtrlHandler(DWORD ctrlcode)
{
	std::lock_guard<std::mutex>(os_event_wait_obj.mtx);
	switch(ctrlcode) {
	case SERVICE_CONTROL_STOP:
	default:
		os_event_wait_obj.event_queue.push(os_event::shutdown);
		service_status.dwCurrentState = SERVICE_STOP_PENDING;
		service_status.dwControlsAccepted = 0;
		service_status.dwCheckPoint = 1;
		if(SetServiceStatus(status_handle, &service_status) == false)
			; // [complain]
		break;
	}
	os_event_wait_obj.cond.notify_one();
}
void WINAPI service_main(DWORD argc, LPSTR *argv)
{
	dout() << "service main";
	status_handle = RegisterServiceCtrlHandler(service_name, ServiceCtrlHandler);
	if(status_handle == nullptr) {
		return;
	}
	memset(&service_status, 0, sizeof(service_status));
	service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    service_status.dwCurrentState = SERVICE_START_PENDING;
	service_status.dwControlsAccepted = 0;
	if(SetServiceStatus(status_handle, &service_status) == false) {
		return;
	}

	service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    service_status.dwCurrentState = SERVICE_RUNNING;
	service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	if(SetServiceStatus(status_handle, &service_status) == false) {
		return;
	}
	
	int rv = smain();
	
	service_status.dwCurrentState = SERVICE_STOPPED;
	service_status.dwControlsAccepted = 0;
	service_status.dwWin32ExitCode = rv;
	service_status.dwCheckPoint = 2;
	if(SetServiceStatus(status_handle, &service_status) == false) {
		return;
	}
}
#else
void handle_signal(int sig)
{
	std::lock_guard<std::mutex>(os_event_wait_obj.mtx);
	switch(sig) {
	case SIGUSR1:
		os_event_wait_obj.event_queue.push(os_event::reload);
		break;
	case SIGTERM:
	default:
		os_event_wait_obj.event_queue.push(os_event::shutdown);
		break;
	}
	os_event_wait_obj.cond.notify_one();
}
#endif

#ifdef WINDOWS
int daemon_start(int (*dmain)(), const char *daemon_name)
{
	dout() << "Daemon start";
	smain = dmain;
	service_name = new char[strlen(daemon_name)];
	memcpy(service_name, daemon_name, strlen(daemon_name));
	SERVICE_TABLE_ENTRY service_table[] = { {service_name, (LPSERVICE_MAIN_FUNCTION) service_main}, {nullptr, nullptr} };
	xout_static::enable_syslog(daemon_name);
	if(StartServiceCtrlDispatcher(service_table) == false)
		return GetLastError();
	return EXIT_SUCCESS;
}
#else
int daemon_start(int (*dmain)(), const char *daemon_name)
{
	pid_t pid = fork();
	check_err(pid, "Failed to fork() daemon");
	if(pid > 0) {
		dout() << "Parent successfully fork()'d child daemon process with pid " << pid;
		return EXIT_SUCCESS;
	}
	// redirect stdin/stdout/stderr to /dev/null, from here we use syslog
	freopen("/dev/null", "r", stdin);
	freopen("/dev/null", "w", stdout);
	freopen("/dev/null", "w", stderr);
	xout_static::enable_syslog(daemon_name);
	umask(S_IWGRP | S_IWOTH);
	check_err(setsid(), "setsid() failed to create new session");
	check_err(chdir("/"), "Failed to change directory to '/'");
	return dmain();
}
#endif

const os_event os_event::shutdown(1);
const os_event os_event::reload(2);

os_event wait_for_os_event()
{
	std::unique_lock<std::mutex> ul(os_event_wait_obj.mtx);
	os_event rv = os_event::shutdown;
	while(true) {
		if(!os_event_wait_obj.event_queue.empty()) {
			rv = os_event_wait_obj.event_queue.front();
			os_event_wait_obj.event_queue.pop();
			break;
		}
		os_event_wait_obj.cond.wait(ul);
	}
	return rv;
}

void register_signals()
{
#ifndef WINDOWS
	struct sigaction signal_action;
	memset(&signal_action, 0, sizeof(signal_action));
	sigemptyset(&signal_action.sa_mask);
	signal_action.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &signal_action, nullptr);
	signal_action.sa_handler = &handle_signal;
	sigaction(SIGTERM, &signal_action, nullptr);
	sigaction(SIGINT, &signal_action, nullptr);
	sigaction(SIGUSR1, &signal_action, nullptr);
	// TODO: maybe add some other os_event objects for different signals
#endif
}
