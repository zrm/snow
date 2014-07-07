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

#include "pollvector.h"

template<class T>
pollvector<T>::pollvector(const std::function<void(size_t)> &cleanup, size_t min_dynamic_start, const char* pv_name) : cleanup_handler(cleanup), dynamic_start(min_dynamic_start), pvname(pv_name) {
#ifdef PV_USE_EPOLL
	const unsigned default_size = 8;
	check_err(epfd = epoll_create(default_size), "Could not create epoll descriptor");
	epevents_size = default_size;
	epevents = reinterpret_cast<epoll_event*>(malloc(sizeof(epoll_event) * epevents_size));
	if(epevents == nullptr) throw std::bad_alloc();
#endif
}

template<class T>
pollvector<T>::~pollvector()
{
#ifdef PV_USE_EPOLL
	while(close(epfd)!=0) {
		if(errno != EINTR) {
			eout_perr() << pvname << ": Failed to close epoll descriptor";
			break;	
		} else {
			dout() << pvname << ": EINTR closing epoll descriptor";
		}
	}
	free(epevents);
#elif defined(WINSOCK)
	// this is a bit particular, we have to:
		// 1) cancel the events for every entry (so that every peer_id index is SIZE_MAX and has cancel in tqueue and every event occurrence has either been added or will not be)
		// 2) execute every entry in tqueue, which for real events will do nothing (invalid index) and for cancel events will delete the peer_id as required
	while(data.size() > dynamic_start) {
		cancel_events(data.size()-1);
		*data.back().index = SIZE_MAX;
		data.pop_back();
	}
	event_exec_wait(0); // execute events that delete peer_id objects
#endif
}


template<class T> template<class... Args>
void pollvector<T>::emplace_back(csocket::sock_t sock, pvevent event, const std::function<void(size_t,pvevent,sock_err)> &ef, Args&&... args)
{
#if defined(PV_USE_EPOLL)
	if(data.size() >= epevents_size) {
		epevents_size = epevents_size ? epevents_size*2 : 8;
		epevents = reinterpret_cast<epoll_event*>(realloc(epevents, sizeof(epoll_event)*epevents_size));
		if(epevents==nullptr) throw std::bad_alloc();
	}
	data.emplace_back(std::forward<Args>(args)..., ef, sock, event, data.size());
	if(sock >= 0) {
		if(epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &data.back().epevents) < 0) {
			data.pop_back();
			throw check_err_exception("epoll_ctl adding socket for new pollvector element");
		}
	}
#elif defined(PV_USE_KQUEUE)
	// [add to kqueue]
#elif defined(WINSOCK)
	size_t idx = data.size();
	data.emplace_back(std::forward<Args>(args)..., ef, sock, idx);
	set_events(idx, event);
#else	// poll()
	data.emplace_back(std::forward<Args>(args)..., ef);
	poll.emplace_back(pollfd{sock, (short int)event.event, 0});
#endif
}

// TODO: sometimes windows gives ERROR_IO_PENDING for UnregisterWait[Ex] for unknown reasons, try to figure out why
	// maybe could have something to do with async read and write happening concurrently on tuntap? check if that is the fd when it occurs
#ifdef WINSOCK
template<class T>
void pollvector<T>::cancel_events(size_t index)
{
	if(data[index].peer_id != nullptr) {
		// this is ugly because the peer_id must be deleted but can't be until after any event in the event_tqueue which contains it has been processed
		// so what happens instead is: 
			// 1) UnregisterWaitEx blocks until the event callback has either completed or will not be called (i.e. if there will be an event it is already in the tqueue)
			// 2) peer_id->wait_handle is set to INVALID_HANDLE_VALUE so if there is any event it will not delete peer_id
			// 3) a cancelation event is added to the event queue to delete peer_id, which is guaranteed to run after the callback event if there was one
		if(UnregisterWaitEx(data[index].peer_id->wait_handle, INVALID_HANDLE_VALUE) == false && GetLastError() != ERROR_IO_PENDING) {
			wout() << "BUG: UnregisterWaitEx failed in pollvector::cancel_events: " << strerror_rp(GetLastError());
		}
		data[index].peer_id->wait_handle = INVALID_HANDLE_VALUE; // indicate that if event is received it should not be deleted; cancelation event will delete
		event_tqueue.put(winsock_event{data[index].peer_id, winsock_event::EVENT_CANCELED});
		data[index].peer_id = nullptr; // this will be deleted when the cancelation event is processed, and should no longer be accessed from here
	}
}

template<class T>
void pollvector<T>::process_winsock_event(winsock_event&& ev)
{
	// be careful here: if an event has been requested, it must continue to be checked when event_exec_wait is called
		// even if the external callback does not call re-enabling functions such as recv() for FD_READ
	// however, it must also not create busy loops or runaway memory consumption as would occur by e.g. using a manual reset event w/o WT_EXECUTEONLYONCE
	// the answer is to use WT_EXECUTEONLYONCE and then call WSAEventSelect and create a new event for each call to event_fn, after the call to event_fn returns
		// that way if the event is still signaled then it gets issued again but only after calling event_fn
		// TODO: there is probably a way to do this without deleting and recreating the peer object every time, look into it
	size_t index = *ev.peer->index;
	switch(ev.event) {
	case winsock_event::EVENT_OCCURRED:
		if(index < data.size()) {
			if(ev.peer->wait_handle != INVALID_HANDLE_VALUE) {
				if(UnregisterWait(ev.peer->wait_handle) == false && GetLastError() != ERROR_IO_PENDING)
					wout() << "BUG: " << pvname << ": UnregisterWait failed for index " << index << " in process_winsock_event: " << get_windows_errorstr(GetLastError());
				ev.peer->wait_handle = INVALID_HANDLE_VALUE;
				delete ev.peer; // delete only if wait_handle was valid, otherwise there will be a subsequent EVENT_CANCELED that will delete
				data[index].peer_id = nullptr; // if wait_handle was not invalid then this is/was the current peer_id
			}
			// still execute the event even if wait handle is invalid because defunct and existing event masks may overlap, i.e. it may still be a valid event
			WSANETWORKEVENTS network_events;
			if(WSAEnumNetworkEvents(data[index].sock, data[index].event_handle.ev, &network_events) == SOCKET_ERROR) {
				wout() << "BUG: WSAEnumNetworkEvents in process_winsock_event gave error " << sock_err::get_last();
				dout() << "BUG socket was " << data[index].sock;
				// maybe throw exception?
			} else if(data[index].events.event & network_events.lNetworkEvents) {
				size_t err = ERROR_SUCCESS;
				for(size_t i=0; i < FD_MAX_EVENTS; ++i) {
					if(network_events.iErrorCode[i] != ERROR_SUCCESS && ( (1 << i) & network_events.lNetworkEvents ) ) { // error codes not in event mask are apparently uninitialized
						err = network_events.iErrorCode[i];
						if(err != ERROR_SUCCESS) {
							WSASetLastError(err);
							eout() << "Got error for " << index << " at event " << i << ": " << sock_err::get_last();
						}
					}
				}
				if(err == ERROR_SUCCESS) {
					dout() << "got winsock event with no error";
					data[index].event_fn(index, data[index].events.event & network_events.lNetworkEvents, sock_err::enoerr);
				} else {
					WSASetLastError(err);
					data[index].event_fn(index, pvevent::error, sock_err::get_last());
				}
			}
			if(data[index].peer_id == nullptr)
				set_events(index, data[index].events); // re-register existing events if event_fn hasn't set new ones
		} // (else index is invalid, peer is gone and EVENT_CANCELED will follow soon)
		break;
	case winsock_event::EVENT_CANCELED:
		delete ev.peer; // has to be deleted here because doing it here ensures it happens after any possible EVENT_OCCURRED event is processed
		break;
	case winsock_event::FORCE_READ:
		if(index < data.size())
			data[index].event_fn(index, pvevent::read, sock_err::enoerr);
		delete ev.peer;
		break;
	case winsock_event::FORCE_WRITE:
		if(index < data.size())
			data[index].event_fn(index, pvevent::read, sock_err::enoerr);
		delete ev.peer;
		break;
	}
}
#endif

template<class T>
void pollvector<T>::set_fd(size_t index, csocket::sock_t fd, bool close_existing)
{
	csocket close(close_existing ? get_fd(index) : INVALID_SOCKET); // destructor will close sock after epoll_ctl etc.
#ifdef WINSOCK
	dout() << pvname <<  " socket " << data[index].sock << " at " << index << " changed to " << fd;
	data[index].sock = fd;
	set_events(index, data[index].events);
#elif defined(PV_USE_EPOLL)
	if(data[index].sock >= 0)
		if(epoll_ctl(epfd, EPOLL_CTL_DEL, data[index].sock, &data[index].epevents) < 0)
			dout_perr() << pvname << " set_fd failed to remove old fd " << data[index].sock;
	data[index].sock = fd;
	if(fd >= 0)
		check_err(epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &data[index].epevents), "epoll_ctl adding socket for set_fd()");
#else // poll()
	poll[index].fd = fd;
#endif
}

template<class T>
csocket::sock_t pollvector<T>::get_fd(size_t index)
{
#if defined(WINSOCK) || defined(PV_USE_EPOLL)
	return data[index].sock;
#else
	return poll[index].fd;
#endif
}
template<class T>
pvevent pollvector<T>::get_events(size_t index) const
{
#ifdef WINSOCK
	return data[index].events;
#elif defined(PV_USE_EPOLL)
	return data[index].epevents.events;
#else // poll()
	return poll[index].events;
#endif
}
template<class T>
void pollvector<T>::set_events(size_t index, pvevent events)
{
#ifdef WINSOCK
	cancel_events(index);
	data[index].events = events;
	dout() << pvname << " pollvector set events for " << index << ":" << ((events & pvevent::read) ? " read" : "") << ((events & pvevent::write) ? " write" : "");
	if(events != pvevent::none && data[index].sock != INVALID_SOCKET) {
		try {
			if(data[index].event_handle.ev == WSA_INVALID_EVENT)
				data[index].event_handle = wsa_event();
			data[index].event_handle.event_select(data[index].sock, data[index].events.event);
		} catch(const e_exception &e) {
			wout() << pvname << " pollvector::set_events: " << e;
#warning fixme: handle exception: call event fn with error event?
		}
		data[index].peer_id = new winsock_peer(this, data[index].index, data[index].event_handle.ev);
	}
#elif defined(PV_USE_EPOLL)
	if(data[index].epevents.events != events.event) {
		data[index].epevents.events = events.event;
		if(data[index].sock >= 0)
			check_err(epoll_ctl(epfd, EPOLL_CTL_MOD, data[index].sock, &data[index].epevents), "epoll_ctl modifying socket events");
	}
#else
	poll[index].events = events.event;
#endif
}
template<class T>
void pollvector<T>::add_events(size_t index, pvevent events)
{
#if defined(WINSOCK) || defined(PV_USE_EPOLL)
	set_events(index, get_events(index) | events);
#else
	poll[index].events |= events.event;
#endif
}
template<class T>
void pollvector<T>::clear_events(size_t index, pvevent events)
{
#if defined(WINSOCK) || defined(PV_USE_EPOLL)
	set_events(index, get_events(index).event & (~events.event));
#else // poll()
	poll[index].events &= ~events.event;
#endif
}

template<class T>
void pollvector<T>::mark_defunct(size_t index)
{
#ifdef WINSOCK
	data[index].events = pvevent::none;
	cancel_events(index);
#elif defined(PV_USE_EPOLL)
	data[index].epevents.events = 0;
	if(data[index].sock >= 0)
		if(epoll_ctl(epfd, EPOLL_CTL_DEL, data[index].sock, &data[index].epevents) < 0)
			dout_perr() << pvname << " failed to EPOLL_CTL_DEL socket";
#else
	poll[index].events = pvevent::none;
#endif
	defunct_connections.push_back(index);
}

template<class T>
bool pollvector<T>::cleanup_defunct_connections()
{
	if(defunct_connections.size() == 0)
		return false;
	// sort the remove vector so that we remove the highest numbered defunct connection first,
	// that way we can swap with connections.back() and never invalidate the index of another unprocessed remove element
	std::sort(defunct_connections.begin(), defunct_connections.end());
	do
	{
		size_t remove_index = defunct_connections.back();
		dout() << pvname << " cleanup_defunct_connections: removing connection at index " << remove_index;
		while(defunct_connections.size() > 0 && defunct_connections.back() == remove_index)
			defunct_connections.pop_back(); // pop remove_index and any duplicates
		if(remove_index >= size() || remove_index < dynamic_start) {
			// TODO: this might want to be a throw in mark_defunct() in addition to this here
			eout() << "BUG: Tried to remove a non-existent connection in " << pvname << " pollvector: " << remove_index;
			continue;
		}
		cleanup_handler(remove_index);
		reorder_remove(remove_index);
	} while(defunct_connections.size() > 0);
	return true;
}

template<class T>
void pollvector<T>::reorder_remove(size_t remove_index)
{
	if(remove_index == data.size()-1)
		dout() << pvname << " socket " << get_fd(remove_index) << " removed from defunct peer at " << remove_index;
	else
		dout() << pvname << " socket " << get_fd(data.size()-1) << " moved from " << (data.size()-1) << " to " << remove_index << " replacing defunct " << get_fd(remove_index);
	// give socket to csocket whose destructor will close it (if it is not INVALID_SOCKET)
	// note that this causes close() to be called after e.g. epoll_ctl(EPOLL_CTL_DEL) below as required
	csocket defunct_sock(get_fd(remove_index));
#ifdef WINSOCK
	cancel_events(remove_index);
	if(data.back().peer_id != nullptr)
		*data.back().index = remove_index;
	if(data[remove_index].peer_id != nullptr)
		*data[remove_index].index = SIZE_MAX;
#elif defined(PV_USE_EPOLL)
	if(data[remove_index].sock >= 0) {
		if(epoll_ctl(epfd, EPOLL_CTL_DEL, data[remove_index].sock, &data[remove_index].epevents) < 0)
			dout_perr() << pvname << " reorder_remove failed to remove fd " << data[remove_index].sock;
	}
	data.back().setidx(remove_index);
	if(remove_index != data.size()-1 && data.back().sock >= 0)
		if(epoll_ctl(epfd, EPOLL_CTL_MOD, data.back().sock, &data.back().epevents) < 0)
			dout_perr() << pvname << " epoll_ctl failed to move existing socket";
	if(epevents_size > (data.size()<<2)) {
		epevents_size>>=1;
		epevents = reinterpret_cast<epoll_event*>(realloc(epevents, sizeof(epoll_event)*epevents_size));
		if(epevents == nullptr && epevents_size) throw std::bad_alloc();
	}
#else // poll()
	poll[remove_index] = std::move(poll.back());
	poll.pop_back();
#endif
	data[remove_index] = std::move(data.back());
	data.pop_back();
}



struct pollfd;
void print_poll_error(const pollfd& p);
void print_epoll_error(uint32_t events);

template<class T>
void pollvector<T>::event_exec_wait(int timeout)
{
	if(cleanup_defunct_connections())
		return; // if connections were cleaned up return immediately, timeout could now be too long
#ifdef WINSOCK
	try {
		wsa_event tqueue_event;
		tqueue_event.event_select(event_tqueue.getSD(), FD_READ);
		DWORD rv = WaitForSingleObjectEx(tqueue_event.ev, timeout, TRUE);
		switch(rv) {
		case WAIT_IO_COMPLETION:
			break;
		case WAIT_OBJECT_0:
			event_tqueue.for_each(std::bind(&pollvector<T>::process_winsock_event, this, std::placeholders::_1));
			break;
		case WAIT_TIMEOUT:
			break;
		default:
			// some error, TODO: handle error
			dout() << "Error from WaitForSingleObjectEx in pollvector " << pvname << " event_exec_wait()";
			break;
		}
	} catch(const e_exception &e) {
		dout() << "event_exec_wait caught: " << e;
	}
	// dout() << "Doing event_exec_wait() with WINSOCK select() timeout " << timeout << ", sds: " << socket_map;
#elif defined(PV_USE_EPOLL)
	int numevents = epoll_wait(epfd, epevents, epevents_size, timeout);
	while(numevents < 0 && errno==EINTR)
		numevents = epoll_wait(epfd, epevents, epevents_size, timeout);
	if(numevents < 0) {
		eout_perr() << pvname << " pollvector epoll_wait()";
		throw check_err_exception("epoll_wait()");
	}
	for(ssize_t j=0; j < numevents; ++j) {
		size_t idx = sizeof(size_t)>4 ? epevents[j].data.u64 : epevents[j].data.u32;
		if(idx >= data.size()) {
			// most likely cause of this is adding sock to pv, dup() it and close original before removing from pv
			eout() << "BUG: pollvector logic error or " << pvname << " did not properly remove epoll descriptor before closing";
			continue;
		}
		if(epevents[j].events & (~(EPOLLIN | EPOLLOUT))) {
			if(data[idx].event_fn != nullptr) {
				data[idx].event_fn(idx, pvevent::error, sock_err::get_error(get_fd(idx)));
			} else {
				// call sock_err::get_error() to at least clear the error and prevent a polling loop:
				wout() << "pollvector epoll error without event function at index " << idx << " for fd " << get_fd(idx) << ": " << sock_err::get_error(get_fd(idx));
			}
		} else if(epevents[j].events != 0 && data[idx].event_fn != nullptr) {
			data[idx].event_fn(idx, pvevent(epevents[j].events & (EPOLLIN|EPOLLOUT)), sock_err::enoerr);
		}
	}
#else // poll()
	int numevents = ::poll(poll.data(), poll.size(), timeout);
	if(is_sock_err(numevents))
	{
		eout() << pvname << " pollvector poll(): " << sock_err::get_last();
		throw e_check_sock_err("poll()", true);
	}
	for(size_t i=0; i < poll.size(); ++i) {
		if(poll[i].revents & (~(POLLIN | POLLOUT))) {
			print_poll_error(poll[i]);
			if(data[i].event_fn != nullptr) {
				data[i].event_fn(i, pvevent::error, sock_err::get_error(poll[i].fd));
			} else {
				// call this to at least clear the error and prevent a polling loop
				eout() << "pollvector poll error without event function at index " << i << " for fd " << poll[i].fd << ": " << sock_err::get_error(poll[i].fd);
			}
		} else if(poll[i].revents != 0 && data[i].event_fn != nullptr) {
			data[i].event_fn(i, pvevent(poll[i].revents & (POLLIN|POLLOUT)), sock_err::enoerr);
		}

	}
#endif
}
