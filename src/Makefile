CC?=cc
CXX?=c++
CFLAGS?=-Wall -Wextra -O3 
CXXFLAGS?=-std=c++11 -pthread $(CFLAGS)
INSTALL=install
SBIN=/usr/sbin
SNOWCONFDIR=/etc/snow
SNOWVAR=/var/lib/snow
LIB=/lib/`arch`-linux-gnu
USRLIB=/usr/lib/`arch`-linux-gnu

SNOW_LDFLAGS=-lssl -lcrypto
ifdef NO_NATPMP
CXXFLAGS+=-DNO_NATPMP
else
SNOW_LDFLAGS+=-lnatpmp
endif
ifdef NO_UPNP
CXXFLAGS+=-DNO_UPNP
else
SNOW_LDFLAGS+=-lminiupnpc
endif
SNOW_SOURCES=common/common.cpp common/daemon.cpp common/err_out.cpp common/network.cpp common/pollvector.cpp common/windows_registry.cpp snow/configuration.cpp snow/crypto.cpp snow/dtls_dispatch.cpp snow/dht.cpp snow/handshake.cpp snow/ip_packet.cpp snow/main.cpp snow/natpmp.cpp snow/nameserv.cpp snow/netpool.cpp snow/peer_init.cpp snow/tls.cpp snow/tuntap.cpp snow/vnet.cpp
SNOW_OBJECTS=$(SNOW_SOURCES:.cpp=.o)

ifeq ($(OS),Windows_NT)
	CXXFLAGS+=-DWINDOWS -DWINSOCK -DNOCRYPT -D_WINNT_WIN32=0x500
	SNOW_OBJECTS+=applink.o
	SNOW_LDFLAGS+=-lws2_32 -liphlpapi -L/c/msys/1.0/home/user/openssl-1.0.1e/dist/lib
	SNOW_BINARY=snowd.exe
else
	SNOW_LDFLAGS+=-lpthread
	SNOW_BINARY=snowd
endif

SNOW_NSS_SO?=libnss_snow.so
SNOW_NSS_BINARY?=$(SNOW_NSS_SO).2
SNOW_NSS_TEST?=snow_nss_test

all: $(SNOW_BINARY) nss_snow/$(SNOW_NSS_BINARY) nss_snow/$(SNOW_NSS_TEST)

nss_snow/$(SNOW_NSS_BINARY): nss_snow/nss_snow.c
	$(CC) $(CFLAGS) -Wno-unused-parameter -Os -fPIC -shared -o nss_snow/$(SNOW_NSS_BINARY) -Wl,-soname,$(SNOW_NSS_BINARY) nss_snow/nss_snow.c

nss_snow/$(SNOW_NSS_TEST): nss_snow/nss_snow.c
	$(CC) $(CFLAGS) -Wno-unused-parameter -Os -DDEBUG=1 -DNSS_SNOW_MAIN_TEST nss_snow/nss_snow.c -o nss_snow/$(SNOW_NSS_TEST)

$(SNOW_BINARY): $(SNOW_OBJECTS) 
	$(CXX) $(SNOW_OBJECTS) $(SNOW_LDFLAGS) -o $(SNOW_BINARY)

applink.o:
	$(CC) $(CFLAGS) /c/Program\ Files\ \(x86\)/mingw-builds/x32-4.8.1-posix-dwarf-rev5/mingw32/lib/gcc/i686-w64-mingw32/4.8.1/include/openssl/applink.c -o applink.o

.cpp.o:
	$(CXX) $(CXXFLAGS) $< -c -o $@

install: all
	$(INSTALL) -d $(SNOWCONFDIR)
	$(INSTALL) -d $(SNOWVAR)
	$(INSTALL) -m 0755 -o root -g root $(SNOW_BINARY) $(SBIN)
	$(INSTALL) -m 0755 -o root -g root nss_snow/$(SNOW_NSS_BINARY) $(LIB)
	ln -s $(LIB)/$(SNOW_NSS_BINARY) $(USRLIB)/$(SNOW_NSS_SO)
	$(INSTALL) -m 0700 -o root -g root ../known_peers $(SNOWVAR)

uninstall:
	-killall -q $(SNOW_BINARY)
	-rm -ir $(USRLIB)/$(SNOW_NSS_SO) $(LIB)/$(SNOW_NSS_BINARY) $(SBIN)/$(SNOW_BINARY) $(SNOWVAR) $(SNOWCONFDIR)

clean:
	rm common/*.o snow/*.o $(SNOW_BINARY) nss_snow/$(SNOW_NSS_BINARY) nss_snow/$(SNOW_NSS_TEST)

