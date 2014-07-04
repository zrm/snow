CC=gcc
CXX=g++
CFLAGS=-c -Wall -Wextra -O3 
CXXFLAGS=-std=c++11 -pthread $(CFLAGS)
SNOW_LDFLAGS=-lssl -lcrypto -lnatpmp -lminiupnpc
SNOW_SOURCES=common/common.cpp common/daemon.cpp common/err_out.cpp common/network.cpp common/pollvector.cpp common/windows_registry.cpp snow/configuration.cpp snow/crypto.cpp snow/dtls_dispatch.cpp snow/dht.cpp snow/handshake.cpp snow/ip_packet.cpp snow/main.cpp snow/natpmp.cpp snow/nameserv.cpp snow/netpool.cpp snow/peer_init.cpp snow/tls.cpp snow/tuntap.cpp snow/vnet.cpp
SNOW_OBJECTS=$(SNOW_SOURCES:.cpp=.o)

ifeq ($(OS),Windows_NT)
	CXXFLAGS+=-DWINDOWS -DWINSOCK -DNOCRYPT -D_WINNT_WIN32=0x500 -DNO_UPNP -DNO_NATPMP
	SNOW_OBJECTS+=applink.o
	SNOW_LDFLAGS+=-lws2_32 -liphlpapi -L/c/msys/1.0/home/user/openssl-1.0.1e/dist/lib
	SNOW_EXECUTABLE=snowd.exe
else
	SNOW_LDFLAGS+=-lpthread
	SNOW_EXECUTABLE=snowd
endif

all: $(SNOW_EXECUTABLE)
	
$(SNOW_EXECUTABLE): $(SNOW_OBJECTS) 
	$(CXX) $(SNOW_OBJECTS) $(SNOW_LDFLAGS) -o $(SNOW_EXECUTABLE)

applink.o:
	$(CC) $(CFLAGS) /c/Program\ Files\ \(x86\)/mingw-builds/x32-4.8.1-posix-dwarf-rev5/mingw32/lib/gcc/i686-w64-mingw32/4.8.1/include/openssl/applink.c -o applink.o

.cpp.o:
	$(CXX) $(CXXFLAGS) $< -o $@
	

clean:
	rm common/*.o snow/*.o $(SNOW_EXECUTABLE)
	
	
