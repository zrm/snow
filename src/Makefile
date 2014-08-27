include defs.mk

COMMON_HDRS=$(wildcard common/*.h common/*.tpp)
COMMON_SRCS=$(wildcard common/*.cpp)
COMMON_OBJS=$(COMMON_SRCS:.cpp=.o)
COMMON_DEPS=$(COMMON_HDRS) $(COMMON_SRCS)
SNOW_HDRS=$(wildcard snow/*.h)
SNOW_SRCS=$(wildcard snow/*.cpp)
SNOW_OBJS+=$(SNOW_SRCS:.cpp=.o)
SNOW_DEPS=$(COMMON_HDRS) $(SNOW_HDRS) $(SNOW_SRCS)
SDNS_HDRS=$(wildcard sdns/*.h)
SDNS_SRCS=$(wildcard sdns/*.cpp)
SDNS_OBJS+=$(SDNS_SRCS:.cpp=.o)
SDNS_DEPS=$(COMMON_HDRS) $(SDNS_HDRS) $(SDNS_SRCS)


all: $(SNOW_BINARY) $(SDNS_BINARY) $(NSS_SNOW_BINARY) $(NSS_SNOW_TEST)

$(SNOW_BINARY): $(COMMON_OBJS) $(SNOW_OBJS) 
	$(CXX) $(COMMON_OBJS) $(SNOW_OBJS) $(SNOW_LDFLAGS) -o $(SNOW_BINARY)

$(SDNS_BINARY): $(COMMON_OBJS) $(SDNS_OBJS)
	$(CXX) $(COMMON_OBJS) $(SDNS_OBJS) $(SDNS_LDFLAGS) -o $(SDNS_BINARY)

$(NSS_SNOW_BINARY) $(NSS_SNOW_TEST): nss_snow/$(NSS_SNOW_SRC) .nss_snow

.INTERMEDIATE: .common .snow .sdns .nss_snow
$(COMMON_OBJS): $(COMMON_DEPS) .common
	@touch -- $@
$(SNOW_OBJS): $(SNOW_DEPS) .snow
	@touch -- $@
$(SDNS_OBJS): $(SDNS_DEPS) .sdns
	@touch -- $@
.common:
	$(MAKE) -C common
.snow:
	$(MAKE) -C snow
.sdns:
	$(MAKE) -C sdns
.nss_snow:
	$(MAKE) -C nss_snow

install: all
	$(INSTALL) -d $(SNOWCONFDIR)
	$(INSTALL) -d $(SNOWVAR)
	$(INSTALL) -d $(SDNSCONFDIR)
	$(INSTALL) -d $(SDNSFWDDIR)
	$(INSTALL) -m 0755 -o root -g root $(SNOW_BINARY) $(SBIN)
	$(INSTALL) -m 0755 -o root -g root $(SDNS_BINARY) $(SBIN)
	$(INSTALL) -m 0444 -o root -g root $(SDNS_ROOTHINTS) $(SDNSCONFDIR)
	$(INSTALL) -m 0644 -o root -g root $(SDNS_LOCALNAMES) $(SDNSCONFDIR)
	$(INSTALL) -m 0600 -o root -g root ../known_peers $(SNOWVAR)

uninstall:
	-killall -q -- $(SNOW_BINARY) $(SDNS_BINARY)
	-rm -ir -- $(SBIN)/$(SNOW_BINARY) $(SNOWVAR) $(SNOWCONFDIR)
	-rm -ir -- $(SBIN)/$(SDNS_BINARY) $(SDNSFWDDIR) $(SDNSCONFDIR)

clean:
	rm -f -- */*.o */.depend $(NSS_SNOW_BINARY) $(NSS_SNOW_TEST) $(SNOW_BINARY) $(SDNS_BINARY)


 
