include defs.mk

COMMON_HDRS=$(wildcard common/*.h common/*.tpp)
COMMON_SRCS=$(wildcard common/*.cpp)
COMMON_OBJS=$(COMMON_SRCS:.cpp=.o)
COMMON_DEPS=$(COMMON_HDRS) $(COMMON_SRCS)
SNOW_HDRS=$(wildcard snow/*.h)
SNOW_SRCS=$(wildcard snow/*.cpp)
SNOW_OBJS+=$(SNOW_SRCS:.cpp=.o)
SNOW_DEPS=$(COMMON_HDRS) $(SNOW_HDRS) $(SNOW_SRCS)

all: $(SNOW_BINARY) nss_snow/$(NSS_SNOW_BINARY) nss_snow/$(NSS_SNOW_TEST)

$(SNOW_BINARY): $(COMMON_OBJS) $(SNOW_OBJS) 
	$(CXX) $(COMMON_OBJS) $(SNOW_OBJS) $(SNOW_LDFLAGS) -o $(SNOW_BINARY)

nss_snow/$(NSS_SNOW_BINARY) nss_snow/$(NSS_SNOW_TEST): nss_snow/$(NSS_SNOW_SRC) .nss_snow

.INTERMEDIATE: .common .snow .nss_snow
$(COMMON_OBJS): $(COMMON_DEPS) .common
	@touch $@
$(SNOW_OBJS): $(SNOW_DEPS) .snow
	@touch $@
.common:
	make -C common
.snow:
	make -C snow
.nss_snow:
	make -C nss_snow

install: all
	$(INSTALL) -d $(SNOWCONFDIR)
	$(INSTALL) -d $(SNOWVAR)
	$(INSTALL) -m 0755 -o root -g root $(SNOW_BINARY) $(SBIN)
	$(INSTALL) -m 0755 -o root -g root nss_snow/$(NSS_SNOW_BINARY) $(LIB)
	ln -s $(LIB)/$(NSS_SNOW_BINARY) $(USRLIB)/$(NSS_SNOW_SO)
	$(INSTALL) -m 0700 -o root -g root ../known_peers $(SNOWVAR)

uninstall:
	-killall -q $(SNOW_BINARY)
	-rm -i $(USRLIB)/$(NSS_SNOW_SO) $(LIB)/$(NSS_SNOW_BINARY)
	-rm -ir $(SBIN)/$(SNOW_BINARY) $(SNOWVAR) $(SNOWCONFDIR)

clean:
	rm -f */*.o */.depend nss_snow/$(NSS_SNOW_BINARY) nss_snow/$(NSS_SNOW_TEST) $(SNOW_BINARY)


 
