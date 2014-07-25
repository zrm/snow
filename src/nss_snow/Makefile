include ../defs.mk
CFLAGS+=-Wno-unused-parameter -Os

all: $(NSS_SNOW_BINARY) $(NSS_SNOW_TEST)

$(NSS_SNOW_BINARY): $(NSS_SNOW_SRC)
	$(CC) $(CFLAGS) -fPIC -shared -o $(NSS_SNOW_BINARY) -Wl,-soname,$(NSS_SNOW_BINARY) $(NSS_SNOW_SRC)

$(NSS_SNOW_TEST): $(NSS_SNOW_SRC)
	$(CC) $(CFLAGS) -DDEBUG=1 -DNSS_SNOW_MAIN_TEST $(NSS_SNOW_SRC) -o $(NSS_SNOW_TEST)


