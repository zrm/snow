CC=gcc

CFLAGS=-Wall -Os
LDFLAGS=
all: libnss_snow.so.2 nss_snow_test

libnss_snow.so.2: nss_snow.c
	$(CC) $(CFLAGS) -fPIC -shared -o libnss_snow.so.2 -Wl,-soname,libnss_snow.so.2 nss_snow.c

nss_snow_test: nss_snow.c
	$(CC) $(CFLAGS) -DDEBUG=1 -DNSS_SNOW_MAIN_TEST nss_snow.c -o nss_snow_test

clean:
	rm libnss_snow.so.2 nss_snow_test

