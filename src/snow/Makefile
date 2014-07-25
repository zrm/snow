include ../defs.mk

COMMON_HDRS=$(wildcard ../common/*.h ../common/*.tpp)
SNOW_HDRS=$(wildcard *.h)
SNOW_SRCS=$(wildcard *.cpp)
SNOW_OBJS+=$(SNOW_SRCS:.cpp=.o)

all: $(SNOW_OBJS) 

applink.o:
	$(CC) $(CFLAGS) /c/Program\ Files\ \(x86\)/mingw-builds/x32-4.8.1-posix-dwarf-rev5/mingw32/lib/gcc/i686-w64-mingw32/4.8.1/include/openssl/applink.c -o applink.o

.depend: $(COMMON_HDRS) $(SNOW_HDRS) 
	@rm -f .depend
	$(CXX) $(CXXFLAGS) -MM $(SNOW_SRCS) >>.depend;
include .depend

