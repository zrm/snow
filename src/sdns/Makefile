include ../defs.mk

COMMON_HDRS=$(wildcard ../common/*.h ../common/*.tpp)
SDNS_HDRS=$(wildcard *.h)
SDNS_SRCS=$(wildcard *.cpp)
SDNS_OBJS+=$(SDNS_SRCS:.cpp=.o)

all: $(SDNS_OBJS) 

.depend: $(COMMON_HDRS) $(SDNS_HDRS) 
	@rm -f .depend
	$(CXX) $(CXXFLAGS) -MM $(SDNS_SRCS) >>.depend;
include .depend

