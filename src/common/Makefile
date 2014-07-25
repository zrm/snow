include ../defs.mk

COMMON_HDRS=$(wildcard *.h *.tpp)
COMMON_SRCS=$(wildcard *.cpp)
COMMON_OBJS=$(COMMON_SRCS:.cpp=.o)

all: $(COMMON_OBJS)

.depend: $(COMMON_HDRS)
	@rm -f .depend
	$(CXX) $(CXXFLAGS) -MM $(COMMON_SRCS) >>.depend;
include .depend


