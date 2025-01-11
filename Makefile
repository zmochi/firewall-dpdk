DPDK_CFLAGS = $(shell pkg-config --cflags libdpdk)
DPDK_LIBFLAGS = $(shell pkg-config --libs libdpdk)

IFACE_EXECUTABLE_NAME = main
FW_EXECUTABLE_NAME = fw

fw_cflags = -std=c++17
interface_cflags = 

fw_cdeps = \
	main.cpp \
	fw_dpdk.cpp \
	interfaces/logs_server.cpp \
	ruletable.cpp \
	logger.cpp \
	macaddr.cpp \

fw_hdeps = \
	interfaces/ruletable_interface.hpp \
	interfaces/simple_ipc.hpp \
	macaddr.hpp \
	interfaces/logs_interface.hpp \
	packet.hpp \
	firewall.hpp \
	interfaces/ruletable_client.hpp \
	interfaces/logs_server.hpp \
	endian.hpp \
	logger.hpp \
	ruletable.hpp \

interface_cdeps = \
	interfaces/interface_main.cpp \
	interfaces/ruletable_client.cpp \
	interfaces/logs_client.cpp \
	interfaces/logs_server.cpp \
	ruletable.cpp \
	parsers/logs_parser.cpp \
	parsers/ruletable_parser.cpp \

interface_hdeps = \
	interfaces/ruletable_interface.hpp \
	interfaces/simple_ipc.hpp \
	interfaces/logs_interface.hpp \
	packet.hpp \
	interfaces/ruletable_client.hpp \
	interfaces/logs_client.hpp \
	endian.hpp \
	logger.hpp \
	parsers/logs_parser.hpp \
	parsers/ruletable_parser.hpp \
	ruletable.hpp

all: fw iface

debug: interface_cflags += -g -O0
debug: fw_cflags += -g -O0
debug: all

fw: $(fw_cdeps) $(fw_hdeps)
	clang++ $(fw_cflags) $(DPDK_CFLAGS) $(fw_cdeps) -o $(FW_EXECUTABLE_NAME) $(DPDK_LIBFLAGS) 

iface: $(interface_cdeps) $(interface_hdeps)
	clang++ $(interface_cflags) $(interface_cdeps) -o $(IFACE_EXECUTABLE_NAME)
