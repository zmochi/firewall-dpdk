CC = clang++

DPDK_CFLAGS = $(shell pkg-config --cflags libdpdk)
DPDK_LIBFLAGS = $(shell pkg-config --libs libdpdk)

IFACE_EXE = main
FW_EXE = fw

OBJ_DIR = obj

DIRS = $(OBJ_DIR) $(OBJ_DIR)/interfaces $(OBJ_DIR)/parsers

cflags = -std=c++17
fw_cflags = 
interface_cflags = 

fw_cdeps = \
	main.cpp \
	fw_dpdk.cpp \
	interfaces/logs_server.cpp \
	ruletable.cpp \
	logger.cpp \
	macaddr.cpp \
	interfaces/ruletable_server.cpp \

fw_odeps = $(patsubst %.cpp,$(OBJ_DIR)/%.o,$(fw_cdeps))

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
	interfaces/ruletable_server.hpp \

interface_cdeps = \
	interfaces/interface_main.cpp \
	interfaces/ruletable_client.cpp \
	interfaces/logs_client.cpp \
	interfaces/logs_server.cpp \
	ruletable.cpp \
	parsers/logs_parser.cpp \
	parsers/ruletable_parser.cpp \

interface_odeps = $(patsubst %.cpp,$(OBJ_DIR)/%.o,$(interface_cdeps))

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

# files that need to be compiled with DPDK flags
DPDK_OBJS = fw_dpdk.cpp

all: directories $(FW_EXE) $(IFACE_EXE)

debug: cflags += -g -O0
debug: all

$(FW_EXE): $(fw_odeps) $(fw_hdeps)
	$(CC) $(cflags) $(fw_cflags) $(DPDK_CFLAGS) $(fw_odeps) -o $(FW_EXE) $(DPDK_LIBFLAGS) 

$(IFACE_EXE): $(interface_odeps) $(interface_hdeps)
	$(CC) $(cflags) $(interface_cflags) $(interface_odeps) -o $(IFACE_EXE)

$(OBJ_DIR)/%.o: %.cpp
	$(CC) $(cflags) $(fw_cflags) -c $< -o $@

$(OBJ_DIR)/interfaces/%.o: interfaces/%.cpp
	$(CC) $(cflags) $(interface_cflags) -c $< -o $@

$(OBJ_DIR)/$(DPDK_OBJS:.cpp=.o): $(DPDK_OBJS)
	$(CC) $(cflags) $(DPDK_CFLAGS) -c $< -o $@

directories: $(DIRS)

$(DIRS):
	mkdir -p $@
