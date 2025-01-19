CXX = clang++

DPDK_CFLAGS = $(shell pkg-config --cflags libdpdk)
DPDK_LIBFLAGS = $(shell pkg-config --libs libdpdk)

IFACE_EXE = main
FW_EXE = fw

OBJ_DIR = obj

DIRS = $(OBJ_DIR) $(OBJ_DIR)/interfaces $(OBJ_DIR)/parsers

cflags = -std=c++17 -MMD -MP
fw_cflags = 
interface_cflags = 

-include $(wildcard $(OBJ_DIR)/**/*.d)
# for some reason above wildcard doesn't include files directly in OBJ_DIR
-include $(wildcard $(OBJ_DIR)/*.d)

fw_cdeps = \
	main.cpp \
	fw_dpdk.cpp \
	interfaces/logs_server.cpp \
	ruletable.cpp \
	logger.cpp \
	macaddr.cpp \
	interfaces/ruletable_server.cpp \
	fnv_hash.cpp \
	conn_table.cpp
	
fw_odeps = $(patsubst %.cpp,$(OBJ_DIR)/%.o,$(fw_cdeps))

interface_cdeps = \
	interfaces/interface_main.cpp \
	interfaces/ruletable_client.cpp \
	interfaces/logs_client.cpp \
	interfaces/logs_server.cpp \
	ruletable.cpp \
	parsers/logs_parser.cpp \
	parsers/ruletable_parser.cpp \

interface_odeps = $(patsubst %.cpp,$(OBJ_DIR)/%.o,$(interface_cdeps))

# files that need to be compiled into object files with DPDK flags
DPDK_OBJS = fw_dpdk.cpp

all: directories $(FW_EXE) $(IFACE_EXE)

debug: cflags += -g -O0
debug: all

$(FW_EXE): $(fw_odeps) $(fw_hdeps)
	$(CXX) $(cflags) $(fw_cflags) $(DPDK_CFLAGS) $(fw_odeps) -o $(FW_EXE) $(DPDK_LIBFLAGS) 

$(IFACE_EXE): $(interface_odeps) $(interface_hdeps)
	$(CXX) $(cflags) $(interface_cflags) $(interface_odeps) -o $(IFACE_EXE)

$(OBJ_DIR)/%.o: %.cpp
	$(CXX) $(cflags) $(fw_cflags) -c $< -o $@

$(OBJ_DIR)/interfaces/%.o: interfaces/%.cpp
	$(CXX) $(cflags) $(interface_cflags) -c $< -o $@

$(OBJ_DIR)/$(DPDK_OBJS:.cpp=.o): $(DPDK_OBJS)
	$(CXX) $(cflags) $(DPDK_CFLAGS) -c $< -o $@

directories: $(DIRS)

$(DIRS):
	mkdir -p $@
