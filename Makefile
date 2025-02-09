CXX = clang++

DPDK_CFLAGS = $(shell pkg-config --cflags libdpdk)
DPDK_LIBFLAGS = $(shell pkg-config --libs libdpdk)

IFACE_EXE = main
FW_EXE = fw

OBJ_DIR = obj

DIRS = $(OBJ_DIR) $(OBJ_DIR)/interfaces $(OBJ_DIR)/parsers $(OBJ_DIR)/DLP

cflags = -std=c++17 -MMD -MP
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
	fnv_hash.cpp \
	conn_table.cpp \
	$(wildcard DLP/*.cpp)
	
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

all: libs directories $(FW_EXE) $(IFACE_EXE)

debug: cflags += -g -O0
debug: all

PCRE2_build_dir = external/PCRE2.build
PCRE2_LIBFLAGS = -L$(PCRE2_build_dir) -lpcre2-8
PCRE2_CFLAGS = -I$(PCRE2_build_dir)
libs:
	make -C external

$(FW_EXE): $(fw_odeps) $(fw_hdeps)
	$(CXX) $(cflags) $(fw_cflags) $(DPDK_CFLAGS) $(fw_odeps) -o $(FW_EXE) $(DPDK_LIBFLAGS) $(PCRE2_LIBFLAGS)

$(IFACE_EXE): $(interface_odeps) $(interface_hdeps)
	$(CXX) $(cflags) $(interface_cflags) $(interface_odeps) -o $(IFACE_EXE)

$(OBJ_DIR)/%.o: %.cpp
	$(CXX) $(cflags) $(fw_cflags) -c $< -o $@

$(OBJ_DIR)/interfaces/%.o: interfaces/%.cpp
	$(CXX) $(cflags) $(interface_cflags) -c $< -o $@

$(OBJ_DIR)/DLP/%.o: DLP/%.cpp
	$(CXX) $(cflags) $(PCRE2_CFLAGS) -c $< -o $@

$(OBJ_DIR)/$(DPDK_OBJS:.cpp=.o): $(DPDK_OBJS)
	$(CXX) $(cflags) $(DPDK_CFLAGS) -c $< -o $@

directories: $(DIRS)

$(DIRS):
	mkdir -p $@

-include $(wildcard $(OBJ_DIR)/**/*.d)
# for some reason above wildcard doesn't include files directly in OBJ_DIR
-include $(wildcard $(OBJ_DIR)/*.d)
