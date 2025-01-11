#include "logger.hpp"
#include "utils.h"
#include <mutex>

#define LOGS_PER_NODE 64

uint64_t get_timestamp_now() {
    using namespace std::chrono;
    auto now = system_clock::now();

    static_assert(sizeof(milliseconds) == sizeof(uint64_t),
                  "Miliseconds have unexpected size");
    return duration_cast<milliseconds>(now.time_since_epoch()).count();
}

int log_list::store_log(log_row_t log_row) {
	std::unique_lock<std::mutex> hashmap_lock(log_hashmap_lock);

    auto item = log_hashmap.find(log_row);
    if ( item != log_hashmap.end() )
        item->second.count++;
    else {
        if ( log_row.timestamp != 0 ) {
            ERROR("log timestamp must be initialized before storing");
            return -1;
        }
        log_row.count = 0;
		log_hashmap[log_row] = log_row;
    }

    return 0;
}
