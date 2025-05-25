#ifndef __FILTER_H
#define __FILTER_H

#include <cstddef> /* for size_t */

enum filter_dc {
	FILTER_DROP,
	FILTER_WAIT,
	FILTER_PASS,
};

using filter_fn = filter_dc (*)(const char* pkt_tcp_data, size_t size);

filter_dc filter_entry(const char* pkt_tcp_data, size_t size);

#endif /* __FILTER_H */
