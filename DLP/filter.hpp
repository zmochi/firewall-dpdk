#include <cstddef> /* for size_t */

enum filter_dc {
	FILTER_DROP,
	FILTER_WAIT,
};

using filter_fn = filter_dc (*)(char* pkt_tcp_data, size_t size);
