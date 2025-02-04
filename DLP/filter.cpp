#include "filter.hpp"
#include "http_parser.hpp"

#include <string>

std::string c_similarities[] = {
    "#ifdef",
    "#ifndef",
    "void main(int argc, char* argv[])",
    "#define",
	"typdef",
};

struct trie_entry {
    char               ch[sizeof(void *)];
    struct trie_entry *next;
};

class trie {};

trie c_code_trie(c_similarities);

using score_t = int;

void filter_handle_http(char* request, size_t size) {
	http_parsed_req req = http_parse_request(request, size);
	if(req.method != M_POST) 
	score_t score = c_code_trie.match(pkt_tcp_data, size);
}

filter_dc filter_c_code(char *pkt_tcp_data, size_t size) {
    constexpr score_t passing_score = 4;
	char* data;
	size_t data_size;

	if(is_http(pkt_tcp_data, size)) {
		filter_handle_http(pkt_tcp_data, size);
		// set data_size to Content-Length header
	}
	if(score >= passing_score) {
		return FILTER_DROP;
	}
}
