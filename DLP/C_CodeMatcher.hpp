#include <string>
#include <limits>
#include <vector>

#define PCRE2_CODE_UNIT_WIDTH 8
#include "../external/PCRE2.build/pcre2.h"

using score_t = int;
constexpr score_t MAX_SCORE = std::numeric_limits<score_t>::max();
constexpr score_t MIN_SCORE = 0;

class C_CodeMatcher {
	std::vector<std::pair<pcre2_code*, score_t>> patterns;

public:
	C_CodeMatcher();
	~C_CodeMatcher();

	score_t match(const std::string_view text);
};
