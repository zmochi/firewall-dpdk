#include <string>
#include <limits>
#include <vector>

using score_t = int;
constexpr score_t MAX_SCORE = std::numeric_limits<score_t>::max();
constexpr score_t MIN_SCORE = 0;

class C_CodeMatcher {
	std::vector<std::pair<struct pcre2_real_code_8*, score_t>> patterns;

public:
	C_CodeMatcher();
	~C_CodeMatcher();

	score_t match(const std::string_view text);
};
