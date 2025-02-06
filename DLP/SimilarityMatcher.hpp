#include <limits>
#include <cstddef>
#include <string>

#include "aho_corasick.hpp"

using score_t = int;
constexpr score_t MAX_SCORE = std::numeric_limits<score_t>::max();

/* Similarity calculations:
 * 	- Given keywords and a text, calculate how many times the keywords
 * appear in the given text.
 */
class SimilarityMatcher {
    aho_corasick::trie trie;
    std::string        delim1, delim2;

  public:
    // Pass keywords
    SimilarityMatcher(std::string *keywords, size_t num_keywords);

    // Pass keywords with interesting delimiters, look for the keywords inside
    // delimiters only
    SimilarityMatcher(std::string *keywords, size_t num_keywords,
                      const std::string delim1, std::string delim2);

    // Pass text to match against
    score_t match(const char *text, size_t text_size);
};
