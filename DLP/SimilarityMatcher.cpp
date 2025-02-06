#include "SimilarityMatcher.hpp"
#include "aho_corasick.hpp"

SimilarityMatcher::SimilarityMatcher(std::string* keywords, size_t num_keywords) : trie() {
	for(int i = 0; i < num_keywords; i++) {
		trie.insert(keywords[i]);
	}
}

SimilarityMatcher::SimilarityMatcher(std::string *keywords, size_t num_keywords, const std::string delim1, std::string delim2) : trie(), delim1(delim1), delim2(delim2) {}

score_t SimilarityMatcher::match(const char* text, size_t text_size) {
	std::string text_view(text, text_size);
	auto matches = trie.parse_text(text_view);
	score_t num_matches = matches.size();
	return num_matches;
}

#ifdef SIMILARITY_MATCHER_UNIT_TEST
#include <iostream>
int main(void) {
	std::string keywords[] = {
		"#ifdef",
		"#define",
		"char*",
		"int",
		"extern",
		"();"
	};
	std::string text = R"EOF(
#ifdef __linux__
#define __test__
#endif
int main(int argc, char* argv[]) {
	doSomething();

	return 1;
}
		)EOF";
	SimilarityMatcher m(keywords, sizeof(keywords)/sizeof(keywords[0]));
	score_t score = m.match(text.data(), text.size());
	if(score != 6) {
		std::cout << "SimilarityMatcher test failed" << std::endl;
	}
}
#endif
