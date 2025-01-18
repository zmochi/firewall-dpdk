#include "fnv_hash.hpp"

#include <cstring>

uint64_t fnv_hash(uint64_t input) {
	/* values of FNV_offset_basis, FNV_prime and algorithm taken from
	 * https://en.wikipedia.org/wiki/Fowler–Noll–Vo_hash_function
	 */

	/* store in array to iterate over each byte separately */
	unsigned char data_to_hash[sizeof(input)];
	memcpy(data_to_hash, &input, sizeof(input));

	uint64_t FNV_offset_basis = 0xcbf29ce484222325;
	uint64_t FNV_prime = 0x00000100000001b3;
	uint64_t hash = FNV_offset_basis;

	/* TODO: add unroll directive? */
	for ( int i = 0; i < sizeof(data_to_hash); i++ ) {
		hash ^= data_to_hash[i];
		hash *= FNV_prime;
	}

	return hash;
}
