#pragma once

#define okvsHashFunctions  3
#define okvsLengthScale  1.27



using namespace osuCrypto;

inline void print_block(std::vector<block> a) {

	for (u64 i = 0; i < a.size(); i++) {
		std::cout << a[i] << std::endl;
	}


}

inline void print_u8vec(std::vector<u8> a) {

	for (u64 i = 0; i < a.size(); i++) {
		std::cout << std::hex<< unsigned(a[i]);
	}

	std::cout << std::endl;

}
