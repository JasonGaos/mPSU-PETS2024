#pragma once
//#include "cryptoTools/Crypto/Curve.h"
#include <cryptoTools/Crypto/RCurve.h>
#include <cryptoTools/Common/config.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/AES.h>

#include <libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h>
#include <libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h>
#include "gbf.h"
#include "utl.h"
#include <vector>

using namespace osuCrypto;


inline std::vector<u8> block_to_u8vec(block a, int size_curve_points) {

	u8 var8[16];
	memcpy(var8, &a, sizeof(var8));
	std::vector<u8> dest(16);
	for (u64 i = 0; i < 16; i++) {
		dest[i] = var8[sizeof(var8) - i - 1];
	}
	//pad zero for the 16 high bit.
	std::vector<u8> zero_high(size_curve_points - 16, 0);
	dest.insert(dest.begin(), zero_high.begin(), zero_high.end());

	return dest;
}

inline block u8vec_to_block(std::vector<u8> dest,int size_curve_points) {
	u8 var8[16];

	for (u64 i = 0; i < 16; i++) {
		var8[sizeof(var8) - i - 1] = dest[size_curve_points - 16 + i];
	}

	block a;

	memcpy(&a, &var8, sizeof(a));

	return a;
}

inline std::vector<block> num_vec_to_blocks(std::vector<u8> vec) {

	std::vector<block> a;

	u8 var8_1[16];
	u8 var8_2[16];
	block b1; //ctx[1:16]
	block b2; //ctx[17:33]

	for (u64 i = 0; i < 16; i++) {
		var8_1[i] = vec[vec.size() - 16 - 1 - i];
		var8_2[i] = vec[vec.size() - 1 - i];
	}

	memcpy(&b1, &var8_1, sizeof(a));
	memcpy(&b2, &var8_2, sizeof(a));

	a.push_back(b1);
	a.push_back(b2);

	return a;
}

inline std::vector<block> point_vec_to_blocks(std::vector<u8> vec) {

	std::vector<block> a;

	if (vec[0] == 0) {
		a.push_back(toBlock(u64(0)));
	}
	else {
		a.push_back(toBlock(u64(1)));
	}

	//vec.erase(vec.begin());

	std::vector<block> b = num_vec_to_blocks(vec);


	a.insert(a.end(), b.begin(), b.end());

	return a;
}

inline std::vector<u8> blocks_to_num_vec(std::vector<block> blocks) {

	std::vector<u8> vec(32);
	u8 var8_1[16];
	u8 var8_2[16];
	block ctx_1;
	memcpy(&var8_1, &blocks[0], sizeof(var8_1));
	memcpy(&var8_2, &blocks[1], sizeof(var8_2));

	for (u64 i = 0; i < 16; i++) {
		vec[i] = var8_1[16 - 1 - i];
		vec[i + 16] = var8_2[16 - 1 - i];
	}

	return vec;
}

inline std::vector<u8> blocks_to_point_vec(std::vector<block> blocks) {
	u8 first_bit;
	if (blocks[0] == toBlock(u64(0))) {
		first_bit = 0;
	}
	else {
		first_bit = 1;
	}

	blocks.erase(blocks.begin());

	std::vector<u8> vec = blocks_to_num_vec(blocks);

	vec.insert(vec.begin(), first_bit);

	return vec;
}


inline std::vector<block> ciphertexts_to_blocks(std::vector<u8> ctx1, std::vector<u8> ctx2) {
	int num_block = 4;// 2*33*8/128
	std::vector<block> a;

	block b;
	if (ctx1[0] == 0 && ctx2[0] == 0)
		b = toBlock(u64(0));
	else if (ctx1[0] == 0 && ctx2[0] == 1)
		b = toBlock(u64(1));
	else if (ctx1[0] == 1 && ctx2[0] == 0)
		b = toBlock(u64(2));
	else if (ctx1[0] == 1 && ctx2[0] == 1)
		b = toBlock(u64(3));

	a.push_back(b);
	
	u8 var8_1[16];
	u8 var8_2[16];
	block ctx_1; //ctx[1:16]
	block ctx_2; //ctx[17:33]
	
	for (u64 i = 0; i < 16; i++) {
		var8_1[i] = ctx1[ctx1.size() - 16 - 1 - i];
		var8_2[i] = ctx1[ctx1.size() - 1 - i];
	}
	
	memcpy(&ctx_1, &var8_1, sizeof(a));
	memcpy(&ctx_2, &var8_2, sizeof(a));

	a.push_back(ctx_1);
	a.push_back(ctx_2);

	for (u64 i = 0; i < 16; i++) {
		var8_1[i] = ctx2[ctx2.size() - 16 - 1 - i];
		var8_2[i] = ctx2[ctx2.size() - 1 - i];
	}

	memcpy(&ctx_1, &var8_1, sizeof(a));
	memcpy(&ctx_2, &var8_2, sizeof(a));

	a.push_back(ctx_1);
	a.push_back(ctx_2);

	return a;

}

inline std::vector<std::vector<u8>> blocks_to_ciphertexts(std::vector<block> blocks, int size_curve_points) {

	std::vector<std::vector<u8>> a;
	std::vector<u8> ctx1(size_curve_points-1);
	std::vector<u8> ctx2(size_curve_points-1);

	
	u8 var8_1[16];
	u8 var8_2[16];
	block ctx_1;
	block ctx_2;

	memcpy(&var8_1, &blocks[1], sizeof(var8_1));
	memcpy(&var8_2, &blocks[2], sizeof(var8_2));

	for (u64 i = 0; i < 16; i++) {
		ctx1[i] = var8_1[16 - 1 - i];
		ctx1[i + 16] = var8_2[16 - 1 - i];
	}

	memcpy(&var8_1, &blocks[3], sizeof(var8_1));
	memcpy(&var8_2, &blocks[4], sizeof(var8_2));

	for (u64 i = 0; i < 16; i++) {
		ctx2[i] = var8_1[16 - 1 - i];
		ctx2[i + 16] = var8_2[16 - 1 - i];
	}

	//std::cout << "before insert" << std::endl;
	
	if (blocks[0] == toBlock(u64(0))) {
		ctx1.insert(ctx1.begin(), 0);
		ctx2.insert(ctx2.begin(), 0);
	}
	else if (blocks[0] == toBlock(u64(1))) {
		ctx1.insert(ctx1.begin(), 0);
		ctx2.insert(ctx2.begin(), 1);
	}
	else if (blocks[0] == toBlock(u64(2))) {
		ctx1.insert(ctx1.begin(), 1);
		ctx2.insert(ctx2.begin(), 0);
	}
	else if (blocks[0] == toBlock(u64(3))) {
		ctx1.insert(ctx1.begin(), 1);
		ctx2.insert(ctx2.begin(), 1);
	}
	//std::cout << "after insert" << std::endl;
	
	a.push_back(ctx1);
	a.push_back(ctx2);

	return a;
}
