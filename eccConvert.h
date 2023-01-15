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

//#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
//#include "libOTe/TwoChooseOne/IknpOtExtSender.h"
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

inline std::vector<block> u8vec_to_blocks(std::vector<u8> dest) {
	u8 var8_1[16];
	u8 var8_2[16];
	std::vector<block> result;
	block a;

	for (u64 i = 0; i < 16; i++) {
		var8_1[sizeof(var8_1) - i - 1] = dest[16 + i];
		var8_2[sizeof(var8_2) - i - 1] = dest[i];
	}
	
	memcpy(&a, &var8_2, sizeof(a));
	result.push_back(a);
	memcpy(&a, &var8_1, sizeof(a));
	result.push_back(a);
	
	return result;
}

inline std::vector<u8> blocks_to_u8vec(std::vector<block> a){
	u8 var8_1[16];
	memcpy(var8_1, &a[0], sizeof(var8_1));
	u8 var8_2[16];
	memcpy(var8_2, &a[1], sizeof(var8_2));

	std::vector<u8> dest(32);
	for (u64 i = 0; i < 16; i++) {
		dest[i] = var8_1[sizeof(var8_1) - i - 1];
		dest[i+16] = var8_2[sizeof(var8_2) - i - 1];
	}

	return dest;
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

inline std::vector<block> ciphertexts_to_blocks(std::vector<std::vector<u8>>& ctx) {
	std::vector<u8> ctx1 = ctx[0];
	std::vector<u8> ctx2 = ctx[1];
	int num_block = 4;// 2*33*8/128
	std::vector<block> a;
	
	block b;
	if (ctx1[0] == 2 && ctx2[0] == 2)
		b = toBlock(u64(0));
	else if (ctx1[0] == 2 && ctx2[0] == 3)
		b = toBlock(u64(1));
	else if (ctx1[0] == 3 && ctx2[0] == 2)
		b = toBlock(u64(2));
	else if (ctx1[0] == 3 && ctx2[0] == 3)
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

	memcpy(&ctx_1, &var8_1, sizeof(ctx_1));
	memcpy(&ctx_2, &var8_2, sizeof(ctx_2));

	a.push_back(ctx_1);
	a.push_back(ctx_2);

	for (u64 i = 0; i < 16; i++) {
		var8_1[i] = ctx2[ctx2.size() - 16 - 1 - i];
		var8_2[i] = ctx2[ctx2.size() - 1 - i];
	}

	memcpy(&ctx_1, &var8_1, sizeof(ctx_1));
	memcpy(&ctx_2, &var8_2, sizeof(ctx_2));

	a.push_back(ctx_1);
	a.push_back(ctx_2);

	return a;

}

inline std::vector<std::vector<u8>> blocks_to_ciphertexts(std::vector<block> blocks) {

	std::vector<std::vector<u8>> a;
	std::vector<u8> ctx1(32);
	std::vector<u8> ctx2(32);

	
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
		ctx1.insert(ctx1.begin(), 2);
		ctx2.insert(ctx2.begin(), 2);
	}
	else if (blocks[0] == toBlock(u64(1))) {
		ctx1.insert(ctx1.begin(), 2);
		ctx2.insert(ctx2.begin(), 3);
	}
	else if (blocks[0] == toBlock(u64(2))) {
		ctx1.insert(ctx1.begin(), 3);
		ctx2.insert(ctx2.begin(), 2);
	}
	else if (blocks[0] == toBlock(u64(3))) {
		ctx1.insert(ctx1.begin(), 3);
		ctx2.insert(ctx2.begin(), 3);
	}
	//std::cout << "after insert" << std::endl;
	
	a.push_back(ctx1);
	a.push_back(ctx2);

	return a;
}

inline std::vector<std::vector<u8>> encryption(std::vector<u8> m_vec, std::vector<u8> pk_vec,PRNG& prng_enc ){
	//Encryption and Decryption testing (ElGamal)
	REllipticCurve curve;//(CURVE_25519)
	
	//generater g
	const auto& g = curve.getGenerator();
	//std::cout <<g.sizeBytes()<< std::endl;
	//sk

	REccPoint pk;
	pk.fromBytes(pk_vec.data());

	m_vec.insert(m_vec.begin(), 2);

	REccPoint m(curve);

	m.fromBytes(m_vec.data());
	//std::cout<<" 6 " <<std::endl;
	REccNumber r(curve);
	r.randomize(prng_enc);

	REccPoint c1 = g * r;
	REccPoint c2 = m + pk * r;

	std::vector<u8> c1_vec(g.sizeBytes());
	std::vector<u8> c2_vec(g.sizeBytes());
	
	c1.toBytes(c1_vec.data());
	c2.toBytes(c2_vec.data());

	std::vector<std::vector<u8>> ciphertext;
	ciphertext.push_back(c1_vec);
	ciphertext.push_back(c2_vec);

	return ciphertext;
	
}

inline std::vector<u8> decryption(std::vector<std::vector<u8>> ciphertext, std::vector<u8> sk_vec ){
	//REllipticCurve curve;//(CURVE_25519)

	REccPoint c1;
	REccPoint c2;
	REccNumber sk;
	c1.fromBytes(ciphertext[0].data());
	c2.fromBytes(ciphertext[1].data());
	sk.fromBytes(sk_vec.data());
	
	REccPoint dec_m = c2 - c1 * sk;
	
	std::vector<u8> dec_m_vec(33);
	//std::cout<<"size: "<<dec_m_vec.size()<<std::endl;
	dec_m.toBytes(dec_m_vec.data());

	dec_m_vec.erase(dec_m_vec.begin());
	
	//print_u8vec(dec_m_vec);

	//block dec_message = u8vec_to_block(dec_m_vec,32);
	//std::cout << "decode message: "<<dec_message << std::endl;
	return dec_m_vec;

}

inline std::vector<std::vector<u8>> partial_decryption(std::vector<std::vector<u8>> ciphertext, std::vector<u8> sk_vec){
	//output a ctx

	REccPoint c1;
	REccPoint c2;
	REccNumber sk;
	c1.fromBytes(ciphertext[0].data());
	c2.fromBytes(ciphertext[1].data());
	sk.fromBytes(sk_vec.data());

	// REccPoint r;
	// r.randomize(prng_dec);
	
	c2 -= c1 * sk;
	std::vector<u8> new_ctx1 = ciphertext[0];
	std::vector<u8> new_ctx2(33);
	c2.toBytes(new_ctx2.data());

	std::vector<std::vector<u8>> ctx;
	ctx.push_back(new_ctx1);
	ctx.push_back(new_ctx2);

	return ctx;
}

inline void ecc_channel_test(){
	u64 setSize = 1 << 4;
	u64 psiSecParam = 40;
	u64 bitSize = 128;
	u64 nParties = 2;

	//Create Channels
	IOService ios(0);

	auto ip = std::string("127.0.0.1");

	std::string sessionHint = "psu";

	std::vector<std::vector<Session>> ssns(nParties,std::vector<Session>(nParties));
	std::vector<std::vector<Channel>> chls(nParties, std::vector<Channel>(nParties));
	
	for (u64 i = 0; i < nParties; i++) {
		for (u64 j = 0; j < nParties; j++) {
			if (i < j) {
				u32 port = 1100 + j * 100 + i;
				std::string serversIpAddress = ip + ':' + std::to_string(port);
				ssns[i][j].start(ios, serversIpAddress, SessionMode::Server, sessionHint);

				chls[i][j] = ssns[i][j].addChannel();
				//ep[i].start(ios, "localhost", port, true, name); //channel bwt i and pIdx, where i is receiver
			}
			else if (i > j) {
				u32 port = 1100 + i * 100 + j ;
				std::string serversIpAddress = ip + ':' + std::to_string(port);
				ssns[i][j].start(ios, serversIpAddress, SessionMode::Client, sessionHint);
				chls[i][j] = ssns[i][j].addChannel();
				//ep[i].start(ios, "localhost", port, false, name); //channel bwt i and pIdx, where i is sender
			}
		}
	}

	
	//Encryption and Decryption testing (ElGamal)
	REllipticCurve curve;//(CURVE_25519)
	PRNG prng(_mm_set_epi32(19249,4923, 2335, 123));
	PRNG prng_r(_mm_set_epi32(4253465, 3434565, 23443, 1231));
	//generater g
	const auto& g = curve.getGenerator();
	//std::cout <<g.sizeBytes()<< std::endl;
	//sk
	REccNumber sk(curve);
	sk.randomize(prng);
	std::vector<u8> sk_vec(g.sizeBytes()-1);
	sk.toBytes(sk_vec.data());
	//print_u8vec(sk_vec);
	//sk_vec.insert(sk_vec.begin(), 2);
	//REccPoint sk_p;
	//sk_p.fromBytes(sk_vec.data());
	//pk
	REccPoint pk = g * sk;
	std::vector<u8> pk_vec(g.sizeBytes());
	pk.toBytes(pk_vec.data());


	for(u64 i = 0;i<10;i++){
		// REccNumber r(curve);
		// r.randomize(prng);
		// REccPoint m = g * r;
		// std::vector<u8> m_vec(g.sizeBytes());
		// m.toBytes(m_vec.data());
		// m_vec.erase(m_vec.begin());
		
		std::vector<u8> zero_u8(32,0);
		std::vector<std::vector<u8>> ciphertext = encryption(zero_u8, pk_vec, prng );
		//print_u8vec(ciphertext[0]);
		//print_u8vec(ciphertext[1]);
		
		std::vector<block> ctx_block = ciphertexts_to_blocks(ciphertext);

		ciphertext = blocks_to_ciphertexts(ctx_block);

		std::vector<u8> zero_u8_dec = decryption(ciphertext,sk_vec);
		print_u8vec(zero_u8_dec);


	}

	std::cout<<"Test done"<<std::endl;

	//generate a valid set
	//u64 setSize = 1<<4;
	// std::vector<block> input;
	// for(u64 i = 0;i<10;i++){
		
	// 	block message = prng.get<block>();

	// 	std::vector<u8> m_vec(g.sizeBytes() - 1,0);
	// 	m_vec = block_to_u8vec(message,g.sizeBytes()-1);

	// 	m_vec.insert(m_vec.begin(), 2);

	// 	REccPoint m(curve);
	// 	std::cout<<"123"<<m.isValidPoint(m_vec.data())<<std::endl;
	// 	if(m.isValidPoint(m_vec.data())){
	// 		input.push_back(message);
	// 	}else{
	// 		std::cout<<"no good"<<std::endl;
	// 	}


	// 	// std::cout<<i<<std::endl;
	// 	// REccNumber m_num(curve);
	// 	// m_num.randomize(prng);
	// 	// std::vector<u8> m_vec(g.sizeBytes()-1);
	// 	// m_num.toBytes(m_vec.data());
	// 	// print_u8vec(m_vec);
	// 	// m_vec.insert(m_vec.begin(), 2);
	// 	// REccPoint m_p;
	// 	// m_p.fromBytes(m_vec.data());
		
	// 	// REccPoint m_p(curve);
	// 	// m_p.randomize(prng);
	// 	// std::vector<u8> m_vec(g.sizeBytes());
	// 	// print_u8vec(m_vec);



	// }

	//std::cout<<input.size()<<std::endl;

	// for (u64 i = 0; i<10; i++){
	// 	block message = input[i];
	// 	std::cout <<"message: " <<message << std::endl;

	// 	std::vector<std::vector<u8>> ciphertext = encryption(message, pk_vec );

	// 	block plaintext = decryption(ciphertext,sk_vec);
	
	// 	std::cout <<"dec message : " << plaintext << std::endl;
	// }
	


	

	chls[0][1].send(pk_vec.data(),pk_vec.size());
	std::vector<u8> recv_pk_vec(g.sizeBytes());
	chls[1][0].recv(recv_pk_vec.data(),recv_pk_vec.size());
	
	//Close channels
	for (u64 i = 0; i < nParties; i++) {
		for (u64 j = 0; j < nParties; j++) {
			if (i != j) {
				chls[i][j].close();
			}
		}
	}
	for (u64 i = 0; i < nParties; i++) {
		for (u64 j = 0; j < nParties; j++) {
			if (i != j) {
				ssns[i][j].stop();
			}
		}
	}

	ios.stop();
}
