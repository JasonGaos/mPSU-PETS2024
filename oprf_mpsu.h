#pragma once
#include <cryptoTools/Crypto/RCurve.h>
#include <cryptoTools/Common/config.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/AES.h>
#include "gbf.h"
#include "utl.h"
#include "eccConvert.h"



using namespace osuCrypto;

inline std::vector<u8>  dh_oprf(u64 myIdx,std::vector<u8> x,std::vector<std::vector<Channel>>chls){
	PRNG prng(_mm_set_epi32(11111, 34567 + myIdx, 234435, 23987054));
	REllipticCurve curve;//(CURVE_25519)
	//receiver
	if (myIdx == 0){

		REccPoint x_point;

		x.insert(x.begin(), 2);

		x_point.fromBytes(x.data());

		REccNumber a(curve);
		a.randomize(prng);

		x_point *= a;

		x_point.toBytes(x.data());

		chls[0][1].send(x.data(),x.size());
		chls[0][1].recv(x.data(),x.size());

		x_point.fromBytes(x.data());

		a = a.inverse();

		x_point *= a;

		x_point.toBytes(x.data());
		return x;


	}
	//sender
	else if(myIdx == 1){
		std::vector<u8> recv_x_vec (33);
		chls[1][0].recv(recv_x_vec.data(),recv_x_vec.size());
		
		REccPoint x_point;
		x_point.fromBytes(recv_x_vec.data());
		//random key
		//block b_block = prng.get<block>();	
		//chosen key
		
		std::vector<u8> b_vec = x;
		REccNumber b(curve);
		b.fromBytes(b_vec.data());
		
		x_point *= b;

		x_point.toBytes(recv_x_vec.data());
		chls[1][0].send(recv_x_vec.data(),recv_x_vec.size());
		
		return x;
		
	}
}

inline std::vector<osuCrypto::block> aes_oprf(u64 myIdx,std::vector<osuCrypto::block> input,u64 setSize,std::vector<std::vector<Channel>>chls,osuCrypto::block AES_key){
	//receiver
	if(myIdx == 0){

		std::vector<osuCrypto::block> recv_okvs_table(setSize*okvsLengthScale);

		chls[0][1].recv(recv_okvs_table.data(),recv_okvs_table.size());

		std::vector<osuCrypto::block> oprf_value(input.size());
		GbfDecode(recv_okvs_table,input,oprf_value);
		//print_block(oprf_value);
		return oprf_value;
	}
	//sender
	else if (myIdx == 1){

		
		AES aes_oprf(AES_key);

		std::vector<osuCrypto::block> oprf_value(input.size());

		aes_oprf.ecbEncBlocks(input.data(),input.size(),oprf_value.data());
		//print_block(oprf_value);

		std::vector<osuCrypto::block> okvs_table(input.size()*okvsLengthScale);

		GbfEncode(input,oprf_value,okvs_table);

		chls[1][0].send(okvs_table.data(),okvs_table.size());

		return oprf_value;
	}else{
		return std::vector<osuCrypto::block> {toBlock(u64(0))};
	}

}

inline void oprf_test(){
	u64 setSize = 1 << 2;
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

	// set generation
	// first half of same elements and second half of different elements.s

	// ECC Points
	// nParties * setSize * 32 u8 vector
	std::vector<std::vector<std::vector<u8>>> inputSet_u8(nParties);
	// nParties * 2setSize  vector
	std::vector<std::vector<block>> inputSet_block(nParties);

	for (u64 i = 0; i < nParties; i++)
	{
		PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, 23987054));
		PRNG prngDiff(_mm_set_epi32(4253465, 3434565, 234423, i));
		// std::cout<<"input from party "<<i<<std::endl;
		REllipticCurve curve; //(CURVE_25519)
		// generater g
		const auto &g = curve.getGenerator();
		for (u64 j = 0; j < setSize; j++)
		{

			REccNumber num(curve);

			if (j < setSize / 2)
			{
				num.randomize(prngSame);
			}
			else
			{
				num.randomize(prngDiff);
			}
			REccPoint p = g * num;
			std::vector<u8> p_vec(g.sizeBytes());
			p.toBytes(p_vec.data());
			p_vec.erase(p_vec.begin());
			// print_u8vec(p_vec);
			inputSet_u8[i].push_back(p_vec);
			std::vector<block> p_block = u8vec_to_blocks(p_vec);
			inputSet_block[i].push_back(p_block[0]);
			inputSet_block[i].push_back(p_block[1]);

			// it is safe to erase the first bit (give 2 later still generate a valid point)
			//  p_vec.erase(p_vec.begin());
			//  p_vec.insert(p_vec.begin(), 2);
			//  p.fromBytes(p_vec.data());
		}
	}

    PRNG prngAES(_mm_set_epi32(123, 3434565, 234435, 23987054));
    std::vector<osuCrypto::block> AES_keys;
    AES_keys.push_back(prngAES.get<osuCrypto::block>());

	//thread 
	std::vector<std::thread>  pThrds(nParties);
	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
	{
		pThrds[pIdx] = std::thread([&, pIdx]() {
			// block a = toBlock(123);
			// block result = dh_oprf(pIdx,a,chls);
			// std::cout<<"result "<<pIdx<<" "<<result<<std::endl;

			// std::vector<osuCrypto::block> result = aes_oprf(pIdx, inputSet[pIdx], setSize,chls,AES_keys[0]);
			std::vector<u8> result = dh_oprf(pIdx, inputSet_u8[pIdx][0],chls);

			

		});
	}

	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
		pThrds[pIdx].join();



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

