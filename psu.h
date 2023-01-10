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

#include <libOTe/TwoChooseOne/IknpOtExtReceiver.h>
#include <libOTe/TwoChooseOne/IknpOtExtSender.h>
#include "gbf.h"
#include "utl.h"
#include "eccConvert.h"
#include "oprf_mpsu.h"

using namespace osuCrypto;

inline std::vector<block> rpir_ot_sim(u64 myIdx, std::vector<block> input, std::vector<std::vector<Channel>> chls, u64 setSize,u64 round,PRNG& secret_value_generater,u64 i){
	/*
	receiver with input of its set in blocks 

	sender with input of a vector input of length 18:
		input[0:1] is the value of element y
		input[2] is 1st aes key0 which is the ot message 0
		input[3] is 2nd aes key1 which is the ot message 1
		input[4:10] is the aes encrypted message of v0
			[4:5] random value
			[6:10] Enc(0) 
		input[11:17] is the aes encrypted message of v1
			[11:12] F(k,y)
			[13:17] Enc(y)

	receiver output corresponding message of length 7:
		[4:10] if y \in X [11:17] otherwise.
	*/

	AES hashOKVS(toBlock(12138));

	//receiver
	if (myIdx == 0) {
		//1.okvs
		block secret_value = secret_value_generater.get<block>();
		//std::cout<<"secret value: "<<secret_value<<std::endl;
		
		std::vector<block> okvs_value(input.size());
		hashOKVS.ecbEncBlocks(input.data(),input.size(),okvs_value.data());
		
		for (u64 i = 0; i < okvs_value.size(); i++) {
			okvs_value[i] = okvs_value[i] ^ secret_value;
		}


		//std::cout<<"okvs value: "<<okvs_value[0]<<std::endl;
		
		std::vector<block> okvs_table(input.size()*okvsLengthScale);
		GbfEncode(input,okvs_value,okvs_table);

		chls[myIdx][1].send(okvs_table.data(), okvs_table.size());

		
		//2.gc

		//3.ot
		/*
		OT reciever here for the AES key
		*/


		//======== simulation ==========
		std::vector<block> recv_aes_key (1);
		chls[myIdx][1].recv(recv_aes_key.data(), recv_aes_key.size());
		//===============================

		std::vector<block> recv_aes_message (14);
		chls[myIdx][1].recv(recv_aes_message.data(), recv_aes_message.size());

		//message decode 
		AESDec decryptor(recv_aes_key[0]);
		block indicator = decryptor.ecbDecBlock(recv_aes_message[2]);
		std::vector<block> return_value;
		if (indicator == toBlock(u64(0)) || indicator == toBlock(u64(1)) || indicator == toBlock(u64(2)) || indicator == toBlock(u64(3)) ){
			return_value.push_back(decryptor.ecbDecBlock(recv_aes_message[0]));
			return_value.push_back(decryptor.ecbDecBlock(recv_aes_message[1]));
			return_value.push_back(decryptor.ecbDecBlock(recv_aes_message[2]));
			return_value.push_back(decryptor.ecbDecBlock(recv_aes_message[3]));
			return_value.push_back(decryptor.ecbDecBlock(recv_aes_message[4]));
			return_value.push_back(decryptor.ecbDecBlock(recv_aes_message[5]));
			return_value.push_back(decryptor.ecbDecBlock(recv_aes_message[6]));
		}
		else {
			return_value.push_back(decryptor.ecbDecBlock(recv_aes_message[7]));
			return_value.push_back(decryptor.ecbDecBlock(recv_aes_message[8]));
			return_value.push_back(decryptor.ecbDecBlock(recv_aes_message[9]));
			return_value.push_back(decryptor.ecbDecBlock(recv_aes_message[10]));
			return_value.push_back(decryptor.ecbDecBlock(recv_aes_message[11]));
			return_value.push_back(decryptor.ecbDecBlock(recv_aes_message[12]));
			return_value.push_back(decryptor.ecbDecBlock(recv_aes_message[13]));
		}
		return return_value;
	}
	//sender
	else if (myIdx == 1) {
		//input is ot message vector

		//1.okvs
		std::vector<block> recv_okvs_table(2 * round * setSize * okvsLengthScale);
		chls[myIdx][0].recv(recv_okvs_table.data(), recv_okvs_table.size());
		//print_block(recv_okvs_table);

		//first half of y, enough for equality check
		std::vector<block> y;
		y.push_back(input[0]);

		std::vector<block> decoded_value(1);
		GbfDecode(recv_okvs_table,y,decoded_value);

		std::vector<block> H_y(1);
		hashOKVS.ecbEncBlocks(y.data(),y.size(),H_y.data());

		block received_value = H_y[0] ^ decoded_value[0];
		//std::cout<<"received value: "<<received_value<<std::endl;

		//std::cout<<received_value<<std::endl;

		//2.gc

		//3.ot
		/*
		OT sender here for the AES key
		*/
		//======== simulation ==========
		std::vector<block> aes_key(1);
		if(i<setSize/2){
			aes_key = {input[2]};
		}else{
			aes_key = {input[3]};
		}
		chls[myIdx][0].send(aes_key.data(), aes_key.size());
		//==============================
		

		//sending AES messages
		std::vector<block> aes_message = {input.begin()+4,input.end()};
		chls[myIdx][0].send(aes_message.data(), aes_message.size());

	}

	std::vector<block> return_value(1);
	return return_value;

}

inline u8 rpir_circuit_psi_gc_sim(u64 myIdx, std::vector<block> input, std::vector<std::vector<Channel>> chls, u64 setSize,u64 round,PRNG& secret_value_generater,u64 i){
	/*
	receiver with input of its set in blocks 

	sender with input of a vector input of length 18:
		input[0:1] is the value of element y
		input[2] is 1st aes key0 which is the ot message 0
		input[3] is 2nd aes key1 which is the ot message 1
		input[4:10] is the aes encrypted message of v0
			[4:5] random value
			[6:10] Enc(0) 
		input[11:17] is the aes encrypted message of v1
			[11:12] F(k,y)
			[13:17] Enc(y)

	receiver output corresponding message of length 7:
		[4:10] if y \in X [11:17] otherwise.
	*/

	AES hashOKVS(toBlock(12138));

	//receiver
	if (myIdx == 0) {
		//1.okvs
		block secret_value = secret_value_generater.get<block>();
		//std::cout<<"secret value: "<<secret_value<<std::endl;
		
		std::vector<block> okvs_value(input.size());
		hashOKVS.ecbEncBlocks(input.data(),input.size(),okvs_value.data());
		
		for (u64 i = 0; i < okvs_value.size(); i++) {
			okvs_value[i] = okvs_value[i] ^ secret_value;
		}


		//std::cout<<"okvs value: "<<okvs_value[0]<<std::endl;
		
		std::vector<block> okvs_table(input.size()*okvsLengthScale);
		GbfEncode(input,okvs_value,okvs_table);

		chls[myIdx][1].send(okvs_table.data(), okvs_table.size());

		
		//2.gc
		//===========sim=============
		u8 result;
		if(i<setSize/2){
			result = 0;
		}else{
			result = 1;
		}
		//===========sim=============
		return result;
	}
	//sender
	else if (myIdx == 1) {
		//input is ot message vector

		//1.okvs
		std::vector<block> recv_okvs_table(2 * round * setSize * okvsLengthScale);
		chls[myIdx][0].recv(recv_okvs_table.data(), recv_okvs_table.size());
		//print_block(recv_okvs_table);

		//first half of y, enough for equality check
		std::vector<block> y;
		y.push_back(input[0]);

		std::vector<block> decoded_value(1);
		GbfDecode(recv_okvs_table,y,decoded_value);

		std::vector<block> H_y(1);
		hashOKVS.ecbEncBlocks(y.data(),y.size(),H_y.data());

		block received_value = H_y[0] ^ decoded_value[0];
		//std::cout<<"received value: "<<received_value<<std::endl;

		//std::cout<<received_value<<std::endl;

		//2.gc
		//===========sim=============
		u8 result = 0;
		//===========sim=============
		return result;

	}
	return 0;
}

inline void rpir_framework_test(){
	u64 setSize = 1 << 3;
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

	//set generation
	//first half of same elements and second half of different elements.s
	std::vector<std::vector<block>> inputSet(nParties,std::vector<block>(setSize));
	for (u64 i = 0; i < nParties; i++) {
		PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, 23987054));
		PRNG prngDiff(_mm_set_epi32(4253465, 3434565, 234423, i));
		for (u64 j = 0; j < setSize; j++) {
			if (j < setSize / 2) {
				inputSet[i][j] = prngSame.get<block>();
				//std::cout <<"input of " << myIdx << " : " << hex << inputSet[j] << std::endl;
			}
			else {
				inputSet[i][j] = prngDiff.get<block>();
				//std::cout << "input of " << myIdx << " : " << hex <<inputSet[j] << std::endl;
			}
		}
	}

	

	//thread 
	PRNG secret_value_generater(_mm_set_epi32(123, 12138, 321, 38324));

	std::vector<std::thread>  pThrds(nParties);
	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
	{
		pThrds[pIdx] = std::thread([&, pIdx]() {
			std::vector<block> result = rpir_ot_sim(pIdx, inputSet[pIdx],chls,setSize,1,secret_value_generater,1);
			if(pIdx == 0){
				std::cout<<"receiver "<<std::endl;
			}else if(pIdx == 1){
				std::cout<<"sender "<<std::endl;
			}
			
			//print_block(result);
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

inline void psu_channel_framework(std::vector<block> inputSet, u64 nParties, u64 myIdx, u64 setSize, std::vector<std::vector<Channel>>chls) {
	
	//protocol
	//1.key exchange
	
	

	for (u64 round = 1; round < nParties; round++) {
		//P_0
		if (myIdx == 0) {
			//2.OPRF P_0 & P_i
			/*

			computing x^a here

			*/
			
			chls[0][round].send(inputSet.data(),inputSet.size());

			std::vector<block> recv_oprf_value(inputSet.size());
			chls[0][round].recv(recv_oprf_value.data(), recv_oprf_value.size());
			
			
			//

			//computing x^b here

			//
			
			//
			//3.RPIR p_0 & p_i
			//rpir channel
			std::vector<std::vector<Channel>> chlsrpir(2, std::vector<Channel>(2));
			chlsrpir[0][1] = chls[0][round];

			std::vector<block> rpir_input;
			/*

			computing rpir input set here
			opprf tabel

			*/


			// for (u64 i = 0; i < setSize; i++) {
			// 	std::vector<block> rpir_output = rpir_channel_framework(0, rpir_input, chlsrpir, setSize);

			// }

			////4.OPRF key sharing



		}
		else if (myIdx == round) {
			//2.OPRF P_0 & P_i

			PRNG prngKey(_mm_set_epi32(4253465, 3434565, 234423, myIdx));
			std::vector<block> recv_oprf_p0(setSize);
			chls[myIdx][0].recv(recv_oprf_p0.data(),recv_oprf_p0.size());
			
			
			std::vector<block> oprf_key(1);
			oprf_key[0] = prngKey.get<block>();

			/*


			computing x^ab here



			*/

			chls[myIdx][0].send(recv_oprf_p0.data(), recv_oprf_p0.size());

			

			
			//3.RPIR p_0 & p_i

			//rpir channel
			std::vector<std::vector<Channel>> chlsrpir(2, std::vector<Channel>(2));
			chlsrpir[1][0] = chls[round][0];

			for (u64 i = 0; i < inputSet.size(); i++) {
				std::vector<block> rpir_input;
				/*

				computing rpir input set here

				*/
				//std::vector<block> rpir_output = rpir_channel_framework(1, rpir_input, chlsrpir, setSize);

		
			}



			//4.OPRF key sharing
			for (u64 j = round + 1; j < nParties; j++) {
				chls[myIdx][j].send(oprf_key.data(), oprf_key.size());
				std::cout << IoStream::lock;

				std::cout << "party " << myIdx << " break point 1" << std::endl;
				print_block(oprf_key);

				std::cout << IoStream::unlock;
			}

		}
		else if (myIdx > round && myIdx < nParties) {
			//2.OPRF P_0 & P_i

			//3.RPIR p_0 & p_i

			//4.OPRF key sharing
			//
			std::vector<block> recv_oprf_key(1);
			chls[myIdx][round].recv(recv_oprf_key.data(), recv_oprf_key.size());

			std::cout << IoStream::lock;

			std::cout << "party " << myIdx  << " break point 1" << std::endl;
			print_block(recv_oprf_key);

			std::cout << IoStream::unlock;
		}
	}

	//5.Decrypt & shuffle

	if (myIdx == 0) {
		std::vector<block> set_V_block(nParties * setSize);
		chls[myIdx][1].send(set_V_block.data(), set_V_block.size());
	}
	else if (myIdx > 0 && myIdx < nParties - 1) {
		std::vector<block> set_V_block(nParties * setSize);
		chls[myIdx][myIdx-1].recv(set_V_block.data(), set_V_block.size());
		chls[myIdx][myIdx+1].send(set_V_block.data(), set_V_block.size());
	}
	else if (myIdx == nParties - 1) {
		std::vector<block> set_V_block(nParties * setSize);
		chls[myIdx][myIdx-1].recv(set_V_block.data(), set_V_block.size());
		std::cout << IoStream::lock;
		std::cout << " party " << myIdx << std::endl;
		print_block(set_V_block);
		std::cout << IoStream::unlock;
	}


}

inline void psu_framework_ot_sim(std::vector<std::vector<u8>> inputSet_u8,std::vector<block> inputSet_block, u64 nParties, u64 myIdx, u64 setSize, std::vector<std::vector<Channel>>chls) {
	

	// std::cout<<IoStream::lock;
	// std::cout<<"P"<<myIdx<<" input"<<std::endl;
	// for(u64 i = 0; i<inputSet_u8.size(); i++){
	// 	print_u8vec(inputSet_u8[i]);
	// }
	// std::cout<<IoStream::unlock;

	//protocol
	//1.key exchange
	//Curve
	REllipticCurve curve;//(CURVE_25519)
	PRNG prng(_mm_set_epi32(19249,4923, 234435, 1231));
	PRNG prng_r(_mm_set_epi32(4253465, 3434565, 234435, 1231));
	//generater g
	const auto& g = curve.getGenerator();
	//sk_i
	std::vector<std::vector<u8>> s_keys;//32 Bytes
	//g^sk_i
	std::vector<std::vector<u8>> g_sks;//33 Bytes, y at index[][0]

	for (u64 i = 0; i < nParties; i++) {
		REccNumber sk(curve);

		sk.randomize(prng);

		std::vector<u8> b(sk.sizeBytes());
		
		sk.toBytes(b.data());

		s_keys.push_back(b);
		
		std::vector<u8> c(g.sizeBytes());
		REccPoint g_sk = g * sk;
		g_sk.toBytes(c.data());
		g_sks.push_back(c);

	}
	//pk
	REccNumber sk0;
	sk0.fromBytes(s_keys[0].data());
	REccPoint pk = g*sk0;//pk

	for(u64 i = 1;i<s_keys.size();i++){
		REccNumber ski;
		ski.fromBytes(s_keys[i].data());
		pk += g*ski;//pk
	}

	std::vector<u8> pk_vec (g.sizeBytes());
	pk.toBytes(pk_vec.data());


	//AES_KEY for OPRF
	PRNG prngAES(_mm_set_epi32(123, 3434565, 234435, 23987054));
    std::vector<osuCrypto::block> AES_keys;
	for(u64 i = 0; i<nParties;i++){
		AES_keys.push_back(prngAES.get<osuCrypto::block>());
	}
    
	PRNG prng_enc(_mm_set_epi32(4253465, 3434565, 234435, 1231));
	//All the parties compute the X' = Enc(pk,X)
	//encrypt_set: setSize * 2 * 33 u8 vector
	std::vector<std::vector<std::vector<u8>>> encrypt_set;
	for(u64 i = 0; i<inputSet_u8.size(); i++){
		//std::cout<<inputSet_u8[i]<<std::endl;
		//print_u8vec(pk_vec);
		std::vector<std::vector<u8>> ciphertext = encryption(inputSet_u8[i],pk_vec,prng_enc);
		encrypt_set.push_back(ciphertext);
	}
	//p0 init V
	std::vector<std::vector<std::vector<u8>>> set_V;
	if(myIdx == 0){
		set_V = encrypt_set;
	}
	

	////All the parties compute the Enc(pk,0)
	//setSize * 2 * 33 u8 vector
	std::vector<std::vector<std::vector<u8>>> encrypt_zero_set;
	for(u64 i = 0; i<inputSet_u8.size(); i++){
		//std::cout<<inputSet_u8[i]<<std::endl;
		//print_u8vec(pk_vec);
		std::vector<u8> zero_u8(32,0);
		std::vector<std::vector<u8>> ciphertext = encryption(zero_u8,pk_vec,prng_enc);
		encrypt_zero_set.push_back(ciphertext);
	}


	Timer timer;
	timer.reset();
	auto start = timer.setTimePoint("start");


	for (u64 round = 1; round < nParties; round++) {
		//P_0
		if (myIdx == 0) {
			//2.=============================== OPRF P_0 & P_i ==================================
			//update channel for oprf
			std::vector<std::vector<Channel>> chlsoprf(2, std::vector<Channel>(2));
			chlsoprf[0][1] = chls[0][round];

			std::vector<osuCrypto::block> oprf_value(inputSet_block.size());

			oprf_value = aes_oprf(0,inputSet_block, 2 * setSize, chlsoprf, ZeroBlock);

			// if(round == 1){
			// 	std::cout << IoStream::lock;
			// 	std::cout << "party " << myIdx<< std::endl;
			// 	print_block(oprf_value);
			// 	std::cout << IoStream::unlock;
			// }
			


			//3.=============================== RPIR p_0 & p_i ==================================
			//rpir channel
			std::vector<std::vector<Channel>> chlsrpir(2, std::vector<Channel>(2));
			chlsrpir[0][1] = chls[0][round];
			
			inputSet_block = oprf_value;
			std::vector<block> rpir_input = inputSet_block;
			//std::vector<block> rpir_input = oprf_value;
			/*

			computing rpir input set here
			opprf tabel

			*/
			PRNG secret_value_generater(_mm_set_epi32(38324, 12114565, 234435, 1231+round));

			for (u64 i = 0; i < setSize; i++) {
				std::vector<block> rpir_output = rpir_ot_sim(0, rpir_input, chlsrpir, setSize,round,secret_value_generater,i);
				
				//received message of length 7
				//update X and V
				//[0:1]prf value
				inputSet_block.push_back(rpir_output[0]);
				inputSet_block.push_back(rpir_output[1]);
				//[2:6]ciphertext of element 
				std::vector<block> new_ctx_block = {rpir_output.begin()+2,rpir_output.end()};
				std::vector<std::vector<u8>> new_ctx = blocks_to_ciphertexts(new_ctx_block);
				//update set_V
				set_V.push_back(new_ctx);
				
				// std::cout << IoStream::lock;
				// std::cout << "party " << myIdx<< std::endl;
				// print_block(new_ctx_block);
				// // print_u8vec(new_ctx[0]);
				// std::cout<<"size of V: "<<set_V.size()<<std::endl;
				// std::cout<<"size of X_block: "<<inputSet_block.size()<<std::endl;
				// //print_block(rpir_output);
				// std::cout << IoStream::unlock;
			}


				

		}
		else if (myIdx == round) {
			//2.=============================== OPRF P_0 & P_i ==================================
			//update channel for oprf
			std::vector<std::vector<Channel>> chlsoprf(2, std::vector<Channel>(2));
			chlsoprf[1][0] = chls[round][0];
			
			std::vector<osuCrypto::block> oprf_value;
			std::vector<osuCrypto::block> oprf_key;
			oprf_key.push_back(AES_keys[myIdx]);
			oprf_value = aes_oprf(1,inputSet_block, 2 * setSize,chlsoprf,oprf_key[0]);

			// if(round == 1){
			// 	std::cout << IoStream::lock;
			// 	std::cout << "party " << myIdx<< std::endl;
			// 	print_block(oprf_value);
			// 	std::cout << IoStream::unlock;
			// }
			

			//3.=============================== RPIR p_0 & p_i ==================================

			//rpir channel
			std::vector<std::vector<Channel>> chlsrpir(2, std::vector<Channel>(2));
			chlsrpir[1][0] = chls[round][0];
			
			
			//message prepare

			PRNG prng_ot_aes(_mm_set_epi32(123, 3434565, 123321, 23987+myIdx));

			for (u64 i = 0; i < setSize; i++) {
				//compute rpir input 
				std::vector<block> rpir_input;
				//y
				// rpir_input.push_back(inputSet_block[2*i]);
				// rpir_input.push_back(inputSet_block[2*i+1]);
				rpir_input.push_back(oprf_value[2*i]);
				rpir_input.push_back(oprf_value[2*i+1]);
				//aes key 0;
				rpir_input.push_back(prng_ot_aes.get<block>());
				//aes key 1;
				rpir_input.push_back(prng_ot_aes.get<block>());
				
				//v0
				//AES
				AES aes_0(rpir_input[2]);
				std::vector<block> v0;
					//$
				v0.push_back(prng_ot_aes.get<block>());

				v0.push_back(prng_ot_aes.get<block>());
					//enc(0)
				std::vector<block> enc_zero = ciphertexts_to_blocks(encrypt_zero_set[i]);
				v0.insert(v0.end(),enc_zero.begin(),enc_zero.end());
				std::vector<block> enc_v0(v0.size());
				aes_0.ecbEncBlocks(v0.data(), v0.size(), enc_v0.data());
				rpir_input.insert(rpir_input.end(), enc_v0.begin(), enc_v0.end());

				//v1
				AES aes_1(rpir_input[3]);
				std::vector<block> v1;
					//F(k,x)
				v1.push_back(oprf_value[2*i]);
				v1.push_back(oprf_value[2*i+1]);
					//Enc(x)
				std::vector<block> enc_x = ciphertexts_to_blocks(encrypt_set[i]);
				v1.insert(v1.end(),enc_x.begin(),enc_x.end());
				std::vector<block> enc_v1(v1.size());
				aes_1.ecbEncBlocks(v1.data(), v1.size(), enc_v1.data());
				rpir_input.insert(rpir_input.end(), enc_v1.begin(), enc_v1.end());

				// if(i == 0 && round == 1){
				// 	print_block(rpir_input);
				// 	std::cout<<"size of rpir input: "<<rpir_input.size()<<std::endl;
				// }


				//rpir sub-protocol
				PRNG secret_value_generater(_mm_set_epi32(38324, 12114565, 234435, 1231+round));

				std::vector<block> rpir_output = rpir_ot_sim(1, rpir_input, chlsrpir, setSize,round,secret_value_generater,i);
				
		
			}



			//4.OPRF key sharing
			for (u64 j = round + 1; j < nParties; j++) {
				
				chls[myIdx][j].send(oprf_key.data(), oprf_key.size());
				// std::cout << IoStream::lock;
				// std::cout << "party " << myIdx << " round "<< round << std::endl;
				// print_block(oprf_key);
				// std::cout << IoStream::unlock;
			}

		}
		else if (myIdx > round && myIdx < nParties) {
			//2.OPRF P_0 & P_i

			//3.RPIR p_0 & p_i

			//4.OPRF key sharing
			//
			std::vector<block> recv_oprf_key(1);
			chls[myIdx][round].recv(recv_oprf_key.data(), recv_oprf_key.size());

			AES aes_oprf(recv_oprf_key[0]);

			std::vector<osuCrypto::block> oprf_value(inputSet_block.size());

			aes_oprf.ecbEncBlocks(inputSet_block.data(),inputSet_block.size(),oprf_value.data());

			inputSet_block = oprf_value;
			
			// if(round == 1){
			// 	std::cout << IoStream::lock;
			// 	std::cout << "party " << myIdx<< std::endl;
			// 	print_block(oprf_value);
			// 	std::cout << IoStream::unlock;
			// }
		
		}
	}
	
	
	//std::cout<<"First phase finished."<<std::endl;
	
	
	//validation for correctness
	// if (myIdx == 0) {
	// 	for(u64 i = 0;i<set_V.size();i++){

	// 	// std::cout<<IoStream::lock;
	// 	// std::cout<<"P"<<myIdx<<" input"<<std::endl;
	// 	// 	print_u8vec(set_V[i][0]);
	// 	// 	print_u8vec(set_V[i][1]);
	// 	// std::cout<<IoStream::unlock;

	// 		REccPoint c1;
	// 		REccPoint c2;
	// 		// REccPoint g_sk;
	// 		// REccPoint g_sk0;
	// 		// REccPoint g_sk1;
	// 		//REccNumber sk;
	// 		REccNumber sk0;
	// 		REccNumber sk1;
	// 		REccNumber sk2;
	// 		REccNumber sk3;

	// 		c1.fromBytes(set_V[i][0].data());
	// 		c2.fromBytes(set_V[i][1].data());

	// 		// g_sk0.fromBytes(g_sks[0].data());
	// 		// g_sk1.fromBytes(g_sks[1].data());
	// 		// g_sk = g_sk0 + g_sk1;
	// 		sk0.fromBytes(s_keys[0].data());
	// 		sk1.fromBytes(s_keys[1].data());
	// 		sk2.fromBytes(s_keys[2].data());
	// 		sk3.fromBytes(s_keys[3].data());
	// 		//sk = sk0 + sk1;
	// 		// for(u64 j = 1;j<s_keys.size();j++){
	// 		// 	REccNumber sk1;
	// 		// 	std::cout<<"j = "<<j<<std::endl;
	// 		// 	sk1.fromBytes(s_keys[j].data());
	// 		// 	sk = sk + sk1;
	// 		// }
	// 		// std::cout<<"4"<<std::endl;

	// 		REccPoint dec_m = c2 - (c1 * sk0) - (c1 * sk1) - (c1 * sk2) - (c1 * sk3);
	
	// 		std::vector<u8> dec_m_vec(33);
	// 		//std::cout<<"size: "<<dec_m_vec.size()<<std::endl;
	// 		dec_m.toBytes(dec_m_vec.data());

	// 		dec_m_vec.erase(dec_m_vec.begin());
	// 		print_u8vec(dec_m_vec);
	// 	}
	// }

	//5.Decrypt & shuffle
	
	if (myIdx == 0) {
		std::vector<block> dec_set_V_block;

		for(u64 i = 0; i< set_V.size(); i++){
			std::vector<std::vector<u8>> ctx = partial_decryption(set_V[i],s_keys[myIdx]);
			std::vector<block> ctx_block = ciphertexts_to_blocks(ctx);
			dec_set_V_block.insert(dec_set_V_block.end(),ctx_block.begin(),ctx_block.end());
		}
		chls[myIdx][1].send(dec_set_V_block.data(), dec_set_V_block.size());

	}
	else if (myIdx > 0 && myIdx < nParties - 1) {
		std::vector<block> recv_set_V_block(nParties * setSize * 5);
		chls[myIdx][myIdx-1].recv(recv_set_V_block.data(), recv_set_V_block.size());
		//print_block(recv_set_V_block);
		std::vector<block> dec_set_V_block;
		for(u64 i = 0; i< nParties*setSize; i++){
			std::vector<block> ctx_block1 = {recv_set_V_block.begin()+5*i,recv_set_V_block.begin()+5*i+5};
			std::vector<std::vector<u8>> ctx_u8 = blocks_to_ciphertexts(ctx_block1);
			std::vector<std::vector<u8>> ctx = partial_decryption(ctx_u8,s_keys[myIdx]);
			std::vector<block> ctx_block = ciphertexts_to_blocks(ctx);
			dec_set_V_block.insert(dec_set_V_block.end(),ctx_block.begin(),ctx_block.end());
		}

		chls[myIdx][myIdx+1].send(dec_set_V_block.data(), dec_set_V_block.size());

	}
	else if (myIdx == nParties - 1) {
		std::vector<block> recv_set_V_block(nParties * setSize * 5);
		chls[myIdx][myIdx-1].recv(recv_set_V_block.data(), recv_set_V_block.size());

		//std::vector<block> dec_set_V_block;
		for(u64 i = 0; i< nParties*setSize; i++){
			std::vector<block> ctx_block1 = {recv_set_V_block.begin()+5*i,recv_set_V_block.begin()+5*i+5};
			std::cout<<"element "<<i<<std::endl;
			//print_block(ctx_block1);
			std::vector<std::vector<u8>> ctx_u8 = blocks_to_ciphertexts(ctx_block1);
			std::vector<u8> element = decryption(ctx_u8,s_keys[myIdx]);
			//print_u8vec(element);
		}

		
		
		// std::cout << IoStream::lock;
		// std::cout << " party " << myIdx << std::endl;
		// print_block(set_V_block);
		// std::cout << IoStream::unlock;
	}

	auto end = timer.setTimePoint("end");

	std::cout << IoStream::lock;
	std::cout << " party " << myIdx <<"\t"<<timer<< std::endl;
	std::cout << IoStream::unlock;


}

inline void psu_framework(std::vector<std::vector<u8>> inputSet_u8,std::vector<block> inputSet_block, u64 nParties, u64 myIdx, u64 setSize, std::vector<std::vector<Channel>>chls) {
	

	// std::cout<<IoStream::lock;
	// std::cout<<"P"<<myIdx<<" input"<<std::endl;
	// for(u64 i = 0; i<inputSet_u8.size(); i++){
	// 	print_u8vec(inputSet_u8[i]);
	// }
	// std::cout<<IoStream::unlock;

	//protocol
	//1.key exchange
	//Curve
	REllipticCurve curve;//(CURVE_25519)
	PRNG prng(_mm_set_epi32(19249,4923, 234435, 1231));
	PRNG prng_r(_mm_set_epi32(4253465, 3434565, 234435, 1231));
	//generater g
	const auto& g = curve.getGenerator();
	//sk_i
	std::vector<std::vector<u8>> s_keys;//32 Bytes
	//g^sk_i
	std::vector<std::vector<u8>> g_sks;//33 Bytes, y at index[][0]

	for (u64 i = 0; i < nParties; i++) {
		REccNumber sk(curve);

		sk.randomize(prng);

		std::vector<u8> b(sk.sizeBytes());
		
		sk.toBytes(b.data());

		s_keys.push_back(b);
		
		std::vector<u8> c(g.sizeBytes());
		REccPoint g_sk = g * sk;
		g_sk.toBytes(c.data());
		g_sks.push_back(c);

	}
	//pk
	REccNumber sk0;
	sk0.fromBytes(s_keys[0].data());
	REccPoint pk = g*sk0;//pk

	for(u64 i = 1;i<s_keys.size();i++){
		REccNumber ski;
		ski.fromBytes(s_keys[i].data());
		pk += g*ski;//pk
	}

	std::vector<u8> pk_vec (g.sizeBytes());
	pk.toBytes(pk_vec.data());


	//AES_KEY for OPRF
	PRNG prngAES(_mm_set_epi32(123, 3434565, 234435, 23987054));
    std::vector<osuCrypto::block> AES_keys;
	for(u64 i = 0; i<nParties;i++){
		AES_keys.push_back(prngAES.get<osuCrypto::block>());
	}
    
	PRNG prng_enc(_mm_set_epi32(4253465, 3434565, 234435, 1231));
	//All the parties compute the X' = Enc(pk,X)
	//encrypt_set: setSize * 2 * 33 u8 vector
	std::vector<std::vector<std::vector<u8>>> encrypt_set;
	for(u64 i = 0; i<inputSet_u8.size(); i++){
		//std::cout<<inputSet_u8[i]<<std::endl;
		//print_u8vec(pk_vec);
		std::vector<std::vector<u8>> ciphertext = encryption(inputSet_u8[i],pk_vec,prng_enc);
		encrypt_set.push_back(ciphertext);
	}
	//p0 init V
	std::vector<std::vector<std::vector<u8>>> set_V;
	if(myIdx == 0){
		set_V = encrypt_set;
	}
	

	////All the parties compute the Enc(pk,0)
	//setSize * 2 * 33 u8 vector
	std::vector<std::vector<std::vector<u8>>> encrypt_zero_set;
	for(u64 i = 0; i<inputSet_u8.size(); i++){
		//std::cout<<inputSet_u8[i]<<std::endl;
		//print_u8vec(pk_vec);
		std::vector<u8> zero_u8(32,0);
		std::vector<std::vector<u8>> ciphertext = encryption(zero_u8,pk_vec,prng_enc);
		encrypt_zero_set.push_back(ciphertext);
	}


	Timer timer;
	timer.reset();
	auto start = timer.setTimePoint("start");



	for (u64 round = 1; round < nParties; round++) {
		//P_0
		if (myIdx == 0) {
			//2.=============================== OPRF P_0 & P_i ==================================
			//update channel for oprf
			std::vector<std::vector<Channel>> chlsoprf(2, std::vector<Channel>(2));
			chlsoprf[0][1] = chls[0][round];

			std::vector<osuCrypto::block> oprf_value(inputSet_block.size());

			oprf_value = aes_oprf(0,inputSet_block, 2 * setSize, chlsoprf, ZeroBlock);

			// if(round == 1){
			// 	std::cout << IoStream::lock;
			// 	std::cout << "party " << myIdx<< std::endl;
			// 	print_block(oprf_value);
			// 	std::cout << IoStream::unlock;
			// }
			


			//3.=============================== RPIR p_0 & p_i ==================================
			//rpir channel
			std::vector<std::vector<Channel>> chlsrpir(2, std::vector<Channel>(2));
			chlsrpir[0][1] = chls[0][round];
			
			inputSet_block = oprf_value;
			std::vector<block> rpir_input = inputSet_block;
			//std::vector<block> rpir_input = oprf_value;
			/*

			computing rpir input set here
			opprf tabel

			*/
			PRNG secret_value_generater(_mm_set_epi32(38324, 12114565, 234435, 1231+round));

			BitVector choices(setSize);

			//3.1 circuit_psi
			for (u64 i = 0; i < setSize; i++) {
				u8 b_r = rpir_circuit_psi_gc_sim(0, rpir_input, chlsrpir, setSize,round,secret_value_generater,i);
				choices[i] = b_r;
			}
			//std::cout<<"b_r: "<<choices<<std::endl;
			//3.2 ot extension
			PRNG prng(sysRandomSeed());
			IknpOtExtReceiver recver;
			std::vector<osuCrypto::block> recv_u_blocks(setSize);
			chls[0][round].recv(recv_u_blocks.data(), recv_u_blocks.size());

				// Receive the messages
			std::vector<osuCrypto::block> messages(setSize);
			recver.receiveChosen(choices, messages, prng, chls[0][round]);

			std::vector<osuCrypto::block> aes_keys(setSize);
			for(u64 i = 0; i<setSize;i++){
				aes_keys[i] = recv_u_blocks[i] ^ messages[i];
			}

			//std::cout<<"recv_key: "<<aes_keys[0]<<std::endl;


			//3.3 message parse & decrypt
			std::vector<osuCrypto::block> recv_ot_messages(setSize*14);
			chls[0][round].recv(recv_ot_messages.data(), recv_ot_messages.size());

			for (u64 i = 0; i < setSize; i++) {
				std::vector<osuCrypto::block> recv_aes_message = {recv_ot_messages.begin()+i*14,recv_ot_messages.begin()+i*14+14};

				//decrypt
				//message decode 
				AESDec decryptor(aes_keys[i]);
				block indicator = decryptor.ecbDecBlock(recv_aes_message[2]);
				std::vector<block> rpir_message;
				if (indicator == toBlock(u64(0)) || indicator == toBlock(u64(1)) || indicator == toBlock(u64(2)) || indicator == toBlock(u64(3)) ){
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[0]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[1]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[2]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[3]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[4]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[5]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[6]));
				}
				else {
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[7]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[8]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[9]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[10]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[11]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[12]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[13]));
				}

				//received message of length 7
				//update X and V
				//[0:1]prf value
				inputSet_block.push_back(rpir_message[0]);
				inputSet_block.push_back(rpir_message[1]);
				//[2:6]ciphertext of element 
				std::vector<block> new_ctx_block = {rpir_message.begin()+2,rpir_message.end()};
				std::vector<std::vector<u8>> new_ctx = blocks_to_ciphertexts(new_ctx_block);
				//update set_V
				set_V.push_back(new_ctx);
				
				// std::cout << IoStream::lock;
				// std::cout << "party " << myIdx<< std::endl;
				// print_block(new_ctx_block);
				// // print_u8vec(new_ctx[0]);
				// std::cout<<"size of V: "<<set_V.size()<<std::endl;
				// std::cout<<"size of X_block: "<<inputSet_block.size()<<std::endl;
				// //print_block(rpir_output);
				// std::cout << IoStream::unlock;
			}

				

		}
		else if (myIdx == round) {
			//2.=============================== OPRF P_0 & P_i ==================================
			//update channel for oprf
			std::vector<std::vector<Channel>> chlsoprf(2, std::vector<Channel>(2));
			chlsoprf[1][0] = chls[round][0];
			
			std::vector<osuCrypto::block> oprf_value;
			std::vector<osuCrypto::block> oprf_key;
			oprf_key.push_back(AES_keys[myIdx]);
			oprf_value = aes_oprf(1,inputSet_block, 2 * setSize,chlsoprf,oprf_key[0]);

			// if(round == 1){
			// 	std::cout << IoStream::lock;
			// 	std::cout << "party " << myIdx<< std::endl;
			// 	print_block(oprf_value);
			// 	std::cout << IoStream::unlock;
			// }
			

			//3.=============================== RPIR p_0 & p_i ==================================

			//rpir channel
			std::vector<std::vector<Channel>> chlsrpir(2, std::vector<Channel>(2));
			chlsrpir[1][0] = chls[round][0];
			
			
			//message prepare

			PRNG prng_ot_aes(_mm_set_epi32(123, 3434565, 123321, 23987+myIdx));


			BitVector b_s_vec(setSize);
			
			//3.1 rpir circuit psi
			for (u64 i = 0; i < setSize; i++) {
				//compute rpir input 
				std::vector<block> rpir_input;
				//y
				// rpir_input.push_back(inputSet_block[2*i]);
				// rpir_input.push_back(inputSet_block[2*i+1]);
				rpir_input.push_back(oprf_value[2*i]);
				rpir_input.push_back(oprf_value[2*i+1]);


				//rpir sub-protocol
				PRNG secret_value_generater(_mm_set_epi32(38324, 12114565, 234435, 1231+round));

				u8 b_s = rpir_circuit_psi_gc_sim(1, rpir_input, chlsrpir, setSize,round,secret_value_generater,i);
				
				b_s_vec[i] = b_s;

			}
			//std::cout<<"b_s: "<<b_s_vec<<std::endl;
			//3.2 ot sender
			PRNG prng(sysRandomSeed());
			IknpOtExtSender sender;
			std::vector<std::array<osuCrypto::block, 2>> sendMessages(setSize);
				// Choose which messages should be sent.
			std::vector<std::array<osuCrypto::block, 2>> aes_keys(setSize);
			std::vector<osuCrypto::block> u_blocks;
			for(u64 i = 0; i<setSize;i++){
				aes_keys[i] = { prng_ot_aes.get<block>(), prng_ot_aes.get<block>() };
				osuCrypto::block r = prng.get<block>();
				osuCrypto::block u;
				if(b_s_vec[i] == 1){
					u = r ^ aes_keys[i][0] ^ aes_keys[i][1];
				}else{
					u = r;
				}
				u_blocks.push_back(u);

				sendMessages[i][0] = r ^ aes_keys[i][0];
				sendMessages[i][1] = r ^ aes_keys[i][1];
			}
			chls[round][0].send(u_blocks.data(), u_blocks.size());

			// std::cout<<"send_key: "<<aes_keys[0][0]<<std::endl;
			// std::cout<<"send_key: "<<aes_keys[0][1]<<std::endl;
			

			// Send the messages.
			sender.sendChosen(sendMessages, prng, chls[round][0]);

			//3.3 message construction & encryption
			std::vector<block> ot_messages;
			for(u64 i = 0; i<setSize;i++){
				//v0
				//AES
				AES aes_0(aes_keys[i][0]);
				std::vector<block> v0;
					//$
				v0.push_back(prng_ot_aes.get<block>());
				v0.push_back(prng_ot_aes.get<block>());
					//enc(0)
				std::vector<block> enc_zero = ciphertexts_to_blocks(encrypt_zero_set[i]);
				v0.insert(v0.end(),enc_zero.begin(),enc_zero.end());
				std::vector<block> enc_v0(v0.size());
				aes_0.ecbEncBlocks(v0.data(), v0.size(), enc_v0.data());
				ot_messages.insert(ot_messages.end(), enc_v0.begin(), enc_v0.end());

				//v1
				AES aes_1(aes_keys[i][1]);
				std::vector<block> v1;
					//F(k,x)
				v1.push_back(oprf_value[2*i]);
				v1.push_back(oprf_value[2*i+1]);
					//Enc(x)
				std::vector<block> enc_x = ciphertexts_to_blocks(encrypt_set[i]);
				v1.insert(v1.end(),enc_x.begin(),enc_x.end());
				std::vector<block> enc_v1(v1.size());
				aes_1.ecbEncBlocks(v1.data(), v1.size(), enc_v1.data());
				ot_messages.insert(ot_messages.end(), enc_v1.begin(), enc_v1.end());

				// if(i == 0 && round == 1){
				// 	print_block(rpir_input);
				// 	std::cout<<"size of rpir input: "<<rpir_input.size()<<std::endl;
				// }
			}
			//std::cout<<ot_messages.size()<<std::endl;
			chls[round][0].send(ot_messages.data(), ot_messages.size());

			//4.OPRF key sharing
			for (u64 j = round + 1; j < nParties; j++) {
				
				chls[myIdx][j].send(oprf_key.data(), oprf_key.size());
				// std::cout << IoStream::lock;
				// std::cout << "party " << myIdx << " round "<< round << std::endl;
				// print_block(oprf_key);
				// std::cout << IoStream::unlock;
			}

		}
		else if (myIdx > round && myIdx < nParties) {
			//2.OPRF P_0 & P_i

			//3.RPIR p_0 & p_i

			//4.OPRF key sharing
			//
			std::vector<block> recv_oprf_key(1);
			chls[myIdx][round].recv(recv_oprf_key.data(), recv_oprf_key.size());

			AES aes_oprf(recv_oprf_key[0]);

			std::vector<osuCrypto::block> oprf_value(inputSet_block.size());

			aes_oprf.ecbEncBlocks(inputSet_block.data(),inputSet_block.size(),oprf_value.data());

			inputSet_block = oprf_value;
			
			// if(round == 1){
			// 	std::cout << IoStream::lock;
			// 	std::cout << "party " << myIdx<< std::endl;
			// 	print_block(oprf_value);
			// 	std::cout << IoStream::unlock;
			// }
		
		}
	}
	
	
	std::cout<<"First phase finished."<<std::endl;
	
	
	

	//5.Decrypt & shuffle
	
	if (myIdx == 0) {
		std::vector<block> dec_set_V_block;

		for(u64 i = 0; i< set_V.size(); i++){
			std::vector<std::vector<u8>> ctx = partial_decryption(set_V[i],s_keys[myIdx]);
			std::vector<block> ctx_block = ciphertexts_to_blocks(ctx);
			dec_set_V_block.insert(dec_set_V_block.end(),ctx_block.begin(),ctx_block.end());
		}
		chls[myIdx][1].send(dec_set_V_block.data(), dec_set_V_block.size());

	}
	else if (myIdx > 0 && myIdx < nParties - 1) {
		std::vector<block> recv_set_V_block(nParties * setSize * 5);
		chls[myIdx][myIdx-1].recv(recv_set_V_block.data(), recv_set_V_block.size());
		//print_block(recv_set_V_block);
		std::vector<block> dec_set_V_block;
		for(u64 i = 0; i< nParties*setSize; i++){
			std::vector<block> ctx_block1 = {recv_set_V_block.begin()+5*i,recv_set_V_block.begin()+5*i+5};
			std::vector<std::vector<u8>> ctx_u8 = blocks_to_ciphertexts(ctx_block1);
			std::vector<std::vector<u8>> ctx = partial_decryption(ctx_u8,s_keys[myIdx]);
			std::vector<block> ctx_block = ciphertexts_to_blocks(ctx);
			dec_set_V_block.insert(dec_set_V_block.end(),ctx_block.begin(),ctx_block.end());
		}

		chls[myIdx][myIdx+1].send(dec_set_V_block.data(), dec_set_V_block.size());

	}
	else if (myIdx == nParties - 1) {
		std::vector<block> recv_set_V_block(nParties * setSize * 5);
		chls[myIdx][myIdx-1].recv(recv_set_V_block.data(), recv_set_V_block.size());

		//std::vector<block> dec_set_V_block;
		for(u64 i = 0; i< nParties*setSize; i++){
			std::vector<block> ctx_block1 = {recv_set_V_block.begin()+5*i,recv_set_V_block.begin()+5*i+5};
			//std::cout<<"element "<<i<<std::endl;
			//print_block(ctx_block1);
			std::vector<std::vector<u8>> ctx_u8 = blocks_to_ciphertexts(ctx_block1);
			std::vector<u8> element = decryption(ctx_u8,s_keys[myIdx]);
			//print_u8vec(element);
		}

		
		
		// std::cout << IoStream::lock;
		// std::cout << " party " << myIdx << std::endl;
		// print_block(set_V_block);
		// std::cout << IoStream::unlock;
	}

	auto end = timer.setTimePoint("end");

	std::cout << IoStream::lock;
	std::cout << " party " << myIdx <<"\t"<<timer<< std::endl;
	std::cout << IoStream::unlock;



}

inline void mpsu_test() {

	u64 setSize = 1 << 16;
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

	//set generation
	//first half of same elements and second half of different elements.s
	
	
	//ECC Points
	//nParties * setSize * 32 u8 vector
	std::vector<std::vector<std::vector<u8>>> inputSet_u8(nParties);
	//nParties * 2setSize  vector
	std::vector<std::vector<block>> inputSet_block(nParties);

	for (u64 i = 0; i < nParties; i++) {
		PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, 23987054));
		PRNG prngDiff(_mm_set_epi32(4253465, 3434565, 234423, i));
		//std::cout<<"input from party "<<i<<std::endl;
		REllipticCurve curve;//(CURVE_25519)
		//generater g
		const auto& g = curve.getGenerator();
		for(u64 j = 0; j< setSize; j++){
			
			REccNumber num(curve);

			if (j < setSize / 2) {
				num.randomize(prngSame);
			}
			else {
				num.randomize(prngDiff);
			}
			REccPoint p = g * num;
			std::vector<u8> p_vec(g.sizeBytes());
			p.toBytes(p_vec.data());
			p_vec.erase(p_vec.begin());
			//print_u8vec(p_vec);
			inputSet_u8[i].push_back(p_vec);
			std::vector<block> p_block= u8vec_to_blocks(p_vec);
			inputSet_block[i].push_back(p_block[0]);
			inputSet_block[i].push_back(p_block[1]);

			//it is safe to erase the first bit (give 2 later still generate a valid point) 
			// p_vec.erase(p_vec.begin());
			// p_vec.insert(p_vec.begin(), 2);
			// p.fromBytes(p_vec.data());
		}
	}

	//blocks
	//std::vector<std::vector<block>> inputSet(nParties,std::vector<block>(setSize));
	// for (u64 i = 0; i < nParties; i++) {
	// 	PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, 23987054));
	// 	PRNG prngDiff(_mm_set_epi32(4253465, 3434565, 234423, i));
	// 	for (u64 j = 0; j < setSize; j++) {
	// 		if (j < setSize / 2) {
	// 			inputSet[i][j] = prngSame.get<block>();
	// 			//std::cout <<"input of " << myIdx << " : " << hex << inputSet[j] << std::endl;
	// 		}
	// 		else {
	// 			inputSet[i][j] = prngDiff.get<block>();
	// 			//std::cout << "input of " << myIdx << " : " << hex <<inputSet[j] << std::endl;
	// 		}
	// 	}
	// }




	std::cout<<"number of parties: "<<nParties<<std::endl;
	std::cout<<"set size: "<<inputSet_u8[0].size()<<std::endl;
	std::cout<<"number of blocks: "<<inputSet_block[0].size()<<std::endl;


	//thread 
	std::vector<std::thread>  pThrds(nParties);
	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
	{
		pThrds[pIdx] = std::thread([&, pIdx]() {
			psu_framework(inputSet_u8[pIdx],inputSet_block[pIdx],nParties, pIdx, setSize, chls);
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





