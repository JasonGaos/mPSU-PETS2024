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
#include "eccConvert.h"

using namespace osuCrypto;


inline void print_block(std::vector<block> a) {

	for (u64 i = 0; i < a.size(); i++) {
		std::cout << a[i] << std::endl;
	}


}

inline std::vector<block> rpir_channel_framework(u64 myIdx, std::vector<block> input, std::vector<std::vector<Channel>> chls, u64 setSize) {
	/*
	receiver with input of its set
	sender with input of a vector input of length 15:
		input[0] is the value of element y
		input[1] is 1st aes key0 which is the ot message 0
		input[2] is 2nd aes key1 which is the ot message 1
		input[3:8] is the aes encrypted message of v0
			[3] random value
			[4:8] Enc(0) 
		input[9:14] is the aes encrypted message of v1
			[9] F(k,y)
			[10:14] Enc(y)

	receiver output corresponding message of length 6:
		[3:8] if y \in X [9:14] otherwise.
	*/

	AES hashOKVS(toBlock(12138));

	//receiver
	if (myIdx == 0) {
		//1.okvs
		
		PRNG secret_value_generater(_mm_set_epi32(123, 12138, 321, 38324));

		block secret_value = secret_value_generater.get<block>();
		std::cout<<"secret value: "<<secret_value<<std::endl;
		
		std::vector<block> okvs_value(input.size());
		hashOKVS.ecbEncBlocks(input.data(),input.size(),okvs_value.data());
		
		for (u64 i = 0; i < okvs_value.size(); i++) {
			okvs_value[i] = okvs_value[i] ^ secret_value;
		}


		//std::cout<<"okvs value: "<<okvs_value[0]<<std::endl;
		
		std::vector<block> okvs_table(input.size()*okvsLengthScale);
		GbfEncode(input,okvs_value,okvs_table);

		chls[myIdx][1].send(okvs_table.data(), okvs_table.size());

		
		//2.secret share

		//3.ot
		/*
		OT reciever here for the AES key
		*/
		std::vector<block> recv_aes_message(12);
		chls[myIdx][1].recv(recv_aes_message.data(), recv_aes_message.size());

		/*

		computing the recv_aes_messages

		*/
		return recv_aes_message;
	}
	//sender
	else if (myIdx == 1) {
		//input is ot message vector

		//1.okvs
		std::vector<block> recv_okvs_table(setSize*okvsLengthScale);
		chls[myIdx][0].recv(recv_okvs_table.data(), recv_okvs_table.size());
		//print_block(recv_okvs_table);

		std::vector<block> y;
		y.push_back(input[0]);

		std::vector<block> decoded_value(1);
		GbfDecode(recv_okvs_table,y,decoded_value);

		//std::cout<<decoded_value[0]<<std::endl;
		std::vector<block> H_y(1,toBlock(u64(0)));
		hashOKVS.ecbEncBlocks(y.data(),y.size(),H_y.data());

		block received_value = H_y[0] ^ decoded_value[0];
		std::cout<<"received value: "<<received_value<<std::endl;

		//std::cout<<received_value<<std::endl;

		//2.gc

		//3.ot
		/*
		OT sender here for the AES key
		*/

		//sending AES messages
		std::vector<block> aes_message(12);
		for (u64 i = 0; i < aes_message.size(); i++) {
			aes_message[i] = toBlock(i);
		}
		chls[myIdx][0].send(aes_message.data(), aes_message.size());

	}

	std::vector<block> return_value(1);
	return return_value;


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
	std::vector<std::thread>  pThrds(nParties);
	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
	{
		pThrds[pIdx] = std::thread([&, pIdx]() {
			std::vector<block> result = rpir_channel_framework(pIdx, inputSet[pIdx],chls,setSize);
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
	/*

	key exchange here

	*/

	for (u64 round = 1; round < nParties; round++) {
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


			for (u64 i = 0; i < setSize; i++) {
				std::vector<block> rpir_output = rpir_channel_framework(0, rpir_input, chlsrpir, setSize);

			}

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
				std::vector<block> rpir_output = rpir_channel_framework(1, rpir_input, chlsrpir, setSize);

		
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

inline void channel_framework_test() {

	u64 setSize = 1 << 1;
	u64 psiSecParam = 40;
	u64 bitSize = 128;
	u64 nParties = 4;

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
	std::vector<std::thread>  pThrds(nParties);
	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
	{
		pThrds[pIdx] = std::thread([&, pIdx]() {
			psu_channel_framework(inputSet[pIdx],nParties, pIdx, setSize, chls);
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

inline void ecc_channel_test(){
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


	//Encryption and Decryption testing (ElGamal)
	REllipticCurve curve(CURVE_25519);
	PRNG prng(_mm_set_epi32(19249,4923, 234435, 1231));
	PRNG prng_r(_mm_set_epi32(4253465, 3434565, 234435, 1231));
	//generater g
	const auto& g = curve.getGenerator();

	//sk
	REccNumber sk(curve);
	sk.randomize(prng);
	//pk
	REccPoint pk = g * sk;

	block message = prng.get<block>();
	std::cout <<"message: " <<message << std::endl;
	
	std::vector<u8> m_vec(g.sizeBytes() - 1);
	m_vec = block_to_u8vec(message,g.sizeBytes()-1);
	
	REccNumber m_num(curve);
	
	m_num.fromBytes(m_vec.data());
	// std::cout <<"message as ecc number: "<< std::endl;
	// for (u64 i = 0; i < m_vec.size(); i++) {
	// 	std::cout  <<std::hex<<unsigned(m_vec[i]) ;
	// }
	// std::cout <<std::endl;
	m_vec.insert(m_vec.begin(), 3);
	// std::cout <<"message as ecc point: "<< std::endl;
	// for (u64 i = 0; i < m_vec.size(); i++) {
	// 	std::cout  <<std::hex<<unsigned(m_vec[i]) ;
	// }
	// std::cout <<std::endl;

	REccPoint m(curve);
	m.fromBytes(m_vec.data());
	//std::cout << "p3"<< std::endl;
	
	REccNumber r(curve);
	r.randomize(prng_r);

	REccPoint c1 = g * r;
	REccPoint c2 = m + pk * r;
	
	REccPoint dec_m(curve);
	dec_m = c2 - c1 * sk;
	
	std::vector<u8> dec_m_vec(g.sizeBytes());
	dec_m.toBytes(dec_m_vec.data());
	
	

	dec_m_vec.erase(dec_m_vec.begin());
	
	block dec_message = u8vec_to_block(dec_m_vec,g.sizeBytes()-1);
	std::cout << "decode message: "<<dec_message << std::endl;

	// std::vector<u8> enc_m(g.sizeBytes());
	// c2.toBytes(enc_m.data());
	// for (u64 i = 0; i < enc_m.size(); i++) {
	// 	std::cout  <<std::hex<<unsigned(enc_m[i]) ;
	// }

	// std::cout << std::endl;

	// std::vector<block> ot_m = ciphertexts_to_blocks(enc_m,enc_m);


	// std::cout << "blocks view: " << std::endl;
	// std::cout << ot_m.size() << std::endl;
	// for (u64 i = 0; i < ot_m.size(); i++) {
	// 	std::cout << ot_m[i]<<std::endl;
	// }

	// std::vector<std::vector<u8>> ctx = blocks_to_ciphertexts(ot_m, 33);

	// for (u64 i = 0; i < ctx[0].size(); i++) {
	// 	std::cout  <<std::hex<< unsigned(ctx[0][i]);
	// }

	
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


// inline void psu_ot(std::vector<block> inputSet, u64 nParties, u64 myIdx, u64 setSize, std::vector<std::vector<Channel>> chls) {
// 	int n = 100;
// 	if (myIdx == 0) {
// 		PRNG prng(sysRandomSeed());
// 		IknpOtExtReceiver recver;

// 		// Choose which messages should be received.
// 		BitVector choices(n);
// 		choices[0] = 1;

// 		// Receive the messages
// 		std::vector<block> messages(n);
// 		recver.receiveChosen(choices, messages, prng, chls[0][1]);

// 		// messages[i] = sendMessages[i][choices[i]];
// 		std::cout << messages[0] << std::endl;
// 	}
// 	else if (myIdx == 1) {
// 		PRNG prng(sysRandomSeed());
// 		IknpOtExtSender sender;

// 		// Choose which messages should be sent.
// 		std::vector<std::array<block, 2>> sendMessages(n);
// 		sendMessages[0] = { toBlock(54), toBlock(33) };

// 		std::cout << sendMessages[1][0] << std::endl;
// 		std::cout << sendMessages[1][1] << std::endl;

// 		// Send the messages.
// 		sender.sendChosen(sendMessages, prng, chls[1][0]);
// 	}
	
// }


// inline void ot_test() {
// 	u64 setSize = 1 << 1;
// 	u64 psiSecParam = 40;
// 	u64 bitSize = 128;
// 	u64 nParties = 2;
	
// 	//Create Channels
// 	IOService ios(0);

// 	auto ip = std::string("127.0.0.1");

// 	std::string sessionHint = "psu";

// 	std::vector<std::vector<Session>> ssns(nParties, std::vector<Session>(nParties));
// 	std::vector<std::vector<Channel>> chls(nParties, std::vector<Channel>(nParties));

// 	for (u64 i = 0; i < nParties; i++) {
// 		for (u64 j = 0; j < nParties; j++) {
// 			if (i < j) {
// 				u32 port = 1100 + j * 100 + i;
// 				std::string serversIpAddress = ip + ':' + std::to_string(port);
// 				ssns[i][j].start(ios, serversIpAddress, SessionMode::Server, sessionHint);

// 				chls[i][j] = ssns[i][j].addChannel();
// 				//ep[i].start(ios, "localhost", port, true, name); //channel bwt i and pIdx, where i is receiver
// 			}
// 			else if (i > j) {
// 				u32 port = 1100 + i * 100 + j;
// 				std::string serversIpAddress = ip + ':' + std::to_string(port);
// 				ssns[i][j].start(ios, serversIpAddress, SessionMode::Client, sessionHint);
// 				chls[i][j] = ssns[i][j].addChannel();
// 				//ep[i].start(ios, "localhost", port, false, name); //channel bwt i and pIdx, where i is sender
// 			}
// 		}
// 	}

// 	//set generation
// 	//first half of same elements and second half of different elements.s
// 	std::vector<std::vector<block>> inputSet(nParties, std::vector<block>(setSize));
// 	for (u64 i = 0; i < nParties; i++) {
// 		PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, 23987054));
// 		PRNG prngDiff(_mm_set_epi32(4253465, 3434565, 234423, i));
// 		for (u64 j = 0; j < setSize; j++) {
// 			if (j < setSize / 2) {
// 				inputSet[i][j] = prngSame.get<block>();
// 				//std::cout <<"input of " << myIdx << " : " << hex << inputSet[j] << std::endl;
// 			}
// 			else {
// 				inputSet[i][j] = prngDiff.get<block>();
// 				//std::cout << "input of " << myIdx << " : " << hex <<inputSet[j] << std::endl;
// 			}
// 		}

// 		/*std::cout << IoStream::lock;

// 		std::cout << "party " << i << " break point 1" << std::endl;
// 		print_block(inputSet[i]);

// 		std::cout << IoStream::unlock;*/

// 	}




// 	std::vector<std::thread>  pThrds(nParties);
// 	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
// 	{
// 		pThrds[pIdx] = std::thread([&, pIdx]() {
// 			psu_ot(inputSet[pIdx], nParties, pIdx, setSize, chls);
// 			});
// 	}

// 	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
// 		pThrds[pIdx].join();




// 	//Close channels
// 	for (u64 i = 0; i < nParties; i++) {
// 		for (u64 j = 0; j < nParties; j++) {
// 			if (i != j) {
// 				chls[i][j].close();
// 			}
// 		}
// 	}

// 	for (u64 i = 0; i < nParties; i++) {
// 		for (u64 j = 0; j < nParties; j++) {
// 			if (i != j) {
// 				ssns[i][j].stop();
// 			}
// 		}
// 	}

// 	ios.stop();
// }







