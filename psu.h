#pragma once
// #include "cryptoTools/Crypto/Curve.h"
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
#include "simpletable.h"
#include "cuckootable.h"
#include "gc.h"

using namespace osuCrypto;
// batched rpir

inline std::vector<osuCrypto::block> rpir_batched_receiver_gcsim(std::vector<std::vector<Channel>> chls, std::vector<std::vector<osuCrypto::block>> inputSet)
{
	AES hashOKVS(toBlock(12138));
	PRNG secret_value_generater(_mm_set_epi32(4253465, 12365, 234435, 23987054));
	BitVector choices(inputSet.size());

	// for(u64 i = 0; i < inputSet.size(); i++){
	// 	std::cout<<inputSet[i].size()<<std::endl;
	// }

	// receiver
	for (u64 i = 0; i < inputSet.size(); i++)
	{
		// 1.okvs
		osuCrypto::block secret_value = secret_value_generater.get<osuCrypto::block>();
		// std::cout<<"secret value: "<<secret_value<<std::endl;
		std::vector<osuCrypto::block> input = inputSet[i];
		std::vector<osuCrypto::block> okvs_value(input.size());

		hashOKVS.ecbEncBlocks(input.data(), input.size(), okvs_value.data());

		for (u64 j = 0; j < okvs_value.size(); j++)
		{
			okvs_value[j] = okvs_value[j] ^ secret_value;
		}

		// std::cout<<"okvs value: "<<okvs_value[0]<<std::endl;

		std::vector<osuCrypto::block> okvs_table(input.size() * okvsLengthScale);
		GbfEncode(input, okvs_value, okvs_table);

		chls[0][1].send(okvs_table.data(), okvs_table.size());

		// 2.gc
		u8 result = 1;

		// 3.1 circuit_psi
		choices[i] = result;
	}

	// choices[4] = 0;
	// choices[9] = 1;
	// std::cout<<"b_r: "<<choices<<std::endl;
	// 3.2 ot extension
	PRNG prng(sysRandomSeed());
	IknpOtExtReceiver recver;
	std::vector<osuCrypto::block> recv_u_blocks(inputSet.size());
	chls[0][1].recv(recv_u_blocks.data(), recv_u_blocks.size());

	// Receive the messages
	std::vector<osuCrypto::block> messages(inputSet.size());
	recver.receiveChosen(choices, messages, prng, chls[0][1]);

	std::vector<osuCrypto::block> aes_keys(inputSet.size());
	for (u64 i = 0; i < inputSet.size(); i++)
	{
		aes_keys[i] = recv_u_blocks[i] ^ messages[i];
	}

	return aes_keys;
}

inline std::vector<std::array<osuCrypto::block, 2>> rpir_batched_sender_gcsim(std::vector<std::vector<Channel>> chls, std::vector<osuCrypto::block> inputSet, u64 maxBinSize)
{
	// sender
	AES hashOKVS(toBlock(12138));
	BitVector b_s_vec(inputSet.size());

	for (u64 i = 0; i < inputSet.size(); i++)
	{
		// 1.okvs
		std::vector<osuCrypto::block> recv_okvs_table(maxBinSize * okvsLengthScale);
		chls[1][0].recv(recv_okvs_table.data(), recv_okvs_table.size());
		// print_block(recv_okvs_table);

		// first half of y, enough for equality check
		std::vector<osuCrypto::block> y;
		y.push_back(inputSet[i]);

		std::vector<osuCrypto::block> decoded_value(1);
		GbfDecode(recv_okvs_table, y, decoded_value);

		std::vector<osuCrypto::block> H_y(1);
		hashOKVS.ecbEncBlocks(y.data(), y.size(), H_y.data());

		osuCrypto::block received_value = H_y[0] ^ decoded_value[0];
		// std::cout<<"received value: "<<received_value<<std::endl;

		// std::cout<<received_value<<std::endl;

		// 2.gc
		//===========sim=============
		u8 result = 0;
		//===========sim=============

		b_s_vec[i] = result;
	}

	// 3.2 ot sender
	PRNG prng(sysRandomSeed());
	IknpOtExtSender sender;
	std::vector<std::array<osuCrypto::block, 2>> sendMessages(inputSet.size());
	// Choose which messages should be sent.
	std::vector<std::array<osuCrypto::block, 2>> aes_keys(inputSet.size());
	std::vector<osuCrypto::block> u_blocks;

	PRNG prng_ot_aes(_mm_set_epi32(4253465, 1265, 234435, 23987054));
	for (u64 i = 0; i < inputSet.size(); i++)
	{
		aes_keys[i] = {prng_ot_aes.get<osuCrypto::block>(), prng_ot_aes.get<osuCrypto::block>()};
		osuCrypto::block r = prng.get<osuCrypto::block>();
		osuCrypto::block u;
		if (b_s_vec[i] == 1)
		{
			u = r ^ aes_keys[i][0] ^ aes_keys[i][1];
		}
		else
		{
			u = r;
		}
		u_blocks.push_back(u);

		sendMessages[i][0] = r ^ aes_keys[i][0];
		sendMessages[i][1] = r ^ aes_keys[i][1];
	}
	chls[1][0].send(u_blocks.data(), u_blocks.size());

	// Send the messages.
	sender.sendChosen(sendMessages, prng, chls[1][0]);

	return aes_keys;
}

// return aes key
inline std::vector<osuCrypto::block> rpir_batched_receiver(std::vector<std::vector<Channel>> chls, std::vector<std::vector<osuCrypto::block>> inputSet, emp::NetIO *io)
{
	AES hashOKVS(toBlock(12138));
	PRNG secret_value_generater(_mm_set_epi32(4253465, 12365, 234435, 23987054));
	BitVector choices(inputSet.size());

	// for(u64 i = 0; i < inputSet.size(); i++){
	// 	std::cout<<inputSet[i].size()<<std::endl;
	// }

	// receiver
	for (u64 i = 0; i < inputSet.size(); i++)
	{
		// 1.okvs
		osuCrypto::block secret_value = secret_value_generater.get<osuCrypto::block>();
		// std::cout<<"secret value: "<<secret_value<<std::endl;
		std::vector<osuCrypto::block> input = inputSet[i];
		std::vector<osuCrypto::block> okvs_value(input.size());

		hashOKVS.ecbEncBlocks(input.data(), input.size(), okvs_value.data());

		for (u64 j = 0; j < okvs_value.size(); j++)
		{
			okvs_value[j] = okvs_value[j] ^ secret_value;
		}

		// std::cout<<"okvs value: "<<okvs_value[0]<<std::endl;

		std::vector<osuCrypto::block> okvs_table(input.size() * okvsLengthScale);
		GbfEncode(input, okvs_value, okvs_table);

		chls[0][1].send(okvs_table.data(), okvs_table.size());

		// 2.gc
		u8 result = 0;
		u64 number_to_compare;
		memcpy(&number_to_compare, &secret_value, sizeof(number_to_compare));
		// std::cout << "num:"<<number_to_compare<<std::endl;
		auto z = _AeqB(io, 1, number_to_compare);
		bool bS = z[0].reveal<bool>();
		bool bR = z[1].reveal<bool>();
		// delete io;
		result = bR;

		// 3.1 circuit_psi
		choices[i] = result;
	}
	delete io;
	// choices[4] = 0;
	// choices[9] = 1;
	// std::cout<<"b_r: "<<choices<<std::endl;
	// 3.2 ot extension
	PRNG prng(sysRandomSeed());
	IknpOtExtReceiver recver;
	std::vector<osuCrypto::block> recv_u_blocks(inputSet.size());
	chls[0][1].recv(recv_u_blocks.data(), recv_u_blocks.size());

	// Receive the messages
	std::vector<osuCrypto::block> messages(inputSet.size());
	recver.receiveChosen(choices, messages, prng, chls[0][1]);

	std::vector<osuCrypto::block> aes_keys(inputSet.size());
	for (u64 i = 0; i < inputSet.size(); i++)
	{
		aes_keys[i] = recv_u_blocks[i] ^ messages[i];
	}

	return aes_keys;
}

inline std::vector<std::array<osuCrypto::block, 2>> rpir_batched_sender(std::vector<std::vector<Channel>> chls, std::vector<osuCrypto::block> inputSet, u64 maxBinSize, emp::NetIO *io)
{
	// sender
	AES hashOKVS(toBlock(12138));
	BitVector b_s_vec(inputSet.size());

	for (u64 i = 0; i < inputSet.size(); i++)
	{
		// 1.okvs
		std::vector<osuCrypto::block> recv_okvs_table(maxBinSize * okvsLengthScale);
		chls[1][0].recv(recv_okvs_table.data(), recv_okvs_table.size());
		// print_block(recv_okvs_table);

		// first half of y, enough for equality check
		std::vector<osuCrypto::block> y;
		y.push_back(inputSet[i]);

		std::vector<osuCrypto::block> decoded_value(1);
		GbfDecode(recv_okvs_table, y, decoded_value);

		std::vector<osuCrypto::block> H_y(1);
		hashOKVS.ecbEncBlocks(y.data(), y.size(), H_y.data());

		osuCrypto::block received_value = H_y[0] ^ decoded_value[0];
		// std::cout<<"received value: "<<received_value<<std::endl;

		// std::cout<<received_value<<std::endl;

		// 2.gc
		//===========sim=============
		u8 result = 0;
		u64 number_to_compare;
		memcpy(&number_to_compare, &received_value, sizeof(number_to_compare));

		auto z = _AeqB(io, 2, number_to_compare);
		bool bS = z[0].reveal<bool>();
		bool bR = z[1].reveal<bool>();

		result = bS;
		//===========sim=============

		b_s_vec[i] = result;
	}
	delete io;
	// 3.2 ot sender
	PRNG prng(sysRandomSeed());
	IknpOtExtSender sender;
	std::vector<std::array<osuCrypto::block, 2>> sendMessages(inputSet.size());
	// Choose which messages should be sent.
	std::vector<std::array<osuCrypto::block, 2>> aes_keys(inputSet.size());
	std::vector<osuCrypto::block> u_blocks;

	PRNG prng_ot_aes(_mm_set_epi32(4253465, 1265, 234435, 23987054));
	for (u64 i = 0; i < inputSet.size(); i++)
	{
		aes_keys[i] = {prng_ot_aes.get<osuCrypto::block>(), prng_ot_aes.get<osuCrypto::block>()};
		osuCrypto::block r = prng.get<osuCrypto::block>();
		osuCrypto::block u;
		if (b_s_vec[i] == 1)
		{
			u = r ^ aes_keys[i][0] ^ aes_keys[i][1];
		}
		else
		{
			u = r;
		}
		u_blocks.push_back(u);

		sendMessages[i][0] = r ^ aes_keys[i][0];
		sendMessages[i][1] = r ^ aes_keys[i][1];
	}
	chls[1][0].send(u_blocks.data(), u_blocks.size());

	// Send the messages.
	sender.sendChosen(sendMessages, prng, chls[1][0]);

	return aes_keys;
}

// cOPRF (bugs for ecc number inverse)
inline void coprf_sender_batched(std::vector<std::vector<Channel>> chls, std::vector<std::vector<osuCrypto::block>> input, std::vector<u8> key_vec)
{ // input is simple hash table (first 128 bit of each element)
	std::vector<osuCrypto::block> aes_keys = rpir_batched_receiver_gcsim(chls, input);

	REllipticCurve curve; //(CURVE_25519)
	// generater g
	const auto &g = curve.getGenerator();

	for (u64 i = 0; i < input.size(); i++)
	{
		std::vector<osuCrypto::block> recv_aes_message(6);
		chls[0][1].recv(recv_aes_message.data(), recv_aes_message.size());
		// std::vector<osuCrypto::block> recv_aes_message = {recv_messages.begin() + i * 6, recv_messages.begin() + i * 6 + 6};

		// decrypt
		// message decode
		AESDec decryptor(aes_keys[i]);
		osuCrypto::block indicator = decryptor.ecbDecBlock(recv_aes_message[0]);
		std::vector<osuCrypto::block> point_block;
		if (indicator == toBlock(u64(2)) || indicator == toBlock(u64(3)))
		{
			point_block.push_back(decryptor.ecbDecBlock(recv_aes_message[0]));
			point_block.push_back(decryptor.ecbDecBlock(recv_aes_message[1]));
			point_block.push_back(decryptor.ecbDecBlock(recv_aes_message[2]));
		}
		else
		{
			point_block.push_back(decryptor.ecbDecBlock(recv_aes_message[3]));
			point_block.push_back(decryptor.ecbDecBlock(recv_aes_message[4]));
			point_block.push_back(decryptor.ecbDecBlock(recv_aes_message[5]));
		}

		// construct point u8vec
		std::vector<u8> y(1);
		if (point_block[0] == toBlock(u64(2)))
		{
			y[0] = 2;
		}
		else if (point_block[0] == toBlock(u64(3)))
		{
			y[0] = 3;
		}
		std::vector<u8> v_vec = blocks_to_u8vec({point_block[1], point_block[2]});
		v_vec.insert(v_vec.begin(), y.begin(), y.end());

		REccPoint v(curve);
		REccNumber key(curve);
		v.fromBytes(v_vec.data());
		key.fromBytes(key_vec.data());
		v = v * key;
		std::vector<u8> w_vec(33);
		v.toBytes(w_vec.data());
		// print_u8vec(w_vec);
		chls[0][1].send(w_vec.data(), w_vec.size());
	}

	return;
}

inline std::vector<osuCrypto::block> coprf_receiver_batched(std::vector<std::vector<Channel>> chls, std::vector<osuCrypto::block> input)
{ // receive 2*16 bytes of coprf value to update inputSet_block
	std::vector<osuCrypto::block> coprf_value;
	// first 128 bit for each element as rpir input
	std::vector<std::array<osuCrypto::block, 2>> aes_keys = rpir_batched_sender_gcsim(chls, input, 20);

	PRNG prngAlpha(_mm_set_epi32(4253465, 3434565, 234435, 1041));
	REllipticCurve curve; //(CURVE_25519)
	// generater g
	const auto &g = curve.getGenerator();
	// hash aes

	input[0] = toBlock(u64(123));

	osuCrypto::AES pubHash(toBlock(12138));
	std::vector<osuCrypto::block> H_q(input.size());
	pubHash.ecbEncBlocks(input.data(), input.size(), H_q.data());

	// compute mOT messsages
	// 6 blocks for each instance
	// 0:2 v0 random osuCrypto::block
	// 3:5 v1 last 32 bytes of point H(q)^alpha

	PRNG prngv0(_mm_set_epi32(4212365, 3434565, 234435, 1041));

	for (u64 i = 0; i < input.size(); i++)
	{
		std::vector<osuCrypto::block> mOT_messages;
		// v0
		REccNumber v0_num(curve);
		v0_num.randomize(prngv0);
		REccPoint v0 = g * v0_num;
		std::vector<u8> v0_vec(33);
		v0.toBytes(v0_vec.data());
		std::vector<osuCrypto::block> y0 = {toBlock(v0_vec[0])};
		v0_vec.erase(v0_vec.begin());
		std::vector<osuCrypto::block> v0_block = u8vec_to_blocks(v0_vec);
		v0_block.insert(v0_block.begin(), y0.begin(), y0.end());
		AES aes_v0(aes_keys[i][0]);
		std::vector<osuCrypto::block> v0_enc(v0_block.size());
		aes_v0.ecbEncBlocks(v0_block.data(), v0_block.size(), v0_enc.data());
		mOT_messages.insert(mOT_messages.end(), v0_enc.begin(), v0_enc.end());

		// v1
		REccNumber alpha(curve);
		alpha.randomize(prngAlpha);

		// H(q)
		REccPoint v1(curve);
		REccNumber hq(curve);
		// std::vector<u8> hq_vec = blocks_to_u8vec({H_q[i * 2], H_q[i * 2 + 1]});
		std::vector<u8> hq_vec = block_to_u8vec(H_q[i], 32);

		hq.fromBytes(hq_vec.data());
		// H(q)
		v1 = g * hq;
		// v1.randomize(prngv1); // bug with randomize function

		// H(q)^alpha
		v1 = v1 * alpha;

		std::vector<u8> v1_vec(33);
		v1.toBytes(v1_vec.data());

		std::vector<osuCrypto::block> y1 = {toBlock(v1_vec[0])};
		v1_vec.erase(v1_vec.begin());
		std::vector<osuCrypto::block> v1_block = u8vec_to_blocks(v1_vec);
		v1_block.insert(v1_block.begin(), y1.begin(), y1.end());
		AES aes_v1(aes_keys[i][1]);
		std::vector<osuCrypto::block> v1_enc(v1_block.size());
		aes_v1.ecbEncBlocks(v1_block.data(), v1_block.size(), v1_enc.data());
		mOT_messages.insert(mOT_messages.end(), v1_enc.begin(), v1_enc.end());

		chls[1][0].send(mOT_messages.data(), mOT_messages.size());

		std::vector<u8> recv_w_vec(33);
		chls[1][0].recv(recv_w_vec.data(), recv_w_vec.size());
		// compute the PRF(k,q)
		REccPoint w(curve);
		w.fromBytes(recv_w_vec.data());

		w *= alpha.inverse();

		std::vector<u8> prf_vec(33);
		w.toBytes(prf_vec.data());
		prf_vec.erase(prf_vec.begin());
		std::vector<osuCrypto::block> prf_block = u8vec_to_blocks(prf_vec);

		coprf_value.insert(coprf_value.end(), prf_block.begin(), prf_block.end());
	}

	return coprf_value;
}

inline void psu2(std::vector<std::vector<u8>> inputSet_u8, std::vector<osuCrypto::block> inputSet_block, u64 nParties, u64 myIdx, u64 setSize, std::vector<std::vector<Channel>> chls)
{
	u64 maxBinSize = 20;
	// std::cout<<IoStream::lock;
	// std::cout<<"P"<<myIdx<<" input"<<std::endl;
	// // for(u64 i = 0; i<inputSet_u8.size(); i++){
	// // 	print_u8vec(inputSet_u8[i]);
	// // }
	// print_block(inputSet_block);
	// std::cout<<IoStream::unlock;

	// ============================================   local execution   ======================================

	// protocol
	// 1.key exchange
	// Curve
	REllipticCurve curve; //(CURVE_25519)
	PRNG prng(_mm_set_epi32(19249, 4923, 234435, 1231));
	PRNG prng_r(_mm_set_epi32(4253465, 3434565, 234435, 1231));
	// generater g
	const auto &g = curve.getGenerator();
	// sk_i
	std::vector<std::vector<u8>> s_keys; // 32 Bytes
	// g^sk_i
	std::vector<std::vector<u8>> g_sks; // 33 Bytes, y at index[][0]

	for (u64 i = 0; i < nParties; i++)
	{
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
	// pk
	REccNumber sk0;
	sk0.fromBytes(s_keys[0].data());
	REccPoint pk = g * sk0; // pk

	for (u64 i = 1; i < s_keys.size(); i++)
	{
		REccNumber ski;
		ski.fromBytes(s_keys[i].data());
		pk += g * ski; // pk
	}

	std::vector<u8> pk_vec(g.sizeBytes());
	pk.toBytes(pk_vec.data());

	// AES_KEY for OPRF
	PRNG prngAES(_mm_set_epi32(123, 3434565, 234435, 23987054));
	std::vector<osuCrypto::block> AES_keys;
	for (u64 i = 0; i < nParties; i++)
	{
		AES_keys.push_back(prngAES.get<osuCrypto::block>());
	}

	PRNG prng_enc(_mm_set_epi32(4253465, 3434565, 234435, 1231));
	// All the parties compute the X' = Enc(pk,X)
	// encrypt_set: setSize * 2 * 33 u8 vector
	std::vector<std::vector<std::vector<u8>>> encrypt_set;
	for (u64 i = 0; i < inputSet_u8.size(); i++)
	{
		// std::cout<<inputSet_u8[i]<<std::endl;
		// print_u8vec(pk_vec);
		std::vector<std::vector<u8>> ciphertext = encryption(inputSet_u8[i], pk_vec, prng_enc);
		encrypt_set.push_back(ciphertext);
	}
	// p0 init V
	std::vector<std::vector<std::vector<u8>>> set_V;
	if (myIdx == 0)
	{
		set_V = encrypt_set;
	}

	////All the parties compute the Enc(pk,0)
	// setSize * 2 * 33 u8 vector
	std::vector<std::vector<std::vector<u8>>> encrypt_zero_set;
	for (u64 i = 0; i < 1.27 * setSize; i++)
	{
		// std::cout<<inputSet_u8[i]<<std::endl;
		// print_u8vec(pk_vec);
		std::vector<u8> zero_u8(32, 0);
		std::vector<std::vector<u8>> ciphertext = encryption(zero_u8, pk_vec, prng_enc);
		encrypt_zero_set.push_back(ciphertext);
	}

	SimpleTable simple;
	CuckooTable cuckoo;
	if (myIdx == 0)
	{

		//----------------simple hashing--------------------

		PRNG simple_dummy(_mm_set_epi32(4253465, 3434565, 234435, 1234567 + myIdx));

		simple.init(1.27, setSize, 3);

		for (u64 i = 0; i < setSize; i++)
		{
			simple.insertItems(inputSet_block[2 * i]);
		}

		simple.padGlobalItems(simple_dummy, maxBinSize);

		// std::cout<<IoStream::lock;
		// std::cout<<"after padding"<<std::endl;
		// simple.print_table();
		// std::cout<<IoStream::unlock;

		//--------------------------------------------------
	}
	else if (myIdx == 1)
	{

		//----------------simple hashing--------------------

		PRNG simple_dummy(_mm_set_epi32(4253465, 3434565, 234435, 1234567 + myIdx));

		simple.init(1.27, setSize, 3);

		for (u64 i = 0; i < setSize; i++)
		{
			simple.insertItems(inputSet_block[2 * i]);
		}

		simple.padGlobalItems(simple_dummy, maxBinSize);

		//--------------------------------------------------
		//----------------cuckoo hashing--------------------

		PRNG cuckoo_dummy(_mm_set_epi32(4253465, 3431235, 23232435, 1234567 + myIdx));

		cuckoo.init(1.27, setSize, 3);

		for (u64 i = 0; i < setSize; i++)
		{
			cuckoo.insertItem(inputSet_block[i * 2], i);
		}

		cuckoo.padGlobalItems(cuckoo_dummy);

		// std::cout<<IoStream::lock;
		// std::cout<<"after padding"<<std::endl;
		// cuckoo.print_table();
		// std::cout<<IoStream::unlock;

		//--------------------------------------------------
	}
	std::cout << "Party " << myIdx << " offline finished" << std::endl;
	// =========================== online execution ==============================================
	for (u64 round = 1; round < nParties; round++)
	{
		if (myIdx == 0)
		{
			// 3a---------------- oprf --------------------------------------------------
			// chls
			std::vector<std::vector<Channel>> chlsoprf(2, std::vector<Channel>(2));
			chlsoprf[0][1] = chls[0][round];

			// oprf receiver

			for (u64 i = 0; i < simple.items.size(); i++)
			{
				for (u64 j = 0; j < simple.items[i].size(); j++)
				{

					std::vector<osuCrypto::block> oprf_input = {simple.items[i][j]};
					std::vector<osuCrypto::block> oprf_value = dh_oprf(0, oprf_input, chlsoprf);
					// std::cout<<oprf_value[0]<<std::endl;
					//  update
					simple.items[i][j] = oprf_value[0];
				}

				// 3c----------------- mOT --------------------------------------------------
			}
			// std::cout << IoStream::lock;
			// std::cout<<"=================="<<std::endl;
			// simple.print_table();
			// std::cout << IoStream::unlock;
		}
		else if (myIdx == round)
		{
			// 3a---------------- oprf --------------------------------------------------
			// chls
			std::vector<std::vector<Channel>> chlsoprf(2, std::vector<Channel>(2));
			chlsoprf[1][0] = chls[round][0];

			PRNG key_gen(toBlock(u64(135246 + myIdx)));
			std::vector<osuCrypto::block> key;
			key.push_back(key_gen.get<osuCrypto::block>());
			key.push_back(key_gen.get<osuCrypto::block>());
			// oprf sender

			for (u64 i = 0; i < simple.items.size(); i++)
			{
				for (u64 j = 0; j < simple.items[i].size(); j++)
				{
					// oprf with p0
					std::vector<osuCrypto::block> a = dh_oprf(1, key, chlsoprf);
					// update own table
					// simple
					std::vector<osuCrypto::block> oprf_value = dh_prf({simple.items[i][j]}, key);
					simple.items[i][j] = oprf_value[0];
				}
				// cuckoo
				std::vector<osuCrypto::block> oprf_value = dh_prf({cuckoo.items[i]}, key);
				// std::cout<<oprf_value[0]<<std::endl;
				cuckoo.items[i] = oprf_value[0];
			}
			// std::cout << IoStream::lock;
			// std::cout<<"=================="<<std::endl;
			// cuckoo.print_table();
			// std::cout << IoStream::unlock;

			// 3c----------------- mOT --------------------------------------------------
			// 3b 3d ------------ coprf & encryption set update -------------------------
		}
		else
		{
			// 3b 3d ------------ coprf & encryption set update -------------------------
		}

		// ========================== Decrypt & Shuffle ==============================================
	}
}
// // MPSU
inline void psu1_final(std::vector<std::vector<u8>> inputSet_u8, std::vector<osuCrypto::block> inputSet_block, u64 nParties, u64 myIdx, u64 setSize, std::vector<std::vector<Channel>> chls)
{
	//=============================   Local Execution   ================================
	u64 maxBinSize = 20;
	// std::cout<<IoStream::lock;
	// std::cout<<"P"<<myIdx<<" input"<<std::endl;
	// for(u64 i = 0; i<inputSet_u8.size(); i++){
	// 	print_u8vec(inputSet_u8[i]);
	// }
	// //print_block(inputSet_block);
	// std::cout<<IoStream::unlock;

	// protocol
	// 1.key exchange
	// Curve
	REllipticCurve curve; //(CURVE_25519)
	PRNG prng(_mm_set_epi32(19249, 4923, 234435, 1231));
	PRNG prng_r(_mm_set_epi32(4253465, 3434565, 234435, 1231));
	// generater g
	const auto &g = curve.getGenerator();
	// sk_i
	std::vector<std::vector<u8>> s_keys; // 32 Bytes
	// g^sk_i
	std::vector<std::vector<u8>> g_sks; // 33 Bytes, y at index[][0]

	for (u64 i = 0; i < nParties; i++)
	{
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
	// pk
	REccNumber sk0;
	sk0.fromBytes(s_keys[0].data());
	REccPoint pk = g * sk0; // pk

	for (u64 i = 1; i < s_keys.size(); i++)
	{
		REccNumber ski;
		ski.fromBytes(s_keys[i].data());
		pk += g * ski; // pk
	}

	std::vector<u8> pk_vec(g.sizeBytes());
	pk.toBytes(pk_vec.data());

	PRNG prng_enc(_mm_set_epi32(4253465, 3434565, 234435, 1231));

	// All the parties compute the X' = Enc(pk,X)
	// encrypt_set: setSize * 2 * 33 u8 vector
	std::vector<std::vector<std::vector<u8>>> encrypt_set;
	if (myIdx != 0)
	{
		for (u64 i = 0; i < inputSet_u8.size(); i++)
		{
			// std::cout<<inputSet_u8[i]<<std::endl;
			// print_u8vec(pk_vec);
			std::vector<std::vector<u8>> ciphertext = encryption(inputSet_u8[i], pk_vec, prng_enc);
			encrypt_set.push_back(ciphertext);
		}
	}

	// p0 init V
	std::vector<std::vector<std::vector<u8>>> set_V;

	// set U
	std::vector<std::vector<u8>> set_U;
	if (myIdx == 0)
	{
		set_U = inputSet_u8;
	}

	////All the parties compute the Enc(pk,0)
	// setSize * 2 * 33 u8 vector
	std::vector<std::vector<std::vector<u8>>> encrypt_zero_set;
	for (u64 i = 0; i < 1.27 * setSize; i++)
	{
		// std::cout<<inputSet_u8[i]<<std::endl;
		// print_u8vec(pk_vec);
		std::vector<u8> zero_u8(32, 0);
		std::vector<std::vector<u8>> ciphertext = encryption(zero_u8, pk_vec, prng_enc);
		encrypt_zero_set.push_back(ciphertext);
	}

	//=============================   End of Local Execution   ================================

	Timer timer;
	timer.reset();
	auto start = timer.setTimePoint("start");

	//=============================   OPRF Execution ==========================================
	if (myIdx == 0)
	{
		// 2.=============================== OPRF P_0 & P_i ==================================
		// update channel for oprf
		std::vector<std::vector<Channel>> chlsoprf(2, std::vector<Channel>(2));
		chlsoprf[0][1] = chls[0][1];

		std::vector<osuCrypto::block> oprf_value(inputSet_block.size());

		oprf_value = aes_oprf(0, inputSet_block, 2 * setSize, chlsoprf, ZeroBlock);
		inputSet_block = oprf_value;
	}
	else if (myIdx == 1)
	{ //----------------- with P1 -----------------
		// update channel for oprf
		std::vector<std::vector<Channel>> chlsoprf(2, std::vector<Channel>(2));
		chlsoprf[1][0] = chls[1][0];
		std::vector<osuCrypto::block> oprf_value;
		// AES_KEY for OPRF
		PRNG prngOPRF(_mm_set_epi32(123, 3434565, 234435, 23987054));
		std::vector<osuCrypto::block> oprf_key = {prngOPRF.get<osuCrypto::block>()};
		oprf_value = aes_oprf(1, inputSet_block, 2 * setSize, chlsoprf, oprf_key[0]);
		inputSet_block = oprf_value;
		//------------------ with others ----------------
		// 4.OPRF key sharing
		for (u64 j = 2; j < nParties; j++)
		{

			chls[1][j].send(oprf_key.data(), oprf_key.size());
			// std::cout << IoStream::lock;
			// std::cout << "party " << myIdx << " round "<< round << std::endl;
			// print_block(oprf_key);
			// std::cout << IoStream::unlock;
		}
	}
	else
	{
		// 4.OPRF key sharing
		//
		std::vector<osuCrypto::block> recv_oprf_key(1);
		chls[myIdx][1].recv(recv_oprf_key.data(), recv_oprf_key.size());

		AES aes_oprf(recv_oprf_key[0]);

		std::vector<osuCrypto::block> oprf_value(inputSet_block.size());

		aes_oprf.ecbEncBlocks(inputSet_block.data(), inputSet_block.size(), oprf_value.data());

		inputSet_block = oprf_value;
	}

	// cuckoo and simple hashing

	u64 tablesize = 1.27 * setSize;
	SimpleTable simple;
	CuckooTable cuckoo;

	if (myIdx == 0)
	{
		//----------------simple hashing--------------------

		PRNG simple_dummy(_mm_set_epi32(4253465, 3434565, 234435, 1234567 + myIdx));

		simple.init(1.27, setSize, 3);

		for (u64 i = 0; i < setSize; i++)
		{
			simple.insertItems(inputSet_block[2 * i]);
		}

		// std::cout << "max bin size: " << simple.getMaxBinSize() << std::endl;
		//  std::cout<<IoStream::lock;
		//  simple.print_table();
		//  std::cout<<IoStream::unlock;
		simple.padGlobalItems(simple_dummy, maxBinSize);

		//--------------------------------------------------
	}
	else
	{
		//----------------cuckoo hashing--------------------
		PRNG cuckoo_dummy(_mm_set_epi32(4253465, 3434565, 23232435, 1234567 + myIdx));

		cuckoo.init(1.27, setSize, 3);
		for (u64 i = 0; i < setSize; i++)
		{
			cuckoo.insertItem(inputSet_block[2 * i], i);
		}

		// std::cout<<IoStream::lock;
		// cuckoo.print_table();
		// std::cout<<IoStream::unlock;

		cuckoo.padGlobalItems(cuckoo_dummy);

		//--------------------------------------------------
	}

	//===============================   mOT Execution   ================================

	for (u64 round = 1; round < nParties; round++)
	{
		// P_0
		if (myIdx == 0)
		{
			std::vector<std::vector<Channel>> chlsrpir(2, std::vector<Channel>(2));
			chlsrpir[0][1] = chls[0][round];

			// rpir_batched

			emp::NetIO *io = new NetIO("127.0.0.1", 6000);
			setup_semi_honest(io, myIdx);

			std::vector<osuCrypto::block> aes_keys = rpir_batched_receiver(chlsrpir, simple.items, io);

			// 3.3 message parse & decrypt

			std::vector<osuCrypto::block> rpir_message;

			for (u64 i = 0; i < simple.items.size(); i++)
			{
				std::vector<osuCrypto::block> recv_aes_message(14);

				chls[0][round].recv(recv_aes_message.data(), recv_aes_message.size());

				// std::vector<osuCrypto::block> recv_aes_message = {recv_ot_messages.begin() + i * 14, recv_ot_messages.begin() + i * 14 + 14};

				// decrypt
				// message decode
				AESDec decryptor(aes_keys[i]);
				osuCrypto::block indicator = decryptor.ecbDecBlock(recv_aes_message[2]);
				std::vector<osuCrypto::block> rpir_message;
				if (indicator == toBlock(u64(0)) || indicator == toBlock(u64(1)) || indicator == toBlock(u64(2)) || indicator == toBlock(u64(3)))
				{
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[0]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[1]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[2]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[3]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[4]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[5]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[6]));
				}
				else
				{
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[7]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[8]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[9]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[10]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[11]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[12]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[13]));
				}

				// received message of length 7
				// update X and V
				//[0:1]prf value

				simple.items[i].push_back(rpir_message[0]);
				//[2:6]ciphertext of element
				std::vector<osuCrypto::block> new_ctx_block = {rpir_message.begin() + 2, rpir_message.end()};
				std::vector<std::vector<u8>> new_ctx = blocks_to_ciphertexts(new_ctx_block);
				// update set_V
				set_V.push_back(new_ctx);
			}
		}
		else if (myIdx == round)
		{
			std::vector<std::vector<Channel>> chlsrpir(2, std::vector<Channel>(2));
			chlsrpir[1][0] = chls[round][0];
			// 3.1 rpir
			emp::NetIO *io = new NetIO(nullptr, 6000);
			setup_semi_honest(io, myIdx);
			std::vector<std::array<osuCrypto::block, 2>> aes_keys = rpir_batched_sender(chlsrpir, cuckoo.items, maxBinSize + round - 1, io);

			// 3.3 message construction & encryption

			PRNG prng_ot_aes(toBlock(12345678 + myIdx));

			for (u64 i = 0; i < cuckoo.items.size(); i++)
			{
				std::vector<osuCrypto::block> ot_messages;
				// for dummy value
				if (cuckoo.item_idx[i] == -1)
				{
					// v0
					// AES
					AES aes_0(aes_keys[i][0]);
					std::vector<osuCrypto::block> v0;
					//$
					v0.push_back(prng_ot_aes.get<osuCrypto::block>());
					v0.push_back(prng_ot_aes.get<osuCrypto::block>());
					// enc(0)
					std::vector<osuCrypto::block> enc_zero0 = ciphertexts_to_blocks(encrypt_zero_set[i]);
					v0.insert(v0.end(), enc_zero0.begin(), enc_zero0.end());
					std::vector<osuCrypto::block> enc_v0(v0.size());
					aes_0.ecbEncBlocks(v0.data(), v0.size(), enc_v0.data());
					ot_messages.insert(ot_messages.end(), enc_v0.begin(), enc_v0.end());
					// v1
					// AES
					AES aes_1(aes_keys[i][1]);
					std::vector<osuCrypto::block> v1;
					//$
					v1.push_back(prng_ot_aes.get<osuCrypto::block>());
					v1.push_back(prng_ot_aes.get<osuCrypto::block>());
					// enc(0)
					std::vector<osuCrypto::block> enc_zero1 = ciphertexts_to_blocks(encrypt_zero_set[i]);
					v1.insert(v1.end(), enc_zero1.begin(), enc_zero1.end());
					std::vector<osuCrypto::block> enc_v1(v1.size());
					aes_1.ecbEncBlocks(v1.data(), v1.size(), enc_v1.data());
					ot_messages.insert(ot_messages.end(), enc_v1.begin(), enc_v1.end());
				}
				// for real value
				else
				{
					// v0
					// AES
					AES aes_0(aes_keys[i][0]);
					std::vector<osuCrypto::block> v0;
					//$
					v0.push_back(prng_ot_aes.get<osuCrypto::block>());
					v0.push_back(prng_ot_aes.get<osuCrypto::block>());
					// enc(0)
					std::vector<osuCrypto::block> enc_zero = ciphertexts_to_blocks(encrypt_zero_set[i]);
					v0.insert(v0.end(), enc_zero.begin(), enc_zero.end());
					std::vector<osuCrypto::block> enc_v0(v0.size());
					aes_0.ecbEncBlocks(v0.data(), v0.size(), enc_v0.data());
					ot_messages.insert(ot_messages.end(), enc_v0.begin(), enc_v0.end());

					// v1
					AES aes_1(aes_keys[i][1]);
					std::vector<osuCrypto::block> v1;
					// F(k,x)
					v1.push_back(inputSet_block[2 * cuckoo.item_idx[i]]);
					v1.push_back(inputSet_block[2 * cuckoo.item_idx[i] + 1]);
					// Enc(x)
					std::vector<osuCrypto::block> enc_x = ciphertexts_to_blocks(encrypt_set[cuckoo.item_idx[i]]);
					v1.insert(v1.end(), enc_x.begin(), enc_x.end());
					std::vector<osuCrypto::block> enc_v1(v1.size());
					aes_1.ecbEncBlocks(v1.data(), v1.size(), enc_v1.data());
					ot_messages.insert(ot_messages.end(), enc_v1.begin(), enc_v1.end());

					// if(i == 0 && round == 1){
					// 	print_block(rpir_input);
					// 	std::cout<<"size of rpir input: "<<rpir_input.size()<<std::endl;
					// }
				}

				chls[round][0].send(ot_messages.data(), ot_messages.size());
			}

			// std::cout<<ot_messages.size()<<std::endl;
		}
	}

	// 5.Decrypt & shuffle

	if (myIdx == 0)
	{
		std::vector<osuCrypto::block> set_V_block;

		for (u64 i = 0; i < set_V.size(); i++)
		{
			// std::vector<std::vector<u8>> ctx = partial_decryption(set_V[i], s_keys[myIdx]);
			std::vector<osuCrypto::block> ctx_block = ciphertexts_to_blocks(set_V[i]);
			set_V_block.insert(set_V_block.end(), ctx_block.begin(), ctx_block.end());
		}
		chls[myIdx][1].send(set_V_block.data(), set_V_block.size());

		// receive from p_n

		// std::cout << IoStream::lock;
		// print_u8vec(element);
		// std::cout << IoStream::unlock;

		std::vector<osuCrypto::block> recv_set_V_block(((nParties - 1) * tablesize) * 5);
		chls[0][nParties - 1].recv(recv_set_V_block.data(), recv_set_V_block.size());
		// print_block(recv_set_V_block);
		std::vector<osuCrypto::block> dec_set_V_block;
		std::vector<u8> zero(32);
		for (u64 i = 0; i < (nParties - 1) * tablesize; i++)
		{
			std::vector<osuCrypto::block> ctx_block1 = {recv_set_V_block.begin() + 5 * i, recv_set_V_block.begin() + 5 * i + 5};
			std::vector<std::vector<u8>> ctx_u8 = blocks_to_ciphertexts(ctx_block1);
			std::vector<u8> element = decryption(ctx_u8, s_keys[myIdx]);
			// print_u8vec(element);

			if (element != zero)
				set_U.push_back(element);
		}
		// std::cout << IoStream::lock;
		// for(u64 i = 0;i<set_U.size();i++){
		// 	print_u8vec(set_U[i]);
		// }
		// std::cout << IoStream::unlock;
	}
	else
	{
		std::vector<osuCrypto::block> recv_set_V_block(((nParties - 1) * tablesize) * 5);
		chls[myIdx][myIdx - 1].recv(recv_set_V_block.data(), recv_set_V_block.size());
		// print_block(recv_set_V_block);
		std::vector<osuCrypto::block> dec_set_V_block;
		for (u64 i = 0; i < (nParties - 1) * tablesize; i++)
		{
			std::vector<osuCrypto::block> ctx_block1 = {recv_set_V_block.begin() + 5 * i, recv_set_V_block.begin() + 5 * i + 5};
			std::vector<std::vector<u8>> ctx_u8 = blocks_to_ciphertexts(ctx_block1);
			std::vector<std::vector<u8>> ctx = partial_decryption(ctx_u8, s_keys[myIdx]);
			std::vector<osuCrypto::block> ctx_block = ciphertexts_to_blocks(ctx);
			dec_set_V_block.insert(dec_set_V_block.end(), ctx_block.begin(), ctx_block.end());
		}

		chls[myIdx][(myIdx + 1) % nParties].send(dec_set_V_block.data(), dec_set_V_block.size());
	}

	auto end = timer.setTimePoint("end");

	std::cout << IoStream::lock;
	std::cout << " party " << myIdx << "\t" << timer << std::endl;

	double dataSent = 0, dataRecv = 0, Mbps = 0, MbpsRecv = 0;

	for (u64 j = 0; j < nParties; ++j)
	{
		if (j != myIdx)
		{
			dataSent += chls[myIdx][j].getTotalDataSent();
			dataRecv += chls[myIdx][j].getTotalDataRecv();
		}
	}

	//	std::cout << "party #" << myIdx << "\t dataSent Comm: " << ((dataSent ) / std::pow(2.0, 20)) << " MB" << std::endl;
	//	std::cout << "party #" << myIdx << "\t dataRecv Comm: " << (( dataRecv) / std::pow(2.0, 20)) << " MB" << std::endl;
	std::cout << "party #" << myIdx << "\t Comm: " << ((dataSent + dataRecv) / std::pow(2.0, 20)) << " MB" << std::endl;
	std::cout << IoStream::unlock;
}

inline void mpsu_test()
{

	u64 setSize = 1 << 2;
	u64 psiSecParam = 40;
	u64 bitSize = 128;
	u64 nParties = 2;

	// Create Channels
	IOService ios(0);

	auto ip = std::string("127.0.0.1");

	std::string sessionHint = "psu";

	std::vector<std::vector<Session>> ssns(nParties, std::vector<Session>(nParties));
	std::vector<std::vector<Channel>> chls(nParties, std::vector<Channel>(nParties));

	for (u64 i = 0; i < nParties; i++)
	{
		for (u64 j = 0; j < nParties; j++)
		{
			if (i < j)
			{
				u32 port = 1100 + j * 100 + i;
				std::string serversIpAddress = ip + ':' + std::to_string(port);
				ssns[i][j].start(ios, serversIpAddress, SessionMode::Server, sessionHint);

				chls[i][j] = ssns[i][j].addChannel();
				// ep[i].start(ios, "localhost", port, true, name); //channel bwt i and pIdx, where i is receiver
			}
			else if (i > j)
			{
				u32 port = 1100 + i * 100 + j;
				std::string serversIpAddress = ip + ':' + std::to_string(port);
				ssns[i][j].start(ios, serversIpAddress, SessionMode::Client, sessionHint);
				chls[i][j] = ssns[i][j].addChannel();
				// ep[i].start(ios, "localhost", port, false, name); //channel bwt i and pIdx, where i is sender
			}
		}
	}

	// set generation
	// first half of same elements and second half of different elements.s

	// ECC Points
	// nParties * setSize * 32 u8 vector
	std::vector<std::vector<std::vector<u8>>> inputSet_u8(nParties);
	// nParties * 2setSize  vector
	std::vector<std::vector<osuCrypto::block>> inputSet_block(nParties);

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

			if (j < setSize)
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
			std::vector<osuCrypto::block> p_block = u8vec_to_blocks(p_vec);
			inputSet_block[i].push_back(p_block[0]);
			inputSet_block[i].push_back(p_block[1]);

			// it is safe to erase the first bit (give 2 later still generate a valid point)
			//  p_vec.erase(p_vec.begin());
			//  p_vec.insert(p_vec.begin(), 2);
			//  p.fromBytes(p_vec.data());
		}
	}

	// blocks
	// std::vector<std::vector<osuCrypto::block>> inputSet(nParties,std::vector<osuCrypto::block>(setSize));
	//  for (u64 i = 0; i < nParties; i++) {
	//  	PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, 23987054));
	//  	PRNG prngDiff(_mm_set_epi32(4253465, 3434565, 234423, i));
	//  	for (u64 j = 0; j < setSize; j++) {
	//  		if (j < setSize / 2) {
	//  			inputSet[i][j] = prngSame.get<osuCrypto::block>();
	//  			//std::cout <<"input of " << myIdx << " : " << hex << inputSet[j] << std::endl;
	//  		}
	//  		else {
	//  			inputSet[i][j] = prngDiff.get<osuCrypto::block>();
	//  			//std::cout << "input of " << myIdx << " : " << hex <<inputSet[j] << std::endl;
	//  		}
	//  	}
	//  }

	std::cout << "number of parties: " << nParties << std::endl;
	std::cout << "set size: " << inputSet_u8[0].size() << std::endl;
	// std::cout << "number of blocks: " << inputSet_block[0].size() << std::endl;

	// thread
	std::vector<std::thread> pThrds(nParties);
	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
	{
		pThrds[pIdx] = std::thread([&, pIdx]()
								   {
									//    psu1_final(inputSet_u8[pIdx], inputSet_block[pIdx], nParties, pIdx, setSize, chls);
									// psu_framework_withHash_batched_gc(inputSet_u8[pIdx], inputSet_block[pIdx], nParties, pIdx, setSize, chls);
									   psu2(inputSet_u8[pIdx], inputSet_block[pIdx], nParties, pIdx, setSize, chls); });
	}

	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
		pThrds[pIdx].join();

	// Close channels
	for (u64 i = 0; i < nParties; i++)
	{
		for (u64 j = 0; j < nParties; j++)
		{
			if (i != j)
			{
				chls[i][j].close();
			}
		}
	}

	for (u64 i = 0; i < nParties; i++)
	{
		for (u64 j = 0; j < nParties; j++)
		{
			if (i != j)
			{
				ssns[i][j].stop();
			}
		}
	}

	ios.stop();
}