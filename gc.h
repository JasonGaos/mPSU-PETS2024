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

//#include <libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h>
//#include <libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h>
#include "gbf.h"
#include "utl.h"
#include "eccConvert.h"

#include "emp-sh2pc/emp-sh2pc.h"
#include <emp-tool/emp-tool.h>
using namespace emp;
using namespace std;
using namespace osuCrypto;

// Based on Goubin theorem
vector<emp::Bit> _AgeqB(emp::NetIO *io, int party_id, long long number){
	// return 2 shares of x \geq y
	emp::Integer A(128, number, ALICE); //x
	emp::Integer r(128, -number, BOB); //-y
	emp::Integer u(128, 0, ALICE);
	for(int i = 0; i < 128; i++){
		u = (u&(A^r)^(A&r));
		u = u+u;
	} 
	vector<emp::Integer> z = {((A^u)), ((r))}; //z0 xor z1 = x-y

	return {(z[0]>>127).bits[0],!(z[1]>>127).bits[0]};
}

vector<emp::Bit> _AeqB(emp::NetIO *io, int party_id, long long number){
   if(true){
       Integer a(128, number, ALICE);
       Integer b(128, number, BOB);
       Bit res = (b == a);
       PRG prg;
       bool r_;
       prg.random_data(&r_,sizeof(bool));
       Bit r2(r_);
       Bit r1 = res^r2;
       bool r1_ = r1.reveal<bool>();
       if(party_id==0)
           cout << r_ << " " << r1_ <<endl;
       return {r1, r2};
   }else{
       auto x = _AgeqB(io, party_id, number);
       auto y = _AgeqB(io, party_id, -number);
       // auto z1 = (x[0]&y[0])^(x[0]&y[1]);
       // auto z2 = (x[1]&y[0])^(x[1]&y[1]);
       emp::PRG prg;
       bool r_;
       prg.random_data(&r_,1);
       emp::Bit r(r_);
       //simply doing secand
       emp::Bit r2 = (r^(x[0]&y[1]))^(x[1]&y[0]);
       emp::Bit z1 = r^(x[0]&y[0]);
       emp::Bit z2 = r2^(x[1]&y[1]);
       return {z1,z2};
   }
}


