#include "emp-sh2pc/emp-sh2pc.h"
#include<emp-tool/emp-tool.h>
using namespace emp;
using namespace std;

// Based on Goubin theorem
vector<Bit> _AgeqB(NetIO *io, int party_id, long long number){
	// return 2 shares of x \geq y
	Integer A(128, number, ALICE); //x
	Integer r(128, -number, BOB); //-y
	Integer u(128, 0, ALICE);
	for(int i = 0; i < 128; i++){
		u = (u&(A^r)^(A&r));
		u = u+u;
	} 
	vector<Integer> z = {((A^u)), ((r))}; //z0 xor z1 = x-y

	return {(z[0]>>127).bits[0],!(z[1]>>127).bits[0]};
}

vector<Bit> _AeqB(NetIO *io, int party_id, long long number){
	auto x = _AgeqB(io, party_id, number);
	auto y = _AgeqB(io, party_id, -number);
	// auto z1 = (x[0]&y[0])^(x[0]&y[1]);
	// auto z2 = (x[1]&y[0])^(x[1]&y[1]);
	PRG prg;
	bool r_;
	prg.random_data(&r_,1);
	Bit r(r_);
	//simply doing secand
	Bit r2 = (r^(x[0]&y[1]))^(x[1]&y[0]);
	Bit z1 = r^(x[0]&y[0]);
	Bit z2 = r2^(x[1]&y[1]);
	return {z1,z2};
}

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	long long num = 20;
	if(argc > 3)
		num = atoll(argv[3]);
	NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);
	setup_semi_honest(io, party);
	auto z = _AeqB(io,party, num);
	bool bS = z[0].reveal<bool>();
	bool bR = z[1].reveal<bool>();
	cout << "bs "<<bS <<endl;
	cout << "br "<<bR <<endl;

	delete io;
	if (bS^bR){
		cout << "Alice = Bob"<<endl;
	}else{
		cout << "Alice =/= Bob" << endl;
	}
}