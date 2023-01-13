#include "iostream"
#include "simpletable.h"
#include "cuckootable.h"
#include "cryptoTools/Crypto/PRNG.h"


using namespace osuCrypto;

inline void hash_test(){
    //gerate the set
    PRNG set_gen(_mm_set_epi32(4253465, 3434565, 234435, 8888));
    u64 setSize = 1<<21;
    std::vector<osuCrypto::block> input;
    for(u64 i = 0;i<setSize;i++){
        input.push_back(set_gen.get<osuCrypto::block>());
    }

    //print_block(input);

    //simple table
    SimpleTable simple;
    simple.init(1.27,setSize/2,3);

    for(u64 i = 0;i<setSize;i++){
        simple.insertItems(input[i]);
    }

    std::cout<<"max bin size: "<<simple.getMaxBinSize()<<std::endl;
    //simple.padGlobalItems(set_gen,3);

    // for(u64 i = 0;i<simple.items.size();i++){
    //     if(simple.items[i].size()==0){
    //         std::cout<<"-1"<<std::endl;
    //     }else{
    //         std::cout<<"bin "<<i<<std::endl;
    //         print_block(simple.items[i]);
    //     }
    //     std::cout<<"-----------------------------------"<<std::endl;
    // }

    std::cout<<"----------------CUCKOO TABLE-------------------"<<std::endl;

    
    CuckooTable cuckoo;
    cuckoo.init(1.27,setSize,3);
    for(u64 i = 0;i<setSize;i++){
        cuckoo.insertItem(input[i],i);
    }


    std::cout<<"num of stash: "<<cuckoo.numStash<<std::endl;

}