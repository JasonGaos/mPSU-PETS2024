#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"
#include "utl.h"
namespace osuCrypto
{

   
    class SimpleTable
    {
    public:

		std::vector<std::vector<block>> items;

        u64 numBins,numHashes;

		u64 getMaxBinSize(){
            u64 maxBinSize = 0;
            for(u64 i = 0;i<items.size();i++){
                if(items[i].size()>maxBinSize){
                    maxBinSize = items[i].size();
                }
            }
            return maxBinSize;
        }

		void init(double scalar, u64 numBalls,u64 num_hash){
            numBins = scalar * numBalls;
            items.resize(numBins);
            numHashes = num_hash;
        }

        void insertItems(block element){
            for(u8 i = 0;i<numHashes;i++){
                u64 address = get_hash(element,i,numBins);
                items[address].push_back(element);
            }

            return;
            
        }
    

    	void padGlobalItems(PRNG& prng,u64 maxNum){

            for (u64 i = 0;i<items.size();i++){
                for (u64 j = items[i].size();j<maxNum;j++){
                    //std::cout<<"1"<<std::endl;
                    items[i].push_back(prng.get<block>());
                }
            }

            return;
        }

        void print_table(){
            for(u64 i = 0;i<items.size();i++){
                if(items[i].size()==0){
                    std::cout<<"-1"<<std::endl;
                }else{
                    print_block(items[i]);
                }
                std::cout<<"-----------------------------------"<<std::endl;
            }
        }

        void clear_table(){
            for(u64 i = 0;i<items.size();i++){
                if(items[i].size()!=0){
					items[i].resize(0);
				}
            }
        }

    };


}
