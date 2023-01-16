#include <iostream>
#include "psu.h"
#include "gbf.h"
#include "gc.h"
#include "ot_mpsu.h"
#include "oprf_mpsu.h"
#include "libOTe/libOTe_Tests/OT_Tests.h"
#include "hash_test.h"

using namespace osuCrypto;

int main(void){

    mpsu_test();
    //rpir_framework_test();
    //ecc_channel_test();
    // oprf_test();
    //gc_test();
    //OtExt_Iknp_Test();
    // ot_test();
    //hash_test();

    return 0;
}