#include <iostream>
#include "psu.h"
#include "gbf.h"
#include "gc.h"
#include "ot_mpsu.h"
#include "oprf_mpsu.h"
#include "libOTe/libOTe_Tests/OT_Tests.h"

using namespace osuCrypto;

int main(void){

    mpsu_test();
    //rpir_framework_test();
    //ecc_channel_test();
    //oprf_test();
    //gc_test();
    //OtExt_Iknp_Test();
    //ot_test();
    //tests_libOTe::DotExt_Iknp_Test();

    return 0;
}