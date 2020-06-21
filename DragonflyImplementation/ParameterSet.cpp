#include "ParameterSet.h"

int ParameterSet::index = 0;
const ParameterSet ParameterSet::predefined[2] = {
	ParameterSet(),
	{
		CryptograpficMode::FFC,
		NTL::ZZ(NTL::INIT_VAL, "340282366920938463463374607431768223907"),
		NTL::ZZ(NTL::INIT_VAL, "170141183460469231731687303715884111953"),
		40,
		NTL::ZZ_p(),
		NTL::ZZ_p()
	}
};
