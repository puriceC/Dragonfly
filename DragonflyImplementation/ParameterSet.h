#pragma once

#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>


enum class CryptograpficMode {
	ECC, FFC
};

struct ParameterSet {
	const static ParameterSet predefined[2];
	static int index;

	CryptograpficMode group = CryptograpficMode::FFC;

	NTL::ZZ p = NTL::ZZ(NTL::INIT_VAL, "340282366920938463463374607431768223907");
	NTL::ZZ q = NTL::ZZ(NTL::INIT_VAL, "170141183460469231731687303715884111953");
	uint8_t k = 40;

	NTL::ZZ_p a;
	NTL::ZZ_p b;
};

