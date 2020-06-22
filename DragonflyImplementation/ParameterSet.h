#pragma once

#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>


enum class CryptograpficMode {
	ECC, FFC
};

struct ParameterSet {
	const static ParameterSet predefined[2];
	static int index;

	CryptograpficMode group;

	uint8_t k;
	NTL::ZZ p;
	NTL::ZZ q;
	NTL::ZZ a;
	NTL::ZZ b;
};

