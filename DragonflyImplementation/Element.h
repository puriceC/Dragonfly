#pragma once

#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>

using Scalar = NTL::ZZ;

class Element {
public:

	
	Element() = default;
	Element(const Element&) = default;
	Element(Element&&) = default;
	Element(const NTL::ZZ_p& v);
	Element(NTL::ZZ_p&& v);
	Element(const NTL::ZZ_p& _x, const NTL::ZZ_p& _y);
	Element(NTL::ZZ_p&& _x, NTL::ZZ_p&& _y);
	Element(const unsigned char* buffer, int size);

	bool isValid() const;

	Element& operator = (const Element&) = default;
	Element& operator = (Element&&) = default;

	bool operator == (const Element& other) const;

	Element elementOp(const Element& other) const;
	Element scalarOp(const NTL::ZZ& scalar) const;
	Element inverse() const;

	static int size();
	int toBytes(unsigned char* buffer, int size) const;

	void destroy();
private:
	NTL::ZZ_p value;
	NTL::ZZ_p x, y;

	operator const NTL::ZZ_p() const
	{
		return value;
	}
	Element& operator = (const NTL::ZZ_p& value)
	{
		this->value = value;
		return *this;
	}
	bool operator == (const int& value)
	{
		return this->value == NTL::ZZ_p(value);
	}

	Element& operator = (const int& value)
	{
		this->value = NTL::ZZ_p(value);
		return *this;
	}
};
