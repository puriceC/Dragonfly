#include "Element.h"

using namespace NTL;

using byte = unsigned char;

Element::GroupType Element::groupType = Element::GroupType::FFC;

Element::Element(const ZZ_p& v)
	: value(v)
{}
Element::Element(ZZ_p&& v)
	: value(std::move(v))
{}
Element::Element(const ZZ_p& _x, const ZZ_p& _y)
	: x(_x), y(_y)
{}
Element::Element(ZZ_p&& _x, ZZ_p&& _y)
	: x(std::move(_x)), y(std::move(_y))
{}

Element::Element(const unsigned char* buffer, int size)
{
	value = to_ZZ_p(ZZFromBytes(buffer, size));
}

bool Element::operator==(const Element& other) const
{
	if (groupType == GroupType::FFC) {
		return this->value == other.value;
	}
	return (x == other.x && y == other.y);
}

Element Element::elementOp(const Element& other) const
{
	if (groupType == GroupType::FFC) {
		return this->value * other.value;
	}
}

Element Element::scalarOp(const ZZ& scalar) const
{
	if (groupType == GroupType::FFC) {
		return power(this->value, scalar);
	}
}

Element Element::inverse() const
{
	if (groupType == GroupType::FFC) {
		return inv(value);
	}
	return Element(x, -y);
}

int Element::size() const
{
	if (groupType == GroupType::FFC) {
		return NumBytes(ZZ_p::modulus());
	}
	return 2 * NumBytes(ZZ_p::modulus());
}

void Element::toBytes(unsigned char* buffer, int size) const
{
	int modulusSize = NumBytes(ZZ_p::modulus());
	if (groupType == GroupType::FFC) {
		if (size < modulusSize)
			return;
		BytesFromZZ(buffer, rep(value), modulusSize);
	} else {
		if (size < 2 * modulusSize)
			return;
		BytesFromZZ(buffer, rep(x), modulusSize);
		BytesFromZZ(buffer + modulusSize, rep(y), modulusSize);
	}
}

void Element::destroy()
{
	value = 0;
	x = 0;
	y = 0;
}