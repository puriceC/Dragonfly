#include "Element.h"
#include "ParameterSet.h"

using namespace NTL;

using byte = unsigned char;

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
	int modulusSize = NumBytes(ZZ_p::modulus());
	if (ParameterSet::predefined[ParameterSet::index].group == CryptograpficMode::FFC) {
		if (modulusSize <= size) {
			value = to_ZZ_p(ZZFromBytes(buffer, modulusSize));
		}
	} else {
		if (2 * modulusSize <= size) {
			x = to_ZZ_p(ZZFromBytes(buffer, modulusSize));
			y = to_ZZ_p(ZZFromBytes(buffer + modulusSize, modulusSize));
		}
	}
}

bool Element::operator==(const Element& other) const
{
	if (ParameterSet::predefined[ParameterSet::index].group == CryptograpficMode::FFC) {
		return this->value == other.value;
	}
	return (x == other.x && y == other.y);
}

Element Element::elementOp(const Element& other) const
{
	if (ParameterSet::predefined[ParameterSet::index].group == CryptograpficMode::FFC) {
		return this->value * other.value;
	}
	if (this->x == 0 && this->y == 0) {
		return other;
	}
	if (other.x == 0 && other.y == 0) {
		return *this;
	}
	if (this->x == other.x && this->y == -other.y) {
		return Element(ZZ_p(0), ZZ_p(0));
	}
	ZZ_p dydx;
	if (this->x == other.x && this->y == other.y) {
		dydx = (3 * power(this->x, 2) + ParameterSet::predefined[ParameterSet::index].a) * inv(2 * this->y);
	} else {
		dydx = (other.y - this->y) * inv(other.x - this->x);
	}
	ZZ_p x = power(dydx, 2) - this->x - other.x;
	return Element(x, dydx * (this->x - x) - this->y);
}

Element Element::scalarOp(const ZZ& scalar) const
{
	if (ParameterSet::predefined[ParameterSet::index].group == CryptograpficMode::FFC) {
		return power(this->value, scalar);
	}
}

Element Element::inverse() const
{
	if (ParameterSet::predefined[ParameterSet::index].group == CryptograpficMode::FFC) {
		return inv(value);
	}
	return Element(x, -y);
}

int Element::size()
{
	if (ParameterSet::predefined[ParameterSet::index].group == CryptograpficMode::FFC) {
		return NumBytes(ZZ_p::modulus());
	}
	return 2 * NumBytes(ZZ_p::modulus());
}

int Element::toBytes(unsigned char* buffer, int size) const
{
	int modulusSize = NumBytes(ZZ_p::modulus());
	if (ParameterSet::predefined[ParameterSet::index].group == CryptograpficMode::FFC) {
		if (size < modulusSize)
			return -1;
		BytesFromZZ(buffer, rep(value), modulusSize);
		return modulusSize;
	} else {
		if (size < 2 * modulusSize)
			return -1;
		BytesFromZZ(buffer, rep(x), modulusSize);
		BytesFromZZ(buffer + modulusSize, rep(y), modulusSize);
		return 2 * modulusSize;
	}
}

void Element::destroy()
{
	value = 0;
	x = 0;
	y = 0;
}
