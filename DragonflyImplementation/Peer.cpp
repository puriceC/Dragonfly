#include "Peer.h"
#include <openssl\sha.h>
#include "ParameterSet.h"

using namespace NTL;
using std::string;


void copyString(Byte** s, const Byte* other, size_t size)
{
	if (other != nullptr) {
		*s = new Byte[size];
		memcpy(*s, other, size);
	} else {
		*s = nullptr;
	}
}

inline int lsb(const ZZ_p& a)
{
	return bit(rep(a), 0);
}
inline ZZ lgr(const ZZ_p& a)
{
	ZZ_p result(power(a, (ZZ_p::modulus() - 1) / 2));
	if (result == 1) return ZZ(1);
	if (result == -1)return ZZ(-1);
	return ZZ(0);
} 
ZZ_p getQuadraticResidue()
{
	static ZZ_p qr(ZZ_p::zero());
	while (lgr(qr) != 1) {
		qr = random_ZZ_p();
	};
	return qr;
}
ZZ_p getQuadraticNonResidue()
{
	static ZZ_p qnr(ZZ_p::zero());
	while (lgr(qnr) != -1) {
		qnr = random_ZZ_p();
	};
	return qnr;
}

bool isQuadraticResidue(const ZZ_p& val)
{
	return lgr(val) == 1;
	ZZ p(ZZ_p::modulus());
	ZZ random(RandomBits_ZZ(NumBits(p) + 4));
	ZZ_p r(to_ZZ_p((random % (p - 1)) + 1));
	ZZ_p num(val * r * r);
	ZZ_p qr(getQuadraticResidue());
	ZZ_p qnr(getQuadraticNonResidue());
	if (lsb(r) == 1) {
		if (lgr(num * qr) == 1) {
			return true;
		}
	} else {
		if (lgr(num * qnr) == -1) {
			return true;
		}
	}
	return false;
}

ZZ_p squareRoot(const ZZ_p& n)
{
	if (lgr(n) != 1) {
		std::cerr << "not a square (mod p)";
		return ZZ_p();
	}
	ZZ p(ZZ_p::modulus());
	ZZ q(p - 1);
	ZZ_p z(to_ZZ_p(2));
	ZZ_p c, r, t;
	int m;

	int ss(0);
	while (bit(q, ss) == 0) {
		ss++;
	}
	q >>= ss;

	if (ss == 1) {
		return power(n, (p + 1) / 4);
	}

	while (lgr(z) != -1) {
		z++;
	}

	c = power(z, q);
	r = power(n, (q + 1) / 2);
	t = power(n, q);
	m = ss;

	while (true) {
		int i(0);
		ZZ_p zz(t);
		ZZ_p b(c);
		int e;
		if (t == 1) {
			return r;
		}
		while (zz != 1 && i < (m - 1)) {
			zz = zz * zz;
			i++;
		}
		e = m - i - 1;
		while (e > 0) {
			b = b * b;
			e--;
		}
		r = r * b;
		c = b * b;
		t = t * c;
		m = i;
	}
}

bool isValidSeed(const ZZ_p& seed)
{
	const ParameterSet& params = ParameterSet::predefined[ParameterSet::index];
	if (params.group == CryptograpficMode::FFC) {
		return rep(power(seed, (params.p - 1) / params.q)) > 1;
	}
	return isQuadraticResidue((power(seed, 3) + to_ZZ_p(params.a) * seed + to_ZZ_p(params.b)));
}

void populateBuffer(Byte* buffer, long* bufferSize, const string& id, const string& otherId, const string& password)
{
	long idOffset = 0;
	long otherIdOffset = 0;
	long passwordOffset = id.size() + otherId.size();
	*bufferSize = passwordOffset + password.size() + 1;
	if (id.compare(otherId) > 0)
		idOffset = otherId.size();
	else
		otherIdOffset = id.size();
	memcpy(buffer + idOffset, id.data(), id.size());
	memcpy(buffer + otherIdOffset, otherId.data(), otherId.size());
	memcpy(buffer + passwordOffset, password.data(), password.size());
}


Peer::Peer(const char* id) : id(id)
{
	elementSize = 0;
	scalarSize = 0;
	kck = nullptr;
	mk = nullptr;
	commitMessage = nullptr;
	confirmMessage = nullptr;
}
Peer::Peer(const Peer& p)
{
	elementSize = p.elementSize;
	scalarSize = p.scalarSize;
	copyString(&kck, p.kck, getKeySize());
	copyString(&mk, p.mk, getKeySize());
	copyString(&commitMessage, p.commitMessage, getCommitMessageSize());
	copyString(&confirmMessage, p.confirmMessage, getConfirmMessageSize());
}
Peer::Peer(Peer&& p) noexcept
{
	elementSize = p.elementSize;
	scalarSize = p.scalarSize;
	kck = p.kck;
	p.kck = nullptr;
	mk = p.mk;
	p.mk = nullptr;
	commitMessage = p.commitMessage;
	p.commitMessage = nullptr;
	confirmMessage = p.confirmMessage;
	p.confirmMessage = nullptr;
}
Peer::~Peer()
{
	destroy();
}


void Peer::selectParameterSet(int index)
{
	ParameterSet::index = index;
}

void Peer::initiate(const char* otherId, const char* password)
{
	this->password = string(password);
	this->otherId = string(otherId);

	ZZ_p::init(ParameterSet::predefined[ParameterSet::index].p);
	scalarSize = NumBytes(ParameterSet::predefined[ParameterSet::index].q);
	elementSize = Element::size();

	mk = new Byte[elementSize];
	memset(mk, 0xFF, elementSize);
	kck = new Byte[elementSize];
	memset(kck, 0, elementSize);
	commitMessage = new Byte[scalarSize + elementSize];
	memset(commitMessage, 0, scalarSize + elementSize);
	confirmMessage = new Byte[DIGEST_SIZE];
	memset(confirmMessage, 0, DIGEST_SIZE);


	HuntingAndPecking();
}
void Peer::destroy()
{
	privateNumber.kill();
	publicScalar.kill();
	peerScalar.kill();
	PE.destroy();
	publicElement.destroy();
	peerElement.destroy();

	if (kck != nullptr)
		memset(kck, 0, elementSize);
	delete kck;
	kck = nullptr;

	if (mk != nullptr)
		memset(mk, 0, elementSize);
	delete mk;
	mk = nullptr;

	delete commitMessage;
	commitMessage = nullptr;

	delete confirmMessage;
	confirmMessage = nullptr;
}
void Peer::commitExchange()
{
	const ZZ& q = ParameterSet::predefined[ParameterSet::index].q;
	Scalar maskNumber;
	do {
		do {
			maskNumber = RandomBits_ZZ(scalarSize * 8);
		} while (maskNumber >= q);
		do {
			privateNumber = RandomBits_ZZ(scalarSize * 8);
		} while (privateNumber >= q);
		publicScalar = AddMod(maskNumber, privateNumber, q);
	} while (publicScalar <= 2);

	publicElement = PE.scalarOp(maskNumber).inverse();
	maskNumber.kill();
	BytesFromZZ(commitMessage, publicScalar, scalarSize);
	publicElement.toBytes(commitMessage + scalarSize, elementSize);
}
void Peer::confirmExchange()
{
	computeSharedSecret();

	Byte buffer[1024];
	int index = 0;

	memcpy(buffer, kck, elementSize);
	index += elementSize;

	BytesFromZZ(buffer + index, publicScalar, scalarSize);
	index += scalarSize;

	BytesFromZZ(buffer + index, peerScalar, scalarSize);
	index += scalarSize;

	publicElement.toBytes(buffer + index, elementSize);
	index += elementSize;

	peerElement.toBytes(buffer + index, elementSize);
	index += elementSize;

	memcpy(buffer + index, id.c_str(), id.size());
	index += id.size();


	Byte message[DIGEST_SIZE];
	Hash(message, buffer, index);
	memcpy(confirmMessage, message, DIGEST_SIZE);
}

void Peer::getCommitMessage(Byte* buffer, size_t bufferSize) const
{
	if (commitMessage != nullptr && bufferSize >= getCommitMessageSize()) {
		memcpy(buffer, commitMessage, getCommitMessageSize());
	}
}
void Peer::getConfirmMessage(Byte* buffer, size_t bufferSize) const
{
	if (confirmMessage != nullptr && bufferSize >= getConfirmMessageSize()) {
		memcpy(buffer, confirmMessage, getConfirmMessageSize());
	}
}
void Peer::getKey(Byte* buffer, size_t bufferSize) const
{
	if (mk != nullptr && bufferSize >= getKeySize()) {
		memcpy(buffer, mk, getKeySize());
	}
}

bool Peer::verifyPeerCommit(const Scalar& peerScalar, const Element& peerElement)
{
	this->peerScalar = peerScalar;
	this->peerElement = peerElement;
	return commitCheck();
}
bool Peer::verifyPeerCommit(const Byte* peerCommitMessage)
{
	if (peerCommitMessage == nullptr) {
		return false;
	}
	peerScalar = ZZFromBytes(peerCommitMessage, scalarSize);
	peerElement = Element(peerCommitMessage + scalarSize, elementSize);
	return commitCheck();
}
bool Peer::verifyPeerConfirm(const Byte* peerConfirmMessage)
{
	if (peerConfirmMessage == nullptr)
		return false;

	Byte buffer[1024];

	int index = 0;

	memcpy(buffer, kck, elementSize);
	index += elementSize;

	BytesFromZZ(buffer + index, peerScalar, scalarSize);
	index += scalarSize;

	BytesFromZZ(buffer + index, publicScalar, scalarSize);
	index += scalarSize;

	peerElement.toBytes(buffer + index, elementSize);
	index += elementSize;

	publicElement.toBytes(buffer + index, elementSize);
	index += elementSize;

	memcpy(buffer + index, otherId.c_str(), otherId.size());
	index += otherId.size();

	Byte message[DIGEST_SIZE];
	Hash(message, buffer, index);
	return memcmp(message, peerConfirmMessage, DIGEST_SIZE) == 0;
}


void Peer::Hash(Byte* result, const Byte* buffer, size_t bufferSize)
{
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, buffer, bufferSize);
	SHA256_Final(result, &ctx);
}
void Peer::HuntingAndPecking()
{
	const ParameterSet& parameters = ParameterSet::predefined[ParameterSet::index];
	bool found = false;
	uint8_t counter = 1;
	const size_t n = NumBytes(ZZ_p::modulus()) + 8;
	ZZ_p seed, savedSeed;
	bool savedBit;
	Byte* temp = new Byte[n];
	Byte base[DIGEST_SIZE];

	Byte buffer[512];
	long bufferSize;
	populateBuffer(buffer, &bufferSize, id, otherId, password);

	do {
		buffer[bufferSize - 1] = counter;
		Hash(base, buffer, bufferSize);
		DeriveKey(temp, n, base, DIGEST_SIZE);
		seed = to_ZZ_p((ZZFromBytes(temp, n) % (ZZ_p::modulus() - 1)) + 1);

		if (isValidSeed(seed)) {
			if (!found) {
				savedSeed = seed;
				savedBit = base[0] & 0x01;
				found = true;
			}
		}
		counter++;
	} while (!found || (counter <= parameters.k));
	delete[] temp;

	if (parameters.group == CryptograpficMode::FFC) {
		PE = Element(power(savedSeed, (parameters.p - 1) / parameters.q));
	} else {
		ZZ_p x = savedSeed;
		ZZ_p y = squareRoot(power(x, 3) + to_ZZ_p(parameters.a) * x + to_ZZ_p(parameters.b));
		if (lsb(y) == savedBit) {
			PE = Element(x, y);
		} else {
			PE = Element(x, -y);
		}
		Byte buf[128];
		PE.toBytes(buf, 128);
	}
}
void Peer::computeSharedSecret()
{
	unsigned long numBytes = NumBytes(ZZ_p::modulus());
	Byte ss[512];

	Element scalarOperation = PE.scalarOp(peerScalar);
	Element elementOperation = scalarOperation.elementOp(peerElement);
	Element integer = elementOperation.scalarOp(privateNumber);

	integer.toBytes(ss, 512);
	Byte buffer[512];
	DeriveKey(buffer, numBytes * 2, ss, integer.size());
	memcpy(kck, buffer, numBytes);
	memcpy(mk, buffer + numBytes, numBytes);
}
bool Peer::commitCheck() const
{
	if (publicScalar == peerScalar) return false;
	if (publicElement == peerElement) return false;
	if (peerScalar <= 1) return false;
	if (peerScalar >= ParameterSet::predefined[ParameterSet::index].q) return false;
	if (!peerElement.isValid() || peerElement == Element()) return false;
	return true;
}
