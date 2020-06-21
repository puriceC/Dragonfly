#include "Peer.h"
#include "ParameterSet.h"

using namespace NTL;
using std::string;


void Peer::Hash(byte* result, const byte* buffer, size_t bufferSize)
{
	DeriveKey(result, DIGEST_SIZE, buffer, bufferSize);
}

int lsb(ZZ_p a)
{
	return bit(rep(a), 0);
}
ZZ lgr(ZZ_p a, ZZ p)
{
	return rep(power(a, (p - 1) / 2));
}
ZZ_p getQuadraticResidue()
{
	static ZZ_p qr = ZZ_p::zero();
	while (lgr(qr, ZZ_p::modulus()) != 1);
	{
		qr = random_ZZ_p();
	};
	return qr;
}
ZZ_p getQuadraticNonResidue()
{
	static ZZ_p qnr = ZZ_p::zero();
	while (lgr(qnr, ZZ_p::modulus()) != -1);
	{
		qnr = random_ZZ_p();
	};
	return qnr;
}

bool isQuadraticResidue(ZZ_p val, ZZ p)
{
	ZZ random = RandomBits_ZZ(NumBits(p) + 4);
	ZZ_p r = to_ZZ_p((random % (p - 1)) + 1);
	ZZ_p num = (val * r * r);
	ZZ_p qr = getQuadraticResidue();
	ZZ_p qnr = getQuadraticNonResidue();
	if (lsb(r) == 1) {
		num *= qr;
		if (lgr(num, p) == 1) {
			return true;
		}
	} else {
		num *= qnr;
		if (lgr(num, p) == -1) {
			return true;
		}
	}
	return false;
}

//todo:
ZZ_p squareRoot(ZZ_p x)
{
	return x;
}

bool isValidSeed(ZZ_p seed)
{
	ParameterSet params = ParameterSet::predefined[ParameterSet::index];
	if (params.group == CryptograpficMode::FFC) {
		return rep(power(seed, (params.p - 1) / params.q)) > 1;
	}
	return isQuadraticResidue((power(seed,  3) + params.a * seed + params.b), params.p);
}

void populateBuffer(byte* buffer, long* bufferSize, const string& id, const string& otherId, const string& password)
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

void Peer::HuntingAndPecking() {
	ParameterSet parameters = ParameterSet::predefined[ParameterSet::index];
	bool found = false;
	uint8_t counter = 1;
	const size_t n = NumBytes(ZZ_p::modulus()) + 8;
	ZZ_p seed, savedSeed;
	bool savedBit;
	byte* temp = new byte[n];
	byte base[DIGEST_SIZE];

	byte buffer[512];
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
		ZZ_p y = squareRoot(power(x, 3) + parameters.a * x + parameters.b);
		if (lsb(y) == savedBit) {
			PE = Element(x, y);
		} else {
			PE = Element(x, -y);
		}
	}
}
void Peer::computeSharedSecret() {
	unsigned long numBytes = NumBytes(ZZ_p::modulus());
	byte ss[512];

	Element scalarOperation = PE.scalarOp(peerScalar);
	Element elementOperation = scalarOperation.elementOp(peerElement);
	Element integer = elementOperation.scalarOp(privateNumber);

	integer.toBytes(ss, 512);
	byte buffer[512];
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
	return true;
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
Peer::~Peer()
{
	destroy();
}

void Peer::initiate(const char* otherId, const char* password, int parameterSetIndex)
{
	this->password = string(password);
	this->otherId = string(otherId);
	ParameterSet::index = parameterSetIndex;

	ZZ_p::init(ParameterSet::predefined[ParameterSet::index].p);
	scalarSize = NumBytes(ParameterSet::predefined[ParameterSet::index].q);
	elementSize = Element::size();

    mk = new byte[elementSize];
	memset(mk, 0xFF, elementSize);
	kck = new byte[elementSize];
	memset(kck, 0, elementSize);
	commitMessage = new byte[scalarSize + elementSize];
	memset(commitMessage, 0, scalarSize + elementSize);
	confirmMessage = new byte[DIGEST_SIZE];
	memset(confirmMessage, 0, DIGEST_SIZE);


	HuntingAndPecking();
}
void Peer::commitExchange() {
	ZZ q = ParameterSet::predefined[ParameterSet::index].q;
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
void Peer::confirmExchange() {
	computeSharedSecret();

	byte buffer[1024];
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


	byte message[DIGEST_SIZE];
	Hash(message, buffer, index);
	memcpy(confirmMessage, message, DIGEST_SIZE);
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

void Peer::getCommitMessage(byte* buffer, size_t bufferSize) const
{
	if (commitMessage != nullptr && bufferSize >= getCommitMessageSize()) {
		memcpy(buffer, commitMessage, getCommitMessageSize());
	}
}
void Peer::getConfirmMessage(byte* buffer, size_t bufferSize) const
{
	if (confirmMessage != nullptr && bufferSize >= getConfirmMessageSize()) {
		memcpy(buffer, confirmMessage, getConfirmMessageSize());
	}
}
void Peer::getKey(byte* buffer, size_t bufferSize) const
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
bool Peer::verifyPeerCommit(const byte* peerCommitMessage)
{
	if (peerCommitMessage == nullptr) {
		return false;
	}
	peerScalar = ZZFromBytes(peerCommitMessage, scalarSize);
	peerElement = Element(peerCommitMessage + scalarSize, elementSize);
	return commitCheck();
}
bool Peer::verifyPeerConfirm(const byte* peerConfirmMessage)
{
	if (peerConfirmMessage == nullptr)
		return false;

	byte buffer[1024];

	int index = 0;

	memcpy(buffer, kck, elementSize);
	index += elementSize;

	BytesFromZZ(buffer + index, peerScalar, scalarSize);
	index += scalarSize;

	BytesFromZZ(buffer + index, publicScalar, scalarSize);
	index += scalarSize;
	//todo check
	//	if (rep(peerElement) <= 1) 
	//	if (rep(peerElement) >= parameters.p - 1) 
	//	if (peerElement.scalarOp(parameters.q) != 1) 
	peerElement.toBytes(buffer + index, elementSize);
	index += elementSize;

	publicElement.toBytes(buffer + index, elementSize);
	index += elementSize;

	memcpy(buffer + index, otherId.c_str(), otherId.size());
	index += otherId.size();

	byte message[DIGEST_SIZE];
	Hash(message, buffer, index);
	return memcmp(message, peerConfirmMessage, DIGEST_SIZE) == 0;
}

void copyString(byte** s, const byte* other, size_t size){
	if (other != nullptr){
		*s = new byte[size];
		memcpy(*s, other, size);
	}else{
		*s = nullptr;
	}
}

Peer::Peer(const Peer &p) {
	elementSize = p.elementSize;
	scalarSize = p.scalarSize;
	copyString(&kck, p.kck, getKeySize());
	copyString(&mk, p.mk, getKeySize());
	copyString(&commitMessage, p.commitMessage, getCommitMessageSize());
	copyString(&confirmMessage, p.confirmMessage, getConfirmMessageSize());
}

Peer::Peer(Peer &&p) noexcept {
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




