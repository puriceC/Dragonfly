#pragma once

#include <string>
#include "Element.h"


using byte = unsigned char;

class Peer {
public:
	Peer(const char* id);
	Peer(const Peer&);
	Peer(Peer&&) noexcept;
	~Peer();
	static void selectParameterSet(int index);
	void initiate(const char* otherId, const char* password);
	void destroy();
	void commitExchange();
	void confirmExchange();

	void getCommitMessage(byte* buffer, size_t bufferSize) const;
	void getConfirmMessage(byte* buffer, size_t bufferSize) const;
	void getKey(byte* buffer, size_t bufferSize) const;

	bool verifyPeerCommit(const Scalar& peerScalar, const Element& peerElement);
	bool verifyPeerCommit(const byte* peerCommitMessage);
	bool verifyPeerConfirm(const byte* peerConfirmMessage);

	inline size_t getCommitMessageSize() const
	{
		return scalarSize + elementSize;
	};
	inline size_t getConfirmMessageSize() const
	{
		return DIGEST_SIZE;
	};
	inline size_t getKeySize() const
	{
		return elementSize;
	};
	inline Scalar getScalar() const
	{
		return publicScalar;
	};
	inline Element getElement() const
	{
		return publicElement;
	};
private:
	static const size_t DIGEST_SIZE = 32;
	static int parameterSetIndex;
	const std::string id;
	std::string otherId;
	std::string password;
	size_t scalarSize;
	size_t elementSize;
	Scalar privateNumber;
	Scalar publicScalar;
	Scalar peerScalar;
	Element PE;
	Element publicElement;
	Element peerElement;
	byte* kck;
	byte* mk;
	byte* commitMessage;
	byte* confirmMessage;

	static void Hash(byte* result, const byte* buffer, size_t bufferSize);
	void HuntingAndPecking();
	void computeSharedSecret();
	bool commitCheck() const;
};

