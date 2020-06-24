#include <iostream>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "Peer.h"
#include "SecureConnection.h"

#define KEY_SIZE 16


SecureConnection::SecureConnection(socket_t mSocket) : mSocket(mSocket), mKey(nullptr), mKeySize(0)
{
    if (mSocket < 0) {
        status = Status::Error;
    } else {
        status = Status::Success;
    }
}
SecureConnection::SecureConnection(const SecureConnection& s) : mSocket(s.mSocket), status(s.status), mKeySize(s.mKeySize)
{
    if (s.mKey != nullptr && s.mKeySize > 0){
        this->mKey = new Byte[mKeySize];
        memcpy(this->mKey, s.mKey, mKeySize);
    }else{
        this->mKey = nullptr;
    }
}
SecureConnection::SecureConnection(SecureConnection&& s)
{
    this->mSocket = s.mSocket;
    this->status = s.status;
    this->mKeySize = s.mKeySize;
    this->mKey = s.mKey;
    s.mKey = nullptr;
}
SecureConnection::SecureConnection(int addressFamily, int type, int protocol) : mKey(nullptr), mKeySize(0)
{
#ifdef _WIN32
    WSADATA WSAData;
    WSAStartup(2, &WSAData);
#endif
    mSocket = socket(addressFamily, type, protocol);
    status = mSocket < 0 ?
        Status::Error : Status::Success;
}
SecureConnection::~SecureConnection()
{
    delete[] mKey;
}

int SecureConnection::Bind(const sockaddr_t* address, socklen_t size)
{
    return bind(mSocket, address, size);
}
int SecureConnection::Listen(int backlog)
{
    return listen(mSocket, backlog);
}

SecureConnection SecureConnection::Accept(sockaddr_t *address, socklen_t *size, const char* password) {
    socket_t peerSocket = accept(mSocket, address, size);
    if (peerSocket < 0) {
        return SecureConnection(INVALID_SOCKET);
    }

    char index;
    recv(peerSocket, &index, 1, 0);
    Peer::selectParameterSet(index);
    Peer peer("Server");
    peer.initiate("Client", password);

    peer.commitExchange();
    uint64_t commitSize = peer.getCommitMessageSize();
    unsigned char* commitBuffer = new Byte[2 * commitSize];
    char control;
    recv(peerSocket, &control, 1, 0);
    if (control != 'c') {
        return SecureConnection(INVALID_SOCKET);
    }
    recv(peerSocket, (char *) commitBuffer, commitSize, 0);
    if (!peer.verifyPeerCommit(commitBuffer)) {
        std::cout << "Commit error" << std::endl;
        return SecureConnection(INVALID_SOCKET);
    }
    recv(peerSocket, &control, 1, 0);
    if (control != 'c') {
        return SecureConnection(INVALID_SOCKET);
    }
    peer.getCommitMessage(commitBuffer+commitSize, commitSize);
    send(peerSocket, (char *) commitBuffer+commitSize, commitSize, 0);

    peer.confirmExchange();
    uint64_t confirmSize = peer.getConfirmMessageSize();
    unsigned char *confirmBuffer = new Byte[2*confirmSize];
    recv(peerSocket, &control, 1, 0);
    if (control != 'c') {
        return SecureConnection(INVALID_SOCKET);
    }
    recv(peerSocket, (char *) confirmBuffer, confirmSize, 0);
    recv(peerSocket, &control, 1, 0);
    if (control != 'c') {
        return SecureConnection(INVALID_SOCKET);
    }
    peer.getConfirmMessage(confirmBuffer+confirmSize, confirmSize);
    send(peerSocket, (char *) confirmBuffer+confirmSize, confirmSize, 0);

    if (!peer.verifyPeerConfirm(confirmBuffer)) {
        std::cout << "Confirm error" << std::endl;
        return SecureConnection(INVALID_SOCKET);
    }
    SecureConnection returnValue = SecureConnection(peerSocket);
    returnValue.mKeySize = peer.getKeySize();
    returnValue.mKey = new Byte[returnValue.mKeySize];
    peer.getKey(returnValue.mKey, returnValue.mKeySize);
    peer.destroy();

    delete[] commitBuffer;
    delete[] confirmBuffer;
    return returnValue;
}

int SecureConnection::Connect(sockaddr_t *address, socklen_t size, const char* password) {
    int returnValue = connect(mSocket, address, size);
    if (returnValue < 0) {
#ifdef _WIN32
        std::cout << "ERROR --->" << WSAGetLastError();
#endif
        return SOCKET_ERROR;
    }
    

    char index = 0;
    send(mSocket, &index, 1, 0);
    Peer::selectParameterSet(index);
    Peer peer("Client");
    peer.initiate("Server", password);
    peer.commitExchange();
    uint64_t commitSize = peer.getCommitMessageSize();
    unsigned char *commitBuffer = new Byte[commitSize];
    peer.getCommitMessage(commitBuffer, commitSize);
    char control = 'c';
    send(mSocket, &control, 1, 0);
    send(mSocket, (char *) commitBuffer, commitSize, 0);
    send(mSocket, &control, 1, 0);
    recv(mSocket, (char *) commitBuffer, commitSize, 0);
    if (!peer.verifyPeerCommit(commitBuffer)) {
        std::cout << "Commit error" << std::endl;
        return SOCKET_ERROR;
    }

    peer.confirmExchange();
    uint64_t confirmSize = peer.getConfirmMessageSize();
    unsigned char *confirmBuffer = new Byte[confirmSize];
    peer.getConfirmMessage(confirmBuffer, confirmSize);
    send(mSocket, &control, 1, 0);
    send(mSocket, (char *) confirmBuffer, confirmSize, 0);
    send(mSocket, &control, 1, 0);
    recv(mSocket, (char *) confirmBuffer, confirmSize, 0);
    if (!peer.verifyPeerConfirm(confirmBuffer)) {
        std::cout << "Confirm error" << std::endl;
        return SOCKET_ERROR;
    }

    mKeySize = peer.getKeySize();
    mKey = new Byte[mKeySize];
    peer.getKey(mKey, mKeySize);
    peer.destroy();
    delete[] commitBuffer;
    delete[] confirmBuffer;
    return returnValue;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 128 bit AES (i.e. a 128 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 128 bit AES (i.e. a 128 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
//*
long SecureConnection::Receive(char* data, size_t size, int flags) {
    if (mKey == nullptr)
        return -1;
    Byte * encryptedData = new Byte[size];

    int received = recv(mSocket, (char*)encryptedData, size, flags);
    int decrypted = 0;
    if (received > 0){
        decrypted = decrypt(encryptedData, received, mKey, (Byte*)"0123456789ABCDEF", (Byte*)data);
        data[decrypted] = '\0';
    }

    delete[] encryptedData;
    return decrypted+1;
}
long SecureConnection::Send(const char* data, size_t size, int flags)
{
    Byte* encryptedData = new Byte[size + mKeySize];

    int encrypted = encrypt((Byte*)data, size, mKey, (Byte*)"0123456789ABCDEF", encryptedData);
    int sent = send(mSocket, (char*)encryptedData, encrypted, flags);

    delete[] encryptedData;
    return sent;
}
/*/
long SecureConnection::Receive(char* data, size_t size, int flags) {
    return recv(mSocket, (char*)data, size, flags);
}
long SecureConnection::Send(const char* data, size_t size, int flags)
{
    return send(mSocket, (char*)data, size, flags);
}
//*/
int SecureConnection::Close()
{
    delete[] mKey;
    mKey = nullptr;
    mKeySize = 0;
    int returnCode = 0;
#ifdef _WIN32
    WSACleanup();
    if (mSocket != INVALID_SOCKET)
        returnCode = closesocket(mSocket);
#elif __unix__
    if (mSocket != INVALID_SOCKET)
        returnCode = close(mSocket);
#endif
    mSocket = INVALID_SOCKET;
    status = Status::Error;
    return returnCode;
}

