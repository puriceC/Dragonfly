#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <Ws2tcpip.h>
using socket_t = SOCKET;
using sockaddr_in_t = SOCKADDR_IN;
using sockaddr_t = SOCKADDR;
using socklen_t = int;
#elif __unix__
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
using socket_t = int;
using sockaddr_t = sockaddr;
using sockaddr_in_t = sockaddr_in;
static const socket_t INVALID_SOCKET = -1;
static const int SOCKET_ERROR = -1;
#endif

class SecureSocket {
public:
    enum class Status{Success = 0, Error = -1};

    SecureSocket(int addressFamily, int type, int protocol);
    SecureSocket(const SecureSocket& s);
    SecureSocket(SecureSocket&& s);
    ~SecureSocket();
    
    int bind(const sockaddr_t* address, socklen_t size);
    int listen(int);
    SecureSocket accept(sockaddr_t* address, socklen_t* size, const char* password);
    int connect(sockaddr_t* address, socklen_t size, const char* password);
    long receive(char* buffer, size_t size, int flags);
    long send(const char*, size_t size, int flags);
    int close();

    Status status;
private:
    socket_t mSocket;
    unsigned char* mKey;
    size_t mKeySize;
    SecureSocket(socket_t socket);
};

