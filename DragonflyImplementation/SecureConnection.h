#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <Ws2tcpip.h>
using socket_t = SOCKET;
using sockaddr_in = SOCKADDR_IN;
using sockaddr_t = SOCKADDR;
using socklen_t = int;
#elif __unix__
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
using socket_t = int;
using sockaddr_t = sockaddr;
static const socket_t INVALID_SOCKET = -1;
static const int SOCKET_ERROR = -1;
#endif

class SecureConnection {
public:
    enum class Status{Success = 0, Error = -1};

    SecureConnection(int addressFamily, int type, int protocol);
    SecureConnection(const SecureConnection& s);
    SecureConnection(SecureConnection&& s);
    ~SecureConnection();
    
    int Bind(const sockaddr_t* address, socklen_t size);
    int Listen(int);
    SecureConnection Accept(sockaddr_t* address, socklen_t* size, const char* password);
    int Connect(sockaddr_t* address, socklen_t size, const char* password);
    long Receive(char* buffer, size_t size, int flags);
    long Send(const char*, size_t size, int flags);
    int Close();

    Status status;
private:
    socket_t mSocket;
    unsigned char* mKey;
    size_t mKeySize;
    SecureConnection(socket_t socket);
};

