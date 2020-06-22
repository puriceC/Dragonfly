#include <string>
#include <iostream>
#include <string.h>

#include "Peer.h"
#include "SecureConnection.h"

int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
            unsigned char* iv, unsigned char* plaintext);
int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
            unsigned char* iv, unsigned char* ciphertext);

#define PORT 57157

using namespace std;
using namespace NTL;
using NTL::ZZ;


int main()
{

    /*
    SecureConnection sock = SecureConnection(AF_INET, SOCK_STREAM, 0);
    if (sock.status == SecureConnection::Status::Error) {
        std::cout << "\n Socket creation error \n" << endl;
        return -1;
    }

    struct sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    int port;
    //std::cin >> port;
    serverAddress.sin_port = htons(PORT);
    PCWSTR str = L"192.168.0.119";
    InetPton(AF_INET,str, &serverAddress.sin_addr);

    std::cout << "\nConnecting... \n" << endl;
    char pass[62] = "123";
    //std::cin >> pass;
    if (sock.Connect((struct sockaddr*) & serverAddress, sizeof(serverAddress), pass) < 0) {
        std::cout << "\nConnection Failed \n" << endl;
        return -1;
    }
    const char message[] = "This will likely fail as it uses more blocks";
    sock.Send(message, sizeof(message), 0);
    std::cout << "\nSmall success!\n" << endl;
    sock.Close();

/*/
/*

    SecureConnection server(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serverAddr, clientAddr;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    server.Bind((sockaddr_t*)&serverAddr, sizeof(serverAddr));
    server.Listen(0);
    cout << "Listening for incoming connections..." << endl;
    socklen_t clientAddrSize = sizeof(clientAddr);
    SecureConnection client = server.Accept((sockaddr_t*)&clientAddr, &clientAddrSize, "");
    if (client.status == SecureConnection::Status::Error) {
        return -1;
    }
    cout << "Client connected!" << endl;
    char message[64];
    int received = client.Receive(message, 64, 0);
    cout << received << " bytes received:\n" << message << endl;
    //*/
    //*/
    int x; std::cin >> x;
    for (int i = 0; i < x; i++) {
        Peer::selectParameterSet(1);
        Peer alice("alice_id"), bob("bob_id");
        alice.initiate("bob_id", "1234");
        bob.initiate("alice_id", "1234");

        byte buffer[512];
        alice.commitExchange();
        bob.commitExchange();
        alice.getCommitMessage(buffer, 256);
        bob.getCommitMessage(buffer + 256, 256);

        if (alice.verifyPeerCommit(buffer + 256) &&
            bob.verifyPeerCommit(buffer)) {
            //std::cout << "Commit successful" << std::endl;
        } else {
            std::cerr << "Commit error" << std::endl;
            return -1;
        }
        alice.confirmExchange();
        bob.confirmExchange();
        alice.getConfirmMessage(buffer, 256);
        bob.getConfirmMessage(buffer + 256, 256);

        if (alice.verifyPeerConfirm(buffer + 256) &&
            bob.verifyPeerConfirm(buffer)) {
            //std::cout << "Confirm successful" << std::endl;
        } else {
            std::cerr << "Confirm error" << std::endl;
            return -1;
        }
        alice.getKey(buffer, 256);
        bob.getKey(buffer + 256, 256);
        if (memcmp(buffer, buffer + 256, alice.getKeySize()) == 0) {
            std::cout << "Key:\n" << std::string((char*)buffer, alice.getKeySize()) << std::endl;
        } else {
            std::cerr << "Keys differ" << std::endl;
            return -1;
        }
        alice.destroy();
        bob.destroy();
    }
    std::cout << "success";
    return 0;
    //*/
}
