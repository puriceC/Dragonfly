#include <string>
#include <iostream>
#include <string.h>
#include <time.h>

#include "Peer.h"
#include "SecureSocket.h"


#define PORT 57157

using namespace std;
using namespace NTL;


int main()
{

    /*
    SecureSocket sock = SecureSocket(AF_INET, SOCK_STREAM, 0);
    if (sock.status == SecureSocket::Status::Error) {
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
    if (sock.connect((struct sockaddr*) & serverAddress, sizeof(serverAddress), pass) < 0) {
        std::cout << "\nConnection Failed \n" << endl;
        return -1;
    }
    const char message[] = "This will likely fail as it uses more blocks";
    sock.send(message, sizeof(message), 0);
    std::cout << "\nSmall success!\n" << endl;
    sock.close();

/*/
/*

    SecureSocket server(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serverAddr, clientAddr;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    server.bind((sockaddr_t*)&serverAddr, sizeof(serverAddr));
    server.listen(0);
    cout << "Listening for incoming connections..." << endl;
    socklen_t clientAddrSize = sizeof(clientAddr);
    SecureSocket client = server.accept((sockaddr_t*)&clientAddr, &clientAddrSize, "");
    if (client.status == SecureSocket::Status::Error) {
        return -1;
    }
    cout << "Client connected!" << endl;
    char message[64];
    int received = client.receive(message, 64, 0);
    cout << received << " bytes received:\n" << message << endl;
    //*/
    //*/



        Byte buffer[512];
    int x; std::cin >> x;
    for (int i = 0; i < x; i++) {

        clock_t start = clock(), diff;

        Peer::selectParameterSet(0);
        Peer alice("alice_id"), bob("bob_id");
        alice.initiate("bob_id", "1234");
        bob.initiate("alice_id", "1234");

        alice.commitExchange();
        bob.commitExchange();
        alice.getCommitMessage(buffer, 256);
        bob.getCommitMessage(buffer + 256, 256);

        if (alice.verifyPeerCommit(buffer + 256) &&
            bob.verifyPeerCommit(buffer)) {
            //std::cout << "Commit successful" << std::endl;
        } else {
            std::cerr << "Commit error" << std::endl;
            continue;
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
            continue;
        }
        alice.getKey(buffer, 256);
        bob.getKey(buffer + 256, 256);
        if (memcmp(buffer, buffer + 256, alice.getKeySize()) == 0) {
            //std::cout << "Key:\n" << std::string((char*)buffer, alice.getKeySize()) << std::endl;
        } else {
            std::cerr << "Keys differ" << std::endl;
            continue;
        }
        alice.destroy();
        bob.destroy();


        diff = clock() - start;

        int msec = diff * 1000 / CLOCKS_PER_SEC;
        printf("Time taken %d seconds %d milliseconds\n", msec / 1000, msec % 1000);
    }
    std::cout << "finished";
    return 0;
    //*/
}
