#include <string>
#include <iostream>
#include <string.h>
#include <time.h>

#include "Peer.h"
#include "SecureSocket.h"


using namespace std;


Byte buffer1[512];
Byte* buffer2 = buffer1 + 256;





void scenariu1()
{
    Peer::selectParameterSet(0);
    Peer alice("Alice"), bob("Bob");
    alice.initiate("Bob", "1234");
    bob.initiate("Alice", "1234");

    alice.commitExchange();
    bob.commitExchange();
    alice.getCommitMessage(buffer1, 256);
    bob.getCommitMessage(buffer2, 256);

    if (!alice.verifyPeerCommit(buffer2) || !bob.verifyPeerCommit(buffer1)) {
        std::cerr << "Commit error" << std::endl;
        return;
    }
    alice.confirmExchange();
    bob.confirmExchange();
    alice.getConfirmMessage(buffer1, 256);
    bob.getConfirmMessage(buffer2, 256);

    if (!alice.verifyPeerConfirm(buffer2) || !bob.verifyPeerConfirm(buffer1)) {
        std::cerr << "Confirm error" << std::endl;
        return;
    }
    alice.getKey(buffer1, 256);
    bob.getKey(buffer2, 256);
    if (memcmp(buffer1, buffer2, alice.getKeySize()) != 0) {
        std::cerr << "Keys differ" << std::endl;
        return;
    }
    alice.destroy();
    bob.destroy();
}






void scenariu2()
{
    Peer::selectParameterSet(0);
    Peer alice("Alice"), bob("Bob");
    alice.initiate("Bob", "1234");
    bob.initiate("Alice", "0000");

    alice.commitExchange();
    bob.commitExchange();
    alice.getCommitMessage(buffer1, 256);
    bob.getCommitMessage(buffer2, 256);

    if (!alice.verifyPeerCommit(buffer2) || !bob.verifyPeerCommit(buffer1)) {
        std::cerr << "Commit error" << std::endl;
        return;
    }
    alice.confirmExchange();
    bob.confirmExchange();
    alice.getConfirmMessage(buffer1, 256);
    bob.getConfirmMessage(buffer2, 256);

    if (!alice.verifyPeerConfirm(buffer2) || !bob.verifyPeerConfirm(buffer1)) {
        std::cerr << "Confirm error" << std::endl;
        return;
    }
    alice.getKey(buffer1, 256);
    bob.getKey(buffer2, 256);
    if (memcmp(buffer1, buffer2, alice.getKeySize()) != 0) {
        std::cerr << "Keys differ" << std::endl;
        return;
    }
    alice.destroy();
    bob.destroy();
}




void scenariu3()
{
    for (int i = 0; i < 20; i++) {
        clock_t start = clock(), diff;
        scenariu1();
        diff = clock() - start;

        int msec = diff * 1000 / CLOCKS_PER_SEC;
        cout << "Time taken: " << msec << " milliseconds\n";
    }
}




int main()
{
    scenariu3();
    return 0;
}
