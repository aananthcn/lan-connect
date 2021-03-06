#include <iostream>

extern "C" {
	#include <stdio.h>
	#include <sys/types.h>
	#include <ifaddrs.h>
	#include <netinet/in.h>
	#include <string.h>
	#include <arpa/inet.h>
}

#include "LcLink.h"

using namespace LanConnect;

#if 0
template <typename T>
bool LcLink<T>::mSearchActive = false;


template <typename T>
LcLink<T>::LcLink() {
	mServerSocket = NULL;
	mClientSocket = new SecureSocket();
}


template <typename T>
LcLink<T>::~LcLink() {
	if (mServerThread) {
		mServerThread->join();
		delete mServerThread;
	}

	if (mServerSocket) {
		mServerSocket->StopConnections(); // to initiate stopping all server threads
		delete mServerSocket;
	}

	if (mClientSocket) {
		delete mClientSocket;
	}

	while (iplist.empty() != true) {
		delete iplist.front();
		iplist.pop_front();
	}
}


template <typename T>
void LcLink<T>::lcServerThread(LcLink<T> *link) {
	int connfd;

	std::cout << __func__ << "(): starting server thread...\n";
	do {
		connfd = link->mServerSocket->OpenConnection();
		if (connfd > 0) {
			if (0 == fork()) {
				std::cout << "Got a connection, creating a child process to handle the current socket\n";
				link->mServerSocket->CloseListenFd(); // we no longer need this in this process space
				LcLinkPkt *lcpkt = new LcLinkPkt;

				// handle new connection
				link->mServerSocket->Recv((char *)&lcpkt, sizeof(LcLinkPkt));
				sleep(1);

				delete lcpkt;
				std::cout << "Child process is going to exit!\n";
				exit(0);
			}
			// close this connection as we have created a new process to handle that above.
			link->mServerSocket->CloseConnection(connfd);
		}
	} while (mSearchActive);

	std::cout << __func__ << "(): exiting server thread.\n";
}


template <typename T>
int LcLink<T>::ShutdownLcLink() {
	mServerSocket->StopConnections();
	mSearchActive = false;
	std::cout << __func__ << "() - usleep()\n";
	usleep(100*1000); // wait for server thread to exit

	return 0;
}


template <typename T>
int LcLink<T>::addLocalIPsToList() {
	struct ifaddrs *ifAddrStruct = NULL;
    struct ifaddrs *ifa = NULL;
    struct in_addr localhost;

	inet_pton(AF_INET, "127.0.0.1", &localhost);
    getifaddrs(&ifAddrStruct);

    std::cout << "finding the ip address of this machine...\n";
    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET) { // check it is IP4
            // is a valid IP4 Address
            struct in_addr *ipaddr = new struct in_addr; // create struct in_addr object

            *ipaddr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr; //copy struct in_addr data to the new object's memory
            if (ipaddr->s_addr == localhost.s_addr) {
            	delete ipaddr;
            }
            else {
            	char ip_str[INET_ADDRSTRLEN];

            	iplist.push_back(ipaddr);
            	inet_ntop(AF_INET, ipaddr, ip_str, INET_ADDRSTRLEN);
            	std::cout << "Found " << ip_str << "! Adding to the iplist ...\n";
            }
        }
    }

    if (ifAddrStruct != NULL)
    	freeifaddrs(ifAddrStruct);

    return 0;
}


template <typename T>
int LcLink<T>::scanForRemoteLcLink(struct in_addr *ip) {
	char ip_str[INET_ADDRSTRLEN];
	int shift_cnt, i;
	unsigned int ip_base;
	int connfd;

#ifdef __BIG_ENDIAN__
	ip_base = (ip->s_addr) & 0xFFFFFF00;
	shift_cnt = 0;
#else
	ip_base = (ip->s_addr) & 0x00FFFFFF;
	shift_cnt = 24;
#endif

	std::cout << "Start of Remote Scan...\n";
	//for (i = 2; i < 254; i++) {
	for (i = 2; i < 25; i++) {
		ip->s_addr = ip_base | (i << shift_cnt);
		inet_ntop(AF_INET, ip, ip_str, INET_ADDRSTRLEN);

		connfd = mClientSocket->Connect(ip_str);
		if(connfd > 0) {
			std::cout << "Connected to \"" << ip_str << "\"!\n";
			mClientSocket->Disconnect(connfd);
		}
	}
	std::cout << "End of Remote Scan...\n";

	return 0;
}


template <typename T>
int LcLink<T>::enterActiveMode() {
	std::cout << __func__ << "();\n";
	return 0;
}


template <typename T>
int LcLink<T>::EnterSearchMode() {
	mSearchActive = true;

	// start a server thread as per LanConnect protocol
	mServerSocket = new SecureSocket("../../resources");
	mServerThread = new std::thread(lcServerThread, this);

	// from the main thread, start scanning other LanConnect nodes as per protocol
	addLocalIPsToList();
	for (auto ip : iplist) {
		scanForRemoteLcLink(ip);
	}

	enterActiveMode();
	mSearchActive = false;
	std::cout << "Reached end of client thread ...\n";
	sleep(1); // wait for server threads to finish jobs

	return 0;
}
#endif

