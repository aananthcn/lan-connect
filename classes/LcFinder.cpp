#include <iostream>

extern "C" {
	#include <stdio.h>
	#include <sys/types.h>
	#include <ifaddrs.h>
	#include <netinet/in.h>
	#include <string.h>
	#include <arpa/inet.h>
}

#include "LcFinder.h"

using namespace LanConnect;


LcFinder::LcFinder() {
	pServer = NULL;
	pClient = new SecureSocket();
	searchActive = false;
}


LcFinder::~LcFinder() {
	if (pClient) {
		delete pClient;
	}

	if (pServer) {
		delete pServer;
	}

	while (iplist.empty() != true) {
		delete iplist.front();
		iplist.pop_front();
	}
}


void LcFinder::lcServerThread(SecureSocket *sskt, std::thread *thread) {
	int connfd;
	std::thread *child;

	std::cout << __func__ << "(): starting server thread...\n";
	connfd = sskt->OpenConnection();
	if (connfd > 0) {
		child = new std::thread(lcServerThread, std::ref(sskt), std::ref(child));
	}

	// do your main server processing here
	sleep(5);

	sskt->CloseConnection(connfd);
	delete thread;

	std::cout << __func__ << "(): exiting server thread.\n";
}


int LcFinder::ShutdownLcFinder() {
	searchActive = false;
	usleep(100*1000); // wait for server thread to exit

	return 0;
}


int LcFinder::addLocalIPsToList() {
	struct ifaddrs *ifAddrStruct = NULL;
    struct ifaddrs *ifa = NULL;
    struct in_addr localhost;

	inet_pton(AF_INET, "127.0.0.1", &localhost);
    getifaddrs(&ifAddrStruct);

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
            	std::cout << __func__ << "(): added " << ip_str << " to the list\n";
            }
        }
    }

    if (ifAddrStruct != NULL)
    	freeifaddrs(ifAddrStruct);

    return 0;
}


int LcFinder::scanForRemoteLcFinder(struct in_addr *ip) {
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

	//for (i = 2; i < 254; i++) {
	for (i = 2; i < 25; i++) {
		ip->s_addr = ip_base | (i << shift_cnt);
		inet_ntop(AF_INET, ip, ip_str, INET_ADDRSTRLEN);

		connfd = pClient->Connect(ip_str);
		if(connfd > 0) {
			std::cout << "Connected to \"" << ip_str << "\"!\n";
		}
		pClient->Disconnect(connfd);
	}

	return 0;
}


int LcFinder::enterActiveMode() {
	std::cout << __func__ << "();\n";
	return 0;
}

int LcFinder::EnterSearchMode() {
	std::thread *sthread;

	searchActive = true;

	// start a server thread as per LanConnect protocol
	pServer = new SecureSocket("../../resources");
	sthread = new std::thread(lcServerThread, std::ref(pServer), std::ref(sthread));

	// from the main thread, start scanning other LanConnect nodes as per protocol
	addLocalIPsToList();
	for (auto ip : iplist) {
		scanForRemoteLcFinder(ip);
	}

	enterActiveMode();

	return 0;
}

