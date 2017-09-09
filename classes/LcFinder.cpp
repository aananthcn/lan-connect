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
	pServer = new SecureSocket("../../resources");
	pClient = new SecureSocket;
	searchActive = false;
}


LcFinder::~LcFinder() {
	if (pServer) {
		delete pServer;
	}
	if (pClient) {
		delete pClient;
	}

	while (iplist.empty() != true) {
		delete iplist.front();
		iplist.pop_front();
	}
}


void* LcFinder::lcServerThread(void *arg) {
	LcFinder *self;

	self = (LcFinder *) arg;
	if (self == NULL) {
		std::cout << __func__ << "(): invalid argument!\n";
		return NULL;
	}

	std::cout << __func__ << "(): starting server thread...\n";

	do {
		if(self->pServer->OpenConnection() < 0)
			break;
	} while (self->searchActive);

	self->pServer->CloseConnection();

	std::cout << __func__ << "(): exiting server thread.\n";

	return NULL;
}


int LcFinder::ShutdownLcFinder() {
	searchActive = false;

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

#ifdef __BIG_ENDIAN__
	ip_base = (ip->s_addr) & 0xFFFFFF00;
	shift_cnt = 0;
#else
	ip_base = (ip->s_addr) & 0x00FFFFFF;
	shift_cnt = 24;
#endif

	for (i = 2; i < 254; i++) {
		ip->s_addr = ip_base | (i << shift_cnt);
		inet_ntop(AF_INET, ip, ip_str, INET_ADDRSTRLEN);

		if(0 == pClient->Connect(ip_str)) {
			std::cout << "Connected to \"" << ip_str << "\"!\n";
		}
		pClient->Disconnect();
	}

	return 0;
}


int LcFinder::enterActiveMode() {
	std::cout << __func__ << "();\n";
	return 0;
}

int LcFinder::EnterSearchMode() {
	pthread_t server_thread;

	searchActive = true;

	if (pthread_create(&server_thread, NULL, this->lcServerThread, this)) {
		std::cout << __func__ << "Error creating server thread!\n";
		return -1;
	}

	addLocalIPsToList();

	for (auto ip : iplist) {
		scanForRemoteLcFinder(ip);
	}

	enterActiveMode();

	return 0;
}

