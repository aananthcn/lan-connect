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
	pServer = new SecureSocket;
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
		// add code here
	} while (self->searchActive);

	std::cout << __func__ << "(): exiting server thread.\n";

	return NULL;
}


int LcFinder::StopSearch() {
	searchActive = false;

	return 0;
}


int LcFinder::StartSearch() {
	pthread_t server_thread;

	searchActive = true;

	if (pthread_create(&server_thread, NULL, this->lcServerThread, this)) {
		std::cout << __func__ << "Error creating server thread!\n";
		return -1;
	}

	getLocalIPs();

	return 0;
}

int LcFinder::getLocalIPs() {
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