#ifndef LANCONNECT_LINK_H
#define LANCONNECT_LINK_H

#include <list>
#include <thread>

extern "C" {
	#include <arpa/inet.h>
}


#include "SecureSocket.h"

#define PAYLOAD_SIZE (1024+256+128) /* kept closer to ethernet frame size */


namespace LanConnect {

	struct LcLinkHdr
	{
		unsigned char dst;
		unsigned char src;
		unsigned short len;
		unsigned short mode; // file transfer mode, query mode
		unsigned short cmd;  // receive, send, getinfo...
	};

	struct LcLinkPkt
	{
		union {
			LcLinkHdr header;
			char byte[sizeof(LcLinkHdr)];
		} u;
		char payload[PAYLOAD_SIZE];

	};

	template <typename T>
	class LcLink {
	public:
		LcLink();
		~LcLink();
		int RegisterProtocol(T *proto);
		int SearchLcNodes();
		int PrintLcNodes();
		int EnterActiveMode();
		int ShutdownLcLink();

	private:
		SecureSocket *mClientSocket;
		SecureSocket *mServerSocket;
		std::thread  *mServerThread;
		std::list<std::string> mIpList; // string is chosen because search or find is easier
		LcLinkPkt *mRxPkt;
		LcLinkPkt *mTxPkt;
		T *mProtocol;

		int addLocalhostToList();
		int scanForOtherHosts();

		static bool mSearchActive;
		static void lcServerThread_SearchMode(LcLink *link);
		static void serveClientConnection(void);
	};

}

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

namespace LanConnect {

template <typename T>
	bool LcLink<T>::mSearchActive = false;


template <typename T>
	LcLink<T>::LcLink() {
		mServerSocket = NULL;
		mClientSocket = new SecureSocket();
		mProtocol = NULL;
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

	mIpList.clear();
}


template <typename T>
void LcLink<T>::lcServerThread_SearchMode(LcLink<T> *link) {
	int connfd;

	std::cout << __func__ << "(): starting server thread...\n";
	do {
		connfd = link->mServerSocket->OpenConnection();
		if (connfd > 0) {
			if (0 == fork()) {
				std::cout << "Got a connection, creating a child process to handle the current socket\n";
				link->mServerSocket->CloseListenFd(); // we no longer need this in this process space
				#if 0 // handling incoming messages are not allowed in search mode
				LcLinkPkt *lcpkt = new LcLinkPkt;

				// handle new connection
				if (link->mProtocol != NULL) {
					link->mServerSocket->Recv((char *)&lcpkt, sizeof(LcLinkPkt));
				}

				delete lcpkt;
				#endif
				std::cout << "Child process is going to exit!\n";
				exit(0);
			}
			// close this connection as we have created a new process to handle that above.
			link->mServerSocket->CloseConnection(connfd);
		}
	} while (mSearchActive);

	std::cout << __func__ << "(): exiting thread!\n";
}

template <typename T>
int LcLink<T>::RegisterProtocol(T *proto) {
	if (proto != NULL) {
		mProtocol = proto;
		return 0;
	}

	return -1;
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
int LcLink<T>::addLocalhostToList() {
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

            	inet_ntop(AF_INET, ipaddr, ip_str, INET_ADDRSTRLEN);
				mIpList.push_back(ip_str);
				std::cout << "Found " << ip_str << "! Adding to the mIpList ...\n";
            }
        }
    }

    if (ifAddrStruct != NULL)
    	freeifaddrs(ifAddrStruct);

    return 0;
}


template <typename T>
int LcLink<T>::scanForOtherHosts(void) {
	char ip_str[INET_ADDRSTRLEN];

	int shift_cnt, i;
	unsigned int ip_base;
	int connfd;
	struct in_addr ip;

	inet_pton(AF_INET, mIpList.front().c_str(), &ip);

#ifdef __BIG_ENDIAN__
	ip_base = (ip.s_addr) & 0xFFFFFF00;
	shift_cnt = 0;
#else
	ip_base = (ip.s_addr) & 0x00FFFFFF;
	shift_cnt = 24;
#endif

	std::cout << "Start of Remote Scan...\n";
	//for (i = 2; i < 254; i++) {
	for (i = 2; i < 25; i++) {
		ip.s_addr = ip_base | (i << shift_cnt);
		inet_ntop(AF_INET, &ip, ip_str, INET_ADDRSTRLEN);

		connfd = mClientSocket->Connect(ip_str);
		if(connfd > 0) {

			auto iter = std::find(mIpList.begin(), mIpList.end(), ip_str);
			if (iter == mIpList.end()) {
				std::cout << "Found new host: \"" << ip_str << "\"!\n";
				mIpList.push_back(ip_str);
			}
			mClientSocket->Disconnect(connfd);
		}
	}
	std::cout << "End of Remote Scan...\n";

	return 0;
}


template <typename T>
int LcLink<T>::EnterActiveMode() {
	std::cout << __func__ << "();\n";
	return 0;
}


template <typename T>
int LcLink<T>::SearchLcNodes() {
	mSearchActive = true;

	// start a server thread as per LanConnect protocol
	mServerSocket = new SecureSocket("../../resources");
	mServerThread = new std::thread(lcServerThread_SearchMode, this);

	// from the main thread, start scanning other LanConnect nodes as per protocol
	addLocalhostToList();
	scanForOtherHosts();

	mSearchActive = false;
	mServerSocket->StopConnections();
	std::cout << "Finished searching LanConnect nodes ...\n";

	if (mIpList.size() > 1) {
		return 1;
	}
	return 0;
}

template <typename T>
int LcLink<T>::PrintLcNodes() {
	int i = 0;

	if (mIpList.size() == 0) {
		std::cout << "LcNode cout is 0\n";
		return -1;
	}

	std::cout << "\nIP addresses scanned:\n";
	std::cout << "---------------------\n";
	for (auto ip: mIpList) {
		if (i == 0)
			std::cout << "  " << ip << " <== This node!\n";
		else
			std::cout << "  " << ip << "\n";
		i++;
	}
	std::cout << "\n";

	return 0;
}

} // namespace

#endif