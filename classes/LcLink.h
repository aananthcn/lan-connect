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
		SecureSocket *mSearchSrvSocket;
		SecureSocket *mActiveSrvSocket;
		std::thread  *mSearchSrvThread;
		std::thread  *mActiveSrvThread;
		std::list<std::string> mIpInterfaceList; // string is chosen because search or find is easier
		std::list<std::string> mIpLanClientList; // string is chosen because search or find is easier
		LcLinkPkt *mRxPkt;
		LcLinkPkt *mTxPkt;
		T *mProtocol;

		int addLocalhostToList();
		int scanForOtherHosts();

		static bool mSearchActive;
		static void lcServerThread_SearchMode(LcLink *link);
		static void lcServerThread_ActiveMode(LcLink *link);
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
		mSearchSrvSocket = NULL;
		mClientSocket = new SecureSocket();
		mProtocol = NULL;
	}


template <typename T>
	LcLink<T>::~LcLink() {
		if (mSearchSrvThread) {
			mSearchSrvThread->join();
			delete mSearchSrvThread;
		}

		if (mActiveSrvThread) {
			mActiveSrvThread->join();
			delete mActiveSrvThread;
		}

		if (mSearchSrvSocket) {
		mSearchSrvSocket->StopConnections(); // to initiate stopping all server threads
		delete mSearchSrvSocket;
	}

	if (mClientSocket) {
		delete mClientSocket;
	}

	mIpInterfaceList.clear();
	mIpLanClientList.clear();
}


template <typename T>
void LcLink<T>::lcServerThread_SearchMode(LcLink<T> *link) {
	int connfd;

	std::cout << __func__ << "(): starting thread (Search Mode)...\n";
	do {
		connfd = link->mSearchSrvSocket->OpenConnection();
		if (connfd > 0) {
			if (0 == fork()) {
				std::cout << "Got a connection, creating a child process to handle the current socket\n";
				link->mSearchSrvSocket->CloseListenFd(); // we no longer need this in this process space
				std::cout << "Child process is going to exit!\n";
				exit(0);
			}
			// close this connection as we have created a new process to handle that above.
			link->mSearchSrvSocket->CloseConnection(connfd);
		}
	} while (mSearchActive);

	std::cout << __func__ << "(): exiting server search mode thread!\n";
}


template <typename T>
void LcLink<T>::lcServerThread_ActiveMode(LcLink<T> *link) {
	int connfd;

	std::cout << __func__ << "(): starting thread (Active Mode)...\n";
	do {
		connfd = link->mActiveSrvSocket->OpenConnection();
		if (connfd > 0) {
			if (0 == fork()) {
				std::cout << "Got a connection, creating a child process to handle the current socket\n";
				link->mActiveSrvSocket->CloseListenFd(); // we no longer need this in this process space
				LcLinkPkt *lcpkt = new LcLinkPkt;

				// handle new connection
				if (link->mProtocol != NULL) {
					link->mActiveSrvSocket->Recv((char *)&lcpkt, sizeof(LcLinkPkt));
					link->mProtocol->HandleRxMessage(lcpkt);
				}

				delete lcpkt;
				std::cout << "Child process is going to exit!\n";
				exit(0);
			}
			// close this connection as we have created a new process to handle that above.
			link->mActiveSrvSocket->CloseConnection(connfd);
		}
	} while (mSearchActive);

	std::cout << __func__ << "(): exiting server active mode thread!\n";
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
	mSearchSrvSocket->StopConnections();
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
				mIpInterfaceList.push_back(ip_str);
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

	inet_pton(AF_INET, mIpInterfaceList.front().c_str(), &ip);

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

			auto iter = std::find(mIpInterfaceList.begin(), mIpInterfaceList.end(), ip_str);
			if (iter == mIpInterfaceList.end()) {
				std::cout << "Found new host: \"" << ip_str << "\"!\n";
				mIpLanClientList.push_back(ip_str);
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
	// start the Active Mode server thread here
	mActiveSrvSocket = new SecureSocket("../../resources");
	mActiveSrvThread = new std::thread(lcServerThread_ActiveMode, this);

	// start connecting to the clients in the mIpList
	/* delete this line */ mActiveSrvSocket->Send("Hi hi hi", 8);

	return 0;
}


template <typename T>
int LcLink<T>::SearchLcNodes() {
	mSearchActive = true;

	// start a server thread as per LanConnect protocol
	mSearchSrvSocket = new SecureSocket("../../resources");
	mSearchSrvThread = new std::thread(lcServerThread_SearchMode, this);

	// from the main thread, start scanning other LanConnect nodes as per protocol
	addLocalhostToList();
	scanForOtherHosts();

	mSearchActive = false;
	mSearchSrvSocket->StopConnections();
	std::cout << "Finished searching LanConnect nodes ...\n";

	if (mIpLanClientList.size() > 0) {
		return 1;
	}
	return 0;
}

template <typename T>
int LcLink<T>::PrintLcNodes() {
	int i = 0;

	if (mIpLanClientList.size() == 0) {
		std::cout << "LcNode count is 0\n";
		return -1;
	}

	std::cout << "\nIP addresses scanned:\n";
	std::cout << "---------------------\n";
	for (auto ip: mIpLanClientList) {
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