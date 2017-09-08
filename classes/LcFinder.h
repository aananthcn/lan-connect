#ifndef LANCONNECT_FINDER_H
#define LANCONNECT_FINDER_H

#include <list>

extern "C" {
	#include <arpa/inet.h>
}


#include "SecureSocket.h"


namespace LanConnect {

	class LcFinder {
	public:
		LcFinder();
		~LcFinder();
		int StartSearch();
		int StopSearch();

	private:
		SecureSocket *pServer;
		SecureSocket *pClient;
		bool searchActive;
		std::list<struct in_addr *> iplist;

		static void* lcServerThread(void *arg);
		int getLocalIPs();
	};

}

#endif