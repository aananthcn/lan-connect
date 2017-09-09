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
		int EnterSearchMode();
		int ShutdownLcFinder();

	private:
		SecureSocket *pServer;
		SecureSocket *pClient;
		bool searchActive;
		std::list<struct in_addr *> iplist;

		static void* lcServerThread(void *arg);
		int addLocalIPsToList();
		int scanForRemoteLcFinder(struct in_addr *ip);
		int enterActiveMode();
	};

}

#endif