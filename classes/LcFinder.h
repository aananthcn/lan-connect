#ifndef LANCONNECT_FINDER_H
#define LANCONNECT_FINDER_H

#include <list>
#include <thread>

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
		SecureSocket *pClient;
		SecureSocket *pServer;
		bool searchActive;
		std::list<struct in_addr *> iplist;

		static void lcServerThread(SecureSocket *sskt, std::thread *thread);
		int addLocalIPsToList();
		int scanForRemoteLcFinder(struct in_addr *ip);
		int enterActiveMode();
	};

}

#endif