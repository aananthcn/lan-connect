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
		SecureSocket *mClientSocket;
		SecureSocket *mServerSocket;
		std::thread  *mServerThread;
		std::list<struct in_addr *> iplist;

		int addLocalIPsToList();
		int scanForRemoteLcFinder(struct in_addr *ip);
		int enterActiveMode();

		static bool mSearchActive;
		static void lcServerThread(SecureSocket *sskt);
	};

}

#endif