#ifndef LANCONNECT_PROTOCOL_H
#define LANCONNECT_PROTOCOL_H

#include "LcLink.h"

namespace LanConnect {
	class LcProtocol {
	public:
		LcProtocol();
		~LcProtocol();

		int HandleRxMessage(LcLinkPkt *pkt);
		int EstablishLink();
		int LinkDisconnect();

	private:
		LcLink<LcProtocol> *mLink;

	};
}

#endif