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

	private:
		LcLink<LcProtocol> *mLink;

	};
}

#endif