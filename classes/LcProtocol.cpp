#include "LcProtocol.h"


using namespace LanConnect;

LcProtocol::LcProtocol() {
	mLink = new LcLink<LcProtocol>;
	if (mLink) {
		mLink->RegisterProtocol(this);
	}
}

LcProtocol::~LcProtocol() {
	mLink->ShutdownLcLink();
	delete mLink;
}

int LcProtocol::EstablishLink(void) {
	if (!mLink) {
		return -1;
	}

	mLink->EnterSearchMode();
	return 0;
}

int LcProtocol::HandleRxMessage(LcLinkPkt *pkt) {
	std::cout << __func__ << "(): data bytes: " << pkt->u.byte << "\n";

	return 0;
}