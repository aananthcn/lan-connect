#include <iostream>


#include "LcProtocol.h"

using namespace LanConnect;



int main(void)
{
	LcProtocol lcp;

	lcp.EstablishLink();
	lcp.LinkDisconnect();


	return 0;
}
