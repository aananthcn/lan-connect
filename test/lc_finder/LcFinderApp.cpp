#include <iostream>


#include "LcFinder.h"

using namespace LanConnect;


void rx_callback(char *data, int len)
{
	std::cout << __func__ << ": " << data << "\n";
}


int main(void)
{
	LcFinder lfinder;

	lfinder.EnterSearchMode();
	sleep(1);
	lfinder.ShutdownLcFinder();

	return 0;
}
