#include <iostream>


#include "LcLink.h"

using namespace LanConnect;


void rx_callback(char *data, int len)
{
	std::cout << __func__ << ": " << data << "\n";
}


int main(void)
{
	LcLink<int> lfinder;

	lfinder.EnterSearchMode();
	sleep(1);
	lfinder.ShutdownLcLink();

	return 0;
}
