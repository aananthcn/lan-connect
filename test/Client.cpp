#include <iostream>


#include "SecureSocket.h"

using namespace LanConnect;

int main(void)
{
	SecureSocket ssk;

	ssk.Connect("localhost");
	ssk.Disconnect();

	return 0;
}