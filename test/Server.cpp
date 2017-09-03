#include <iostream>


#include "SecureSocket.h"

using namespace LanConnect;

int main(void)
{
	SecureSocket ssk("../security");

	if (ssk.Start() < 0) {
		std::cout << "Unable to create server socket\n";
		return -1;
	}

	sleep(5);

	ssk.Stop();

	return 0;
}