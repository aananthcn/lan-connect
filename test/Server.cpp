#include <iostream>


#include "SecureSocket.h"

using namespace LanConnect;

int main(void)
{
	SecureSocket sk("../security");

	if (sk.Init() < 0) {
		std::cout << "Unable to create server socket\n";
		return -1;
	}

	sleep(5);

	return 0;
}