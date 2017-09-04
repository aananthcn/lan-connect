#include <iostream>


#include "SecureSocket.h"

using namespace LanConnect;

int main(void)
{
	SecureSocket ssk("../security");
	char buffer[512];

	if (ssk.Open() < 0) {
		std::cout << "Unable to create server socket\n";
		return -1;
	}

	ssk.Recv(buffer, sizeof(buffer));
	std::cout << "Received: " << buffer << "\n";

	sprintf(buffer, "Hello Client!!");
	ssk.Send(buffer, strlen(buffer));

	sleep(5);

	ssk.Close();

	return 0;
}
