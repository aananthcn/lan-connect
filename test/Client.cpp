#include <iostream>


#include "SecureSocket.h"

using namespace LanConnect;

int main(void)
{
	SecureSocket ssk;
	char buffer[512];

	ssk.Connect("localhost");

	sprintf(buffer, "Hello Server!!");
	ssk.Send(buffer, strlen(buffer));
	ssk.Recv(buffer, sizeof(buffer));
	std::cout << "Received: " << buffer << "\n";

	sprintf(buffer, "Thank you! I received the data!");
	ssk.Send(buffer, strlen(buffer));

	ssk.Disconnect();

	return 0;
}
