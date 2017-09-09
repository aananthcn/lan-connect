#include <iostream>


#include "SecureSocket.h"

using namespace LanConnect;


void rx_callback(char *data, int len)
{
	std::cout << __func__ << ": " << data << "\n";
}


int main(void)
{
	SecureSocket ssk("../../security");
	char buffer[512];

	if (ssk.OpenConnection() < 0) {
		std::cout << "Unable to create server socket\n";
		return -1;
	}

	ssk.Recv(buffer, sizeof(buffer));
	std::cout << "Received: " << buffer << "\n";

	sprintf(buffer, "Hello Client!!");
	ssk.Send(buffer, strlen(buffer));

	std::cout << "Calling RecvAsync() ... \n";
	ssk.RecvAsync(buffer, sizeof(buffer), rx_callback);

	sleep(5);

	ssk.CloseConnection();

	return 0;
}
