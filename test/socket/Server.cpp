#include <iostream>


#include "SecureSocket.h"

using namespace LanConnect;


void rx_callback(char *data, int len)
{
	std::cout << __func__ << ": " << data << "\n";
}


int main(void)
{
	SecureSocket ssk("../../resources");
	char buffer[512];
	int connfd;

	if ((connfd = ssk.OpenConnection()) < 0) {
		std::cout << "Unable to create server socket\n";
		return -1;
	}

	ssk.Recv(buffer, sizeof(buffer));
	std::cout << "Received: " << buffer << "\n";

	sprintf(buffer, "Hello Client!!");
	ssk.Send(buffer, strlen(buffer));

	std::cout << "Calling RecvAsync() ... \n";
	ssk.RecvAsync(buffer, sizeof(buffer), rx_callback);

	std::cout << "Entering 5 sec sleep\n";
	sleep(5);

	ssk.StopConnections();
	ssk.CloseConnection(connfd);

	return 0;
}
