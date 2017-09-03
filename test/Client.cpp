#include <iostream>


#include "SecureSocket.h"

using namespace LanConnect;

int main(void)
{
	SecureSocket sk;

	sk.Connect("localhost");

	return 0;
}