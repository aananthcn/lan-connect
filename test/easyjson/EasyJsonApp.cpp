#include <iostream>


extern "C" {
	#include <unistd.h>
}

#include "EasyJson.h"

using namespace LanConnect;


void rx_callback(char *data, int len)
{
	std::cout << __func__ << ": " << data << "\n";
}


int main(void)
{
	int value;
	char buff[256];

	EasyJson ej("../../resources/device_info.json");
	ej.GetInt("number", &value);
	std::cout << "Id number from device_info.json = " << value << "\n";

	ej.SetInt("number", 707);
	ej.GetInt("number", &value);
	std::cout << "Id number from device_info.json = " << value << "\n";

	ej.AddInt("aananth", 007);
	ej.GetInt("aananth", &value);
	std::cout << "Newly added int 'aananth' from device_info.json = " << value << "\n";

	if (ej.GetStr("uid", buff) < 0) {
		ej.AddStr("uid", (char *)"dummy");
	}
	std::cout << "uid = " << buff << "\n";
	std::cout << "Enter new uid: ";
	std::cin >> buff;
	std::cout << "\n";
	ej.SetStr("uid", buff);
	ej.GetStr("uid", buff);
	std::cout << "uid = " << buff << "\n";
	std::cout << "Type your signature: ";
	std::cin.ignore(256, '\n');
	std::cin.get(buff, 256);
	std::cout << "\n";
	std::cout << buff << "\n";
	ej.AddStr("signature", buff);
	ej.SaveFile("./modified.json");

	ej.LoadFile("../../resources/device_info.json");
	ej.AddStr("signature", buff);
	ej.SaveFile("./unmodified.json");

	return 0;
}
