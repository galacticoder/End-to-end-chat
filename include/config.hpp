#pragma once

#include <iostream>
#include <vector>

class Server
{
public:
	static const int SERVER_USER_LIMIT = 2;
	std::vector<int> clientSockets;
};