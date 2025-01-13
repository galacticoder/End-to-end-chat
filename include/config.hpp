#pragma once

#include <iostream>
#include <vector>

class Server
{
public:
	static const int SERVER_USER_LIMIT = 2;
	static inline std::vector<int> clientSockets;
	static inline std::vector<std::string> publicKeyData;
};