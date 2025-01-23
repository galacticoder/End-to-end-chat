#pragma once

#include <iostream>
#include <vector>
#include <openssl/ssl.h>

class ServerStorage
{
public:
	static const int SERVER_USER_LIMIT = 9; // add this to the server later
	static inline std::vector<SSL *> clientSSLSockets;
	static inline std::map<std::string, std::string> clientPublicKeys;
};