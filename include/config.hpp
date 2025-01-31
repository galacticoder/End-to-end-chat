#pragma once

#include <iostream>
#include <vector>
#include <openssl/ssl.h>

namespace ClientManagement
{
	static inline std::vector<SSL *> clientSSLSockets;
	static inline std::map<std::string, std::string> clientPublicKeys;
};

class ServerConfig
{
public:
	static const size_t SERVER_USER_LIMIT = 9;
	static inline size_t MAX_USERNAME_LENGTH = 12;
	static inline size_t MIN_USERNAME_LENGTH = 3;
	static inline std::string UNALLOWED_CHARACTERS = "/\\{}|.,()~` ";
};