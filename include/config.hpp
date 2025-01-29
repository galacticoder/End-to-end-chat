#pragma once

#include <iostream>
#include <vector>
#include <openssl/ssl.h>

class ClientManagement
{
public:
	static inline std::vector<SSL *> clientSSLSockets;
	static inline std::map<std::string, std::string> clientPublicKeys;
};

class ServerConfig
{
public:
	static const size_t SERVER_USER_LIMIT = 9;
	static inline size_t MAX_USERNAME_LENGTH = 12;
	static inline size_t MIN_USERNAME_LENGTH = 3;
	static inline bool PASSWORD_REQUIRED;
	static inline std::string SERVER_HASHED_PASSWORD;
	static inline std::string UNALLOWED_CHARACTERS = "/\\{}|.,()~` ";
};