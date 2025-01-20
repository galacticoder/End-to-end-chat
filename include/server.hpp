#pragma once

#include <iostream>
#include <unistd.h>
#include <openssl/ssl.h>

class Clean
{
public:
	static void cleanUpClient(SSL *ssl, int &clientSocket)
	{
		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(clientSocket);
		std::cout << "Cleaned up client" << std::endl;
	}
};
