#pragma once

#include <iostream>
#include <csignal>
#include <unistd.h>
#include <openssl/ssl.h>

class CleanUp
{
public:
	class Server
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
	class Client
	{
	public:
		static void cleanUpClient()
		{
			raise(SIGINT);
		}
	};
};
