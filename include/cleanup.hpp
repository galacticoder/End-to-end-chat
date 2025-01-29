#pragma once

#include <iostream>
#include <csignal>
#include <vector>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "config.hpp"

class CleanUp
{
public:
	class Server
	{
	private:
		static void cleanUpOpenssl()
		{
			EVP_cleanup();
			ERR_free_strings();
			CRYPTO_cleanup_all_ex_data();
		}

		static void freeAndDeleteSSLSocket(SSL *ssl)
		{
			if (ssl)
			{
				SSL_shutdown(ssl);
				SSL_free(ssl);
			}

			auto sslSocketIndex = std::remove(ClientManagement::clientSSLSockets.begin(), ClientManagement::clientSSLSockets.end(), ssl);

			std::cout << "ClientManagement::clientSSLSockets size before: " << ClientManagement::clientSSLSockets.size() << std::endl;

			if (sslSocketIndex != ClientManagement::clientSSLSockets.end())
				ClientManagement::clientSSLSockets.erase(sslSocketIndex, ClientManagement::clientSSLSockets.end());

			std::cout << "ClientManagement::clientSSLSockets size after: " << ClientManagement::clientSSLSockets.size() << std::endl;
		}

		static void deleteUserPublicKey(std::string &clientUsername)
		{
			if (clientUsername.empty())
				return;

			std::cout << "ClientManagement::clientPublicKeys size before: " << ClientManagement::clientPublicKeys.size() << std::endl;

			auto it = ClientManagement::clientPublicKeys.find(clientUsername);

			if (it != ClientManagement::clientPublicKeys.end())
				ClientManagement::clientPublicKeys.erase(it);

			std::cout << "ClientManagement::clientPublicKeys size after: " << ClientManagement::clientPublicKeys.size() << std::endl;
		}

	public:
		static void cleanUpClient(SSL *ssl, int &clientSocket, std::string clientUsername = "")
		{
			cleanUpOpenssl();
			freeAndDeleteSSLSocket(ssl);
			deleteUserPublicKey(clientUsername);
			close(clientSocket);
			std::cout << "Cleaned up client" << std::endl;
		}
	};
	class Client
	{
	public:
		static void cleanUpClient()
		{ // work on this soon
			raise(SIGINT);
		}
	};
};
