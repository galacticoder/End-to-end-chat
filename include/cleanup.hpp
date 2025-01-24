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

			auto sslSocketIndex = std::remove(ServerStorage::clientSSLSockets.begin(), ServerStorage::clientSSLSockets.end(), ssl);

			std::cout << "ServerStorage::clientSSLSockets size before: " << ServerStorage::clientSSLSockets.size() << std::endl;

			if (sslSocketIndex != ServerStorage::clientSSLSockets.end())
				ServerStorage::clientSSLSockets.erase(sslSocketIndex, ServerStorage::clientSSLSockets.end());

			std::cout << "ServerStorage::clientSSLSockets size after: " << ServerStorage::clientSSLSockets.size() << std::endl;
		}

		static void deleteUserPublicKey(std::string &clientUsername)
		{
			if (clientUsername.empty())
				return;

			std::cout << "ServerStorage::clientPublicKeys size before: " << ServerStorage::clientPublicKeys.size() << std::endl;

			auto it = ServerStorage::clientPublicKeys.find(clientUsername);

			if (it != ServerStorage::clientPublicKeys.end())
				ServerStorage::clientPublicKeys.erase(it);

			std::cout << "ServerStorage::clientPublicKeys size after: " << ServerStorage::clientPublicKeys.size() << std::endl;
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
