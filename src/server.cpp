#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <fstream>
#include <vector>
#include <thread>
#include <map>
#include "../include/keys.hpp"
#include "../include/ssl.hpp"
#include "../include/file_handling.hpp"
#include "../include/networking.hpp"
#include "../include/config.hpp"
#include "../include/security.hpp"
#include "../include/encryption.hpp"
#include "../include/cleanup.hpp"
#include "../include/send_receive.hpp"

std::function<void(int)> shutdownHandler;
void signalHandle(int signal) { shutdownHandler(signal); }

void handleClient(SSL *ssl, int &clientSocket)
{
	ServerStorage::clientSSLSockets.push_back(ssl);

	std::string clientUsername;
	if ((clientUsername = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
	{
		CleanUp::Server::cleanUpClient(ssl, clientSocket, clientUsername);
		return;
	}

	if (!ValidateClient::checkClientUsernameValidity(ssl, clientUsername))
	{
		CleanUp::Server::cleanUpClient(ssl, clientSocket, clientUsername);
		return;
	}

	std::string clientPublicKey;
	if ((clientPublicKey = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
	{
		CleanUp::Server::cleanUpClient(ssl, clientSocket, clientUsername);
		return;
	}

	ServerStorage::clientPublicKeys[clientUsername] = clientPublicKey;
	std::cout << "Public key: " << clientPublicKey << std::endl;

	if (!Send::Server::sendAllPublicKeys(ssl, clientUsername))
	{
		CleanUp::Server::cleanUpClient(ssl, clientSocket, clientUsername);
		return;
	}

	if (!Receive::Server::receiveAndSendEncryptedAesKey(ssl))
	{
		CleanUp::Server::cleanUpClient(ssl, clientSocket, clientUsername);
		return;
	}

	while (1)
	{
		std::string message;
		if ((message = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
		{
			CleanUp::Server::cleanUpClient(ssl, clientSocket, clientUsername);
			return;
		}

		std::cout << "Client message: " << message << std::endl;

		if (!Send::Server::broadcastMessage(ssl, message))
		{
			CleanUp::Server::cleanUpClient(ssl, clientSocket, clientUsername);
			return;
		}
	}
}

int main()
{
	SSLSetup::initOpenssl();

	CreateDirectory makeKeysDir(keysDirectory);
	GenerateKeys::generateCertAndPrivateKey(serverPrivateKeyPath, serverCertPath);

	SSL_CTX *ctx = SSLSetup::createCTX(TLS_server_method());
	SSLSetup::configureCTX(ctx, serverCertPath, serverPrivateKeyPath);

	int serverSocket = Networking::startServerSocket(Networking::findAvailablePort());

	shutdownHandler = [&](int signal)
	{
		std::cout << fmt::format("\nSignal {} caught. Killing server", strsignal(signal)) << std::endl;
		close(serverSocket);
		SSL_CTX_free(ctx);
		DeletePath deleteDirectory(keysDirectory);
		exit(signal);
	};

	std::signal(SIGINT, signalHandle);

	while (1)
	{
		int clientSocket = Networking::acceptClientConnection(serverSocket);

		SSL *ssl = SSL_new(ctx);
		SSL_set_fd(ssl, clientSocket);

		if (SSL_accept(ssl) <= 0)
		{
			std::cout << "Error accepting client: ";
			ERR_print_errors_fp(stderr);
			CleanUp::Server::cleanUpClient(ssl, clientSocket);
			continue;
		}

		if (!ValidateClient::checkServerUserLimit(ssl))
		{
			CleanUp::Server::cleanUpClient(ssl, clientSocket);
			continue;
		}

		std::thread(handleClient, ssl, std::ref(clientSocket)).detach();
	}

	close(serverSocket);
	SSL_CTX_free(ctx);
	DeletePath deleteDirectory(keysDirectory);

	std::cout << "Cleaned up server" << std::endl;
	return 0;
}