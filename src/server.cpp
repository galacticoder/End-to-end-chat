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
#include "../include/encryption.hpp"
#include "../include/server.hpp"

std::function<void(int)> shutdownHandler;
void signalHandle(int signal) { shutdownHandler(signal); }

std::map<std::string, SSL *> keyToSockets;

void handleClient(SSL *ssl)
{
	Server::clientSSLSockets.push_back(ssl);

	std::string publicKey;
	if ((publicKey = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
		return;

	Server::publicKeyData.push_back(publicKey);
	std::cout << "Public key: " << publicKey << std::endl;
	std::cout << "here" << std::endl;
	// keyToSockets[publicKey] = ssl; // add the key and map it to the socket

	if (!Send::sendAllPublicKeys(ssl, Server::publicKeyData, publicKey))
	{
		// clean up client here
	}

	std::cout << "here" << std::endl;
	// std::string encryptedAesKey;

	// if ((encryptedAesKey = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
	// 	return;
	// std::cout << "HEREE" << std::endl;

	// if (!Send::broadcastMessage(ssl, encryptedAesKey))
	// {
	// 	return;
	// }
	std::cout << "here" << std::endl;

	//-------------
	std::string amountOfUsers;
	if ((amountOfUsers = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
		return;

	std::cout << "here now" << std::endl;
	std::cout << "userrs: " << std::stoi(amountOfUsers) << std::endl;

	if (std::stoi(amountOfUsers) > 0)
	{
		std::cout << "inside here" << std::endl;
		for (int i = 0; i < std::stoi(amountOfUsers); i++)
		{
			std::string publicData;
			if ((publicData = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
				return;

			std::cout << "Public key data: " << publicData << std::endl;

			std::string delimeter = ":";
			std::string extractIndex = publicData.substr(publicData.find(delimeter) + 1);
			std::cout << "string extracted index: " << extractIndex << std::endl;
			int extractedIndex = stoi(extractIndex);
			std::cout << "Extracted index: " << extractedIndex << std::endl;
			std::string encryptedKey = publicData.substr(0, publicData.find(delimeter)); // KEYDATAHEREAESKEY

			std::cout << "Key is: " << encryptedKey << std::endl;

			if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(Server::clientSSLSockets[extractedIndex], publicData.data(), publicData.size()))
				return;

			std::cout << "Sent aes key" << std::endl;
		}
		std::cout << "Sent all aes keys" << std::endl;
	}

	while (1)
	{
		std::string message;
		if ((message = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
			return;

		std::cout << "Client message: " << message << std::endl;
		if (!Send::broadcastMessage(ssl, message))
		{
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
			Clean::cleanUpClient(ssl, clientSocket);
		}

		std::thread(handleClient, ssl).detach();
		// Clean::cleanUpClient(ssl, clientSocket);
	}

	close(serverSocket);
	SSL_CTX_free(ctx);
	DeletePath deleteDirectory(keysDirectory);

	std::cout << "Cleaned up server" << std::endl;
	return 0;
}