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

void handleClient(SSL *ssl, int &clientSocket)
{
	std::string clientUsername;
	if (clientUsername = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl); clientUsername.empty())
		return;

	ClientManagement::clientSSLSockets.push_back(ssl);

	if (!Validate::validateAndSetupClient(ssl, clientUsername))
	{
		CleanUp::Server::cleanUpClient(ssl, clientSocket);
		return;
	}

	Send::Server::broadcastClientJoinOrExitMessage(ssl, clientUsername, ClientManagement::clientPublicKeys, ClientManagement::clientSSLSockets, Signals::SignalManager::getSignalAsString(Signals::SignalType::SERVERMESSAGE), true); // send join message

	while (1)
	{
		std::string message;
		if ((message = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
		{
			Send::Server::broadcastClientJoinOrExitMessage(ssl, clientUsername, ClientManagement::clientPublicKeys, ClientManagement::clientSSLSockets, Signals::SignalManager::getSignalAsString(Signals::SignalType::SERVERMESSAGE), false);

			CleanUp::Server::cleanUpClient(ssl, clientSocket, clientUsername);
			return;
		}

		if (Signals::SignalManager::getSignalTypeFromMessage(message) == Signals::SignalType::UNKNOWN)
			message.append(fmt::format("|{}", clientUsername) + Signals::SignalManager::getSignalAsString(Signals::SignalType::CLIENTMESSAGE));

		std::cout << "Client message: " << message << std::endl;

		if (!Send::Server::broadcastMessageToClients(ssl, message, ClientManagement::clientSSLSockets, ClientManagement::clientPublicKeys))
		{
			CleanUp::Server::cleanUpClient(ssl, clientSocket, clientUsername);
			return;
		}
	}
}

int main()
{
	SSLSetup::initOpenssl();

	FileSystem::createDirectory(FilePaths::keysDirectory);
	GenerateKeys::generateCertAndPrivateKey(FilePaths::serverPrivateKeyPath, FilePaths::serverCertPath);

	SSL_CTX *ctx = SSLSetup::createCTX(TLS_server_method());
	SSLSetup::configureCTX(ctx, FilePaths::serverCertPath, FilePaths::serverPrivateKeyPath);

	int serverSocket = Networking::startServerSocket(Networking::findAvailablePort());

	shutdownHandler = [&]()
	{
		std::cout << fmt::format("\nKilling server") << std::endl;
		CleanUp::Server::cleanUpServer(ctx, serverSocket);
		exit(1);
	};

	std::signal(SIGINT, signalHandle);

	while (1)
	{
		int clientSocket = Networking::acceptClientConnectionTCP(serverSocket);

		SSL *ssl = SSL_new(ctx);
		SSL_set_fd(ssl, clientSocket);

		if (!Networking::acceptClientConnectionSSL(ssl))
			continue;

		if (!Validate::handleClientPreChecks(ssl))
		{
			CleanUp::Server::cleanUpClient(ssl, clientSocket);
			continue;
		}

		std::thread(handleClient, ssl, std::ref(clientSocket)).detach();
	}

	return 0;
}