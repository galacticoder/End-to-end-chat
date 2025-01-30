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
#include "../include/bcrypt.h"

std::function<void(int)> shutdownHandler;
void signalHandle(int signal) { shutdownHandler(signal); }

void handleClient(SSL *ssl, int &clientSocket)
{
	ClientManagement::clientSSLSockets.push_back(ssl);

	std::string clientUsername;
	if (clientUsername = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl); clientUsername.empty())
		return;

	if (!Validate::validateAndSetupClient(ssl, clientUsername))
	{
		CleanUp::Server::cleanUpClient(ssl, clientSocket);
		return;
	}

	while (1)
	{
		std::string message;
		if ((message = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
		{
			Send::Server::broadcastClientExitMessage(ssl, clientUsername, ClientManagement::clientPublicKeys, ClientManagement::clientSSLSockets, Signals::SignalManager::getSignalAsString(Signals::SignalType::SERVERMESSAGE));
			CleanUp::Server::cleanUpClient(ssl, clientSocket, clientUsername);
			return;
		}

		message.append(fmt::format("|{}", clientUsername) + Signals::SignalManager::getSignalAsString(Signals::SignalType::CLIENTMESSAGE));
		std::cout << "Client message: " << message << std::endl;

		if (!Send::Server::broadcastMessageToClients(ssl, message, ClientManagement::clientSSLSockets))
		{
			CleanUp::Server::cleanUpClient(ssl, clientSocket, clientUsername);
			return;
		}
	}
}

int main()
{
	SetServerPassword setServerPassword;

	SSLSetup::initOpenssl();

	FileSystem::createDirectory(FilePaths::keysDirectory);
	GenerateKeys::generateCertAndPrivateKey(FilePaths::serverPrivateKeyPath, FilePaths::serverCertPath);

	SSL_CTX *ctx = SSLSetup::createCTX(TLS_server_method());
	SSLSetup::configureCTX(ctx, FilePaths::serverCertPath, FilePaths::serverPrivateKeyPath);

	int serverSocket = Networking::startServerSocket(Networking::findAvailablePort());

	shutdownHandler = [&](int signal)
	{
		std::cout << fmt::format("\nSignal {} caught. Killing server", strsignal(signal)) << std::endl;
		close(serverSocket);
		SSL_CTX_free(ctx);
		FileSystem::deletePath(FilePaths::keysDirectory);
		exit(signal);
	};

	std::signal(SIGINT, signalHandle);

	GenerateKeys::generateRSAKeys(FilePaths::serverPrivateKeyPath, FilePaths::serverPublicKeyPath);

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

		const std::string serverPublicKey = FileIO::readFileContents(FilePaths::serverPublicKeyPath);
		if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, serverPublicKey.data(), serverPublicKey.size()))
		{
			CleanUp::Server::cleanUpClient(ssl, clientSocket);
			continue;
		}

		if (!Validate::handleClientPreChecks(ssl))
		{
			CleanUp::Server::cleanUpClient(ssl, clientSocket);
			continue;
		}

		std::thread(handleClient, ssl, std::ref(clientSocket)).detach();
	}

	close(serverSocket);
	SSL_CTX_free(ctx);
	FileSystem::deletePath(FilePaths::keysDirectory);

	std::cout << "Cleaned up server" << std::endl;
	return 0;
}