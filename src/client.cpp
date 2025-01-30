#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fstream>
#include <thread>
#include <vector>
#include "../include/ssl.hpp"
#include "../include/client_security.hpp"
#include "../include/send_receive.hpp"
#include "../include/signals.hpp"
#include "../include/keys.hpp"
#include "../include/file_handling.hpp"
#include "../include/networking.hpp"
#include "../include/encryption.hpp"
#include "../include/cleanup.hpp"

std::function<void(int)> shutdownHandler;
void signalHandle(int signal) { shutdownHandler(signal); }

CryptoPP::byte key[CryptoPP::AES::MAX_KEYLENGTH]; // 32 bytes
CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];	  // 16 bytes

std::vector<std::string> publicKeys;

void receiveMessages(SSL *ssl)
{
	while (true)
	{
		std::string message;
		if (message = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl); message.empty())
		{
			std::cout << "Server killed" << std::endl;
			CleanUp::Client::cleanUpClient();
		}

		Signals::SignalType detectSignal = Signals::SignalManager::getSignalTypeFromMessage(message);
		HandleSignal(detectSignal, message, key, sizeof(key), iv, sizeof(iv));
	}
}

void communicateWithServer(SSL *ssl)
{
	if (!ClientValidation::clientAuthenticationAndKeyExchange(ssl, key, sizeof(key), iv, sizeof(iv), publicKeys))
		return;

	std::thread(receiveMessages, ssl).detach();
	std::cout << "You can now chat" << std::endl;

	auto trimws = [&](std::string &str)
	{
		str.erase(0, str.find_first_not_of(" \t\n\r"));
		str.erase(str.find_last_not_of(" \t\n\r") + 1);
		return str;
	};

	while (1)
	{
		std::string message;
		std::getline(std::cin, message);
		message = trimws(message);

		if (!message.empty())
		{
			std::cout << "\033[A";
			std::cout << fmt::format("{}: {}", username, message) << std::endl;
			std::string ciphertext = Encrypt::encryptDataAESGCM(message, key, sizeof(key));
			if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, ciphertext.data(), ciphertext.size()))
				break;
		}
		else
			std::cout << "\033[A";
	}
}

int main()
{
	SSLSetup::initOpenssl();

	FileSystem::createDirectory(FilePaths::keysDirectory);
	FileSystem::createDirectory(FilePaths::receivedKeysDirectory);

	GenerateKeys::generateCertAndPrivateKey(FilePaths::clientPrivateKeyCertPath, FilePaths::clientCertPath);

	SSL_CTX *ctx = SSLSetup::createCTX(TLS_client_method());
	SSLSetup::configureCTX(ctx, FilePaths::clientCertPath, FilePaths::clientPrivateKeyCertPath);

	const std::string serverIpAddress = "127.0.0.1";
	const int port = 8080;

	int socketfd = Networking::startClientSocket(port, serverIpAddress);

	std::signal(SIGINT, signalHandle);

	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, socketfd);

	shutdownHandler = [&](int signal)
	{
		if (ssl)
		{
			SSL_shutdown(ssl);
			SSL_free(ssl);
		}
		close(socketfd);

		if (ctx)
			SSL_CTX_free(ctx);

		// DeletePath deleteKeysDirectory(FilePaths::keysDirectory);
		FileSystem::deletePath(FilePaths::receivedKeysDirectory);
		_exit(signal); // seg fault here
	};

	if (SSL_connect(ssl) <= 0)
	{
		ERR_print_errors_fp(stderr);
		raise(SIGINT);
	}

	std::string validateConnectionString;
	if ((validateConnectionString = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
		CleanUp::Client::cleanUpClient();
	HandleSignal(Signals::SignalManager::getSignalTypeFromMessage(validateConnectionString), validateConnectionString);

	communicateWithServer(ssl);

	CleanUp::Client::cleanUpClient();
	return 0;
}
