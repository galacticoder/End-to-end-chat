#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fstream>
#include <thread>
#include <atomic>
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

std::vector<std::string> publicKeys;
std::string username;

std::atomic<bool> running{true};
void receiveMessages(SSL *ssl, CryptoPP::byte *key, size_t keySize, CryptoPP::byte *iv, size_t ivSize)
{
	while (running)
	{
		std::string message;
		if (message = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl); message.empty())
		{
			running = false;
			std::cout << "Server killed" << std::endl;
			raise(SIGINT);
		}

		Signals::SignalType detectSignal = Signals::SignalManager::getSignalTypeFromMessage(message);
		HandleSignal(detectSignal, message, key, keySize, iv, ivSize);
	}
}

void communicateWithServer(SSL *ssl)
{
	CryptoPP::byte key[CryptoPP::AES::MAX_KEYLENGTH];
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];

	if (!ClientValidation::clientAuthenticationAndKeyExchange(ssl, key, sizeof(key), iv, sizeof(iv), publicKeys))
		return;

	std::thread(receiveMessages, ssl, key, sizeof(key), iv, sizeof(iv)).detach();

	auto trimws = [&](std::string &str)
	{
		str.erase(0, str.find_first_not_of(" \t\n\r"));
		str.erase(str.find_last_not_of(" \t\n\r") + 1);
		return str;
	};

	std::cout << "You can now chat" << std::endl;

	while (1)
	{
		std::string message;
		std::getline(std::cin, message);
		message = trimws(message);

		if (message.empty())
		{
			std::cout << "\033[A";
			continue;
		}

		std::cout << "\033[A";
		std::cout << fmt::format("{}: {}", username, message) << std::endl;

		std::string ciphertext = Encrypt::encryptDataAESGCM(message, key, sizeof(key));
		if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, ciphertext.data(), ciphertext.size()))
			break;
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
		running = false;
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		CleanUp::Client::cleanUpClient(ssl, ctx, socketfd);
		_exit(signal);
	};

	if (SSL_connect(ssl) <= 0)
	{
		ERR_print_errors_fp(stderr);
		raise(SIGINT);
	}

	std::string validateConnectionString;
	if ((validateConnectionString = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
		raise(SIGINT);

	HandleSignal(Signals::SignalManager::getSignalTypeFromMessage(validateConnectionString), validateConnectionString);

	communicateWithServer(ssl);

	raise(SIGINT);
	return 0;
}
