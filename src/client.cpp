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
#include <future>
#include <condition_variable>
#include <mutex>
#include <sys/select.h>
#include "../include/ssl.hpp"
#include "../include/client_security.hpp"
#include "../include/client_input.hpp"
#include "../include/send_receive.hpp"
#include "../include/signals.hpp"
#include "../include/keys.hpp"
#include "../include/file_handling.hpp"
#include "../include/networking.hpp"
#include "../include/encryption.hpp"
#include "../include/cleanup.hpp"

constexpr const char *SERVER_IP_ADDRESS = "127.0.0.1";
constexpr int PORT = 8080;

std::vector<std::string> publicKeys;
std::string username;

std::atomic<bool> threadRunning{true};
std::atomic<bool> shutdownRequested{false};
std::mutex ssl_mutex;
std::condition_variable ssl_cv;

void receiveMessages(SSL *ssl, CryptoPP::byte *key, size_t keySize, CryptoPP::byte *iv, size_t ivSize)
{
	const int sslfd = SSL_get_fd(ssl);
	struct timeval timeout = {0, 100000};

	while (threadRunning)
	{
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(sslfd, &readfds);

		if (select(sslfd + 1, &readfds, nullptr, nullptr, &timeout) > 0)
		{
			std::string message;

			if (message = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl); message.empty())
			{
				std::cout << "Server killed" << std::endl;
				break;
			}

			Signals::SignalType detectSignal = Signals::SignalManager::getSignalTypeFromMessage(message);
			HandleSignal(detectSignal, message, key, keySize, iv, ivSize);
		}
	}

	raise(SIGINT);
	ssl_cv.notify_one();
}

void communicateWithServer(SSL *ssl)
{
	CryptoPP::byte key[CryptoPP::AES::MAX_KEYLENGTH];
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];

	if (!ClientValidation::clientAuthenticationAndKeyExchange(ssl, key, sizeof(key), iv, sizeof(iv), publicKeys))
		return;

	std::thread receiveMessageThread(receiveMessages, ssl, key, sizeof(key), iv, sizeof(iv));

	auto trimws = [&](std::string *str)
	{
		(*str).erase(0, (*str).find_first_not_of(" \t\n\r"));
		(*str).erase((*str).find_last_not_of(" \t\n\r") + 1);
	};

	std::cout << "You can now chat" << std::endl;

	ClientInput::startMessageInput();
	while (threadRunning)
	{
		std::string message = ClientInput::receiveMessage();
		trimws(&message);

		if (!message.empty())
		{
			std::cout << fmt::format("\033[A{}: {}", username, message) << std::endl;

			std::string ciphertext = Encrypt::encryptDataAESGCM(message, key, sizeof(key));
			if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, ciphertext.data(), ciphertext.size()))
				break;
		}
	}

	ssl_cv.notify_one();
	receiveMessageThread.join();
}

int main()
{
	SSLSetup::initOpenssl();

	FileSystem::createDirectory(FilePaths::keysDirectory);
	FileSystem::createDirectory(FilePaths::receivedKeysDirectory);

	GenerateKeys::generateCertAndPrivateKey(FilePaths::clientPrivateKeyCertPath, FilePaths::clientCertPath);

	SSL_CTX *ctx = SSLSetup::createCTX(TLS_client_method());
	SSLSetup::configureCTX(ctx, FilePaths::clientCertPath, FilePaths::clientPrivateKeyCertPath);

	int socketfd = Networking::startClientSocket(PORT, SERVER_IP_ADDRESS);

	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, socketfd);

	shutdownHandler = [&](int signal)
	{
		shutdownRequested = true;
		{
			std::unique_lock<std::mutex> lock(ssl_mutex);
			threadRunning = false;
		}
		ssl_cv.notify_one();
	};

	std::signal(SIGINT, signalHandle);

	if (SSL_connect(ssl) <= 0)
	{
		ERR_print_errors_fp(stderr);
		raise(SIGINT);
	}

	std::string validateConnectionString;
	if (validateConnectionString = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl); validateConnectionString.empty())
		raise(SIGINT);

	HandleSignal(Signals::SignalManager::getSignalTypeFromMessage(validateConnectionString), validateConnectionString);

	communicateWithServer(ssl);

	if (shutdownRequested)
	{
		ClientInput::cleanUpProcesses();
		CleanUp::Client::cleanUpClient(ssl, ctx, socketfd);
	}

	return 0;
}
