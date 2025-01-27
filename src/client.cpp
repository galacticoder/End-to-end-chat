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

void receiveMessages(SSL *ssl)
{
	while (true)
	{
		std::string message;

		std::cout << "msg received" << std::endl;

		if ((message = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
		{
			std::cout << "Server killed" << std::endl;
			CleanUp::Client::cleanUpClient();
		}

		Signals::SignalType detectSignal = Signals::SignalManager::getSignalTypeFromMessage(message);
		HandleSignal(detectSignal, message, key, sizeof(key), iv, sizeof(iv));

		if (detectSignal == Signals::SignalType::UNKNOWN)
		{
			Decode::deserializeIV(message, iv, sizeof(iv));
			std::string decryptedMessage = Decrypt::decryptDataAESGCM(message, key, sizeof(key), iv, sizeof(iv));
			std::cout << "Received message: " << decryptedMessage << std::endl;
		}
	}
}

void communicateWithServer(SSL *ssl)
{
	std::cout << "Enter username: ";
	std::string username;
	std::getline(std::cin, username);

	if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, username.data(), username.size()))
		return;

	std::string validateUsername;
	if ((validateUsername = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
	{
		CleanUp::Client::cleanUpClient();
		return;
	}

	Signals::SignalType getSignal = Signals::SignalManager::getSignalTypeFromMessage(validateUsername);
	HandleSignal(getSignal, validateUsername, key, sizeof(key), iv, sizeof(iv));

	FilePaths::setKeyPaths(username);
	GenerateKeys::generateRSAKeys(FilePaths::clientPrivateKeyPath, FilePaths::clientPublicKeyPath);

	const std::string publicKeyData = ReadFile::ReadPemKeyContents(FilePaths::clientPublicKeyPath);
	if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, publicKeyData.data(), publicKeyData.size()))
		return;

	int amountOfKeys;
	if (!Receive::Client::receiveAllPublicKeys(ssl, &amountOfKeys))
	{
		CleanUp::Client::cleanUpClient();
		return;
	}

	CryptoPP::GCM<CryptoPP::AES>::Encryption setKey;
	GenerateKeys::generateKeyAESGCM(key, iv);
	setKey.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

	std::string serializedKeyAndIv = Encode::serializeKeyAndIV(key, sizeof(key), iv, sizeof(iv));

	if (!Send::Client::sendEncryptedAESKey(ssl, serializedKeyAndIv, amountOfKeys, Signals::SignalManager::getSignalAsString(Signals::SignalType::NEWAESKEY)))
	{
		CleanUp::Client::cleanUpClient();
		return;
	}

	std::thread(receiveMessages, ssl).detach();
	std::cout << "You can now chat" << std::endl;

	while (1)
	{
		std::string message;
		std::getline(std::cin, message);

		std::cout << "\033[A";
		std::cout << fmt::format("{}: {}", username, message) << std::endl;

		if (message.empty())
			continue;

		std::string ciphertext = Encrypt::encryptDataAESGCM(message, key, sizeof(key));
		if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, ciphertext.data(), ciphertext.size()))
			return;
	}
}

int main()
{
	SSLSetup::initOpenssl();

	CreateDirectory makeKeysDir(FilePaths::keysDirectory);
	CreateDirectory makeReceivedKeysDir(FilePaths::receivedKeysDirectory);

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
		DeletePath deleteReceivedKeysDirectory(FilePaths::receivedKeysDirectory);
		_exit(signal); // seg fault here
	};

	if (SSL_connect(ssl) <= 0)
	{
		ERR_print_errors_fp(stderr);
	}
	else
	{
		std::string serverPublicKey;
		if ((serverPublicKey = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
			CleanUp::Client::cleanUpClient();

		SaveFile savePubKey(FilePaths::clientServerPublicKeyPath, serverPublicKey, std::ios::binary);

		std::string getSignalString;
		if ((getSignalString = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
			CleanUp::Client::cleanUpClient();

		Signals::SignalType getSignal = Signals::SignalManager::getSignalTypeFromMessage(getSignalString);
		HandleSignal(getSignal, getSignalString);

		communicateWithServer(ssl);
	}

	CleanUp::Client::cleanUpClient();
	return 0;
}
