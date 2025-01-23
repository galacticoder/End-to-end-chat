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

	SetKeyPaths setKeyPaths(username);
	GenerateKeys::generateRSAKeys(clientPrivateKeyPath, clientPublicKeyPath);

	const std::string publicKeyData = ReadFile::ReadPemKeyContents(clientPublicKeyPath);
	if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, publicKeyData.data(), publicKeyData.size()))
		return;

	int amountOfKeys;
	if (!Receive::Client::receiveAllPublicKeys(ssl, &amountOfKeys))
		return;

	CryptoPP::GCM<CryptoPP::AES>::Encryption setKey;
	GenerateKeys::generateKeyAESGCM(key, iv);
	setKey.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

	std::string serializedKeyAndIv = Encode::serializeKeyAndIV(key, sizeof(key), iv, sizeof(iv));
	if (!Send::Client::sendEncryptedAESKey(ssl, serializedKeyAndIv, amountOfKeys))
		return;

	std::thread(receiveMessages, ssl).detach();

	std::cout << "You can now chat" << std::endl;
	while (1)
	{
		std::string message;
		std::getline(std::cin, message);

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

	CreateDirectory makeKeysDir(keysDirectory);
	CreateDirectory makeReceivedKeysDir(receivedKeysDirectory);

	GenerateKeys::generateCertAndPrivateKey(clientPrivateKeyCertPath, clientCertPath);

	SSL_CTX *ctx = SSLSetup::createCTX(TLS_client_method());
	SSLSetup::configureCTX(ctx, clientCertPath, clientPrivateKeyCertPath);

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

		DeletePath deleteKeysDirectory(keysDirectory);
		DeletePath deleteReceivedKeysDirectory(receivedKeysDirectory);
		_exit(signal); // seg fault here
	};

	SSL_connect(ssl) <= 0 ? ERR_print_errors_fp(stderr) : communicateWithServer(ssl);

	CleanUp::Client::cleanUpClient();
	return 0;
}
