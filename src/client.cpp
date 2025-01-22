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

std::function<void(int)> shutdownHandler;
void signalHandle(int signal) { shutdownHandler(signal); }

CryptoPP::byte key[CryptoPP::AES::MAX_KEYLENGTH]; // 32 bytes
CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];	  // 16 bytes

void ReceiveMessages(SSL *ssl, const std::string privateKeyPath, CryptoPP::GCM<CryptoPP::AES>::Encryption &encryption)
{
	while (true)
	{
		std::string message;

		if ((message = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
		{
			std::cout << "Server killed" << std::endl;
			// clean up here and exit
			return;
		}

		Signals::SignalType detectSignal = Signals::SignalManager::getSignalTypeFromMessage(message);
		HandleSignal(detectSignal, message, privateKeyPath, encryption, key, sizeof(key), iv, sizeof(iv));

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
	// send rsa key
	std::cout << "Enter username: ";
	std::string username;
	std::getline(std::cin, username);
	std::string publicKey = keysDirectory + username + "PubKey.pem";
	std::string privateKey = keysDirectory + username + "PrivateKey.pem";
	GenerateKeys::generateRSAKeys(privateKey, publicKey);
	std::cout << "Made rsa keys" << std::endl;

	const std::string publicKeyData = ReadFile::ReadPemKeyContents(publicKey);
	// send pub key
	if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, publicKeyData.data(), publicKeyData.size()))
		return;

	// SSL_write(ssl, publicKeyData.data(), publicKeyData.length());

	int amountOfKeys;
	CreateDirectory("../received_keys");

	if (!Receive::Client::receiveAllPublicKeys(ssl, &amountOfKeys))
		return;

	CryptoPP::GCM<CryptoPP::AES>::Encryption encryption;

	GenerateKeys::generateKeyAESGCM(key, iv);
	encryption.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

	std::string serializedKeyAndIv = Encode::serializeKeyAndIV(key, sizeof(key), iv, sizeof(iv));

	if (!Send::Client::sendEncryptedAESKey(ssl, serializedKeyAndIv, amountOfKeys))
		return;

	std::thread(ReceiveMessages, ssl, privateKey, std::ref(encryption)).detach();

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
	GenerateKeys::generateCertAndPrivateKey(clientPrivateKeyCertPath, clientCertPath);

	SSL_CTX *ctx = SSLSetup::createCTX(TLS_client_method());
	SSLSetup::configureCTX(ctx, clientCertPath, clientPrivateKeyCertPath);

	const std::string serverIpAddress = "127.0.0.1";
	const int port = 8080;

	int socketfd = Networking::startClientSocket(port, serverIpAddress);

	shutdownHandler = [&](int signal)
	{
		std::cout << fmt::format("\nSignal {} caught. Exiting.", strsignal(signal)) << std::endl;
		close(socketfd);
		SSL_CTX_free(ctx);
		DeletePath deleteDirectory(keysDirectory);
		exit(signal);
	};

	std::signal(SIGINT, signalHandle);

	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, socketfd);

	SSL_connect(ssl) <= 0 ? ERR_print_errors_fp(stderr) : communicateWithServer(ssl);

	SSL_shutdown(ssl);
	SSL_free(ssl);
	DeletePath deleteDirectory(keysDirectory);
	close(socketfd);

	SSL_CTX_free(ctx);
	return 0;
}
