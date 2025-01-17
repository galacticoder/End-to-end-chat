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
#include "../include/keys.hpp"
#include "../include/file_handling.hpp"
#include "../include/networking.hpp"
#include "../include/encryption.hpp"

std::function<void(int)> shutdownHandler;
void signalHandle(int signal) { shutdownHandler(signal); }

CryptoPP::byte key[CryptoPP::AES::MAX_KEYLENGTH];
CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];

std::string base64Decode(const std::string &input)
{
	std::string decoded;
	CryptoPP::StringSource(input, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
	return decoded;
}

void ReceiveMessages(SSL *ssl)
{
	while (true)
	{
		std::string message;

		if ((message = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
			return;

		// SignalType anySignalReceive = SignalHandling::getSignalType(receivedMessage);
		// SignalHandling::handleSignal(anySignalReceive, receivedMessage, ssl, receivedPublicKey);
		// when it looks like a random exit its cuz it didnt receive a key properly so pause the other client from sending messages till after this guy receives the key

		if (message.find("AESkey") != std::string::npos)
		{
			std::cout << "Aeskey new" << std::endl;
			std::string aesKey = message.substr(0, message.find("AESkey") - 6);
			// aesKey = base64Decode(aesKey);
			std::cout << "Extracted AES key size: " << aesKey.size() << std::endl;
			std::cout << "Key size: " << sizeof(key) << ", IV size: " << sizeof(iv) << std::endl;
			// decyrpt with private key rsa
			std::cout << "Here3" << std::endl;
			Deserialize::deserializeKeyAndIV(aesKey, key, sizeof(key), iv, sizeof(iv));
			std::cout << "Here4" << std::endl;
		}
		else
		{
			std::cout << "Here1" << std::endl;
			Deserialize::deserializeIV(message, iv, sizeof(iv));
			std::cout << "Here2" << std::endl;
			std::cout << "Message: " << message << std::endl;
			std::string decryptedMessage = Decrypt::decryptDataAESGCM(message, key, sizeof(key), iv, sizeof(iv));
			std::cout << "Received message: " << decryptedMessage << std::endl;
		}

		// std::string decodedMessage = Decode::Base64Decode(receivedMessage);
		// std::string decryptedMessage = Decrypt::DecryptData(privateKey, decodedMessage);

		// std::string message = GetFormattedMessage(decryptedMessage, (messageType == 'C') ? clientInfo[2] : "");

		// clientInfo.clear();
		// messageType = '\0';
		// printAndRefreshWindow(subwin, inputWindow, message);
	}
}

void communicateWithServer(SSL *ssl)
{
	// send rsa key
	GenerateKeys::generateRSAKeys(clientPrivateKeyPath, clientPublicKeyPath);
	std::cout << "Made rsa keys" << std::endl;

	// const std::string publicKeyData = ReadFile::ReadPemKeyContents(clientPublicKeyPath);
	// SSL_write(ssl, publicKeyData.data(), publicKeyData.length());

	// int amountOfKeys;

	// if (!Receive::receiveAllPublicKeys(ssl, &amountOfKeys))
	// 	return;

	// std::cout << "keys: " << amountOfKeys << std::endl;

	//------------
	CryptoPP::GCM<CryptoPP::AES>::Encryption encryption;

	GenerateKeys::generateKeyAESGCM(key, iv);
	encryption.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

	// send to all users but encrypt with their pub key first
	std::string serializedKeyAndIv = Serialize::serializeKeyAndIV(key, sizeof(key), iv, sizeof(iv));

	if (!Send::sendEncryptedAESKey(ssl, serializedKeyAndIv))
		return;

	std::thread(ReceiveMessages, ssl).detach();

	while (1)
	{
		std::string message;
		std::getline(std::cin, message);
		std::string ciphertext = Encrypt::encryptDataAESGCM(message, key, sizeof(key));

		if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, ciphertext.data(), ciphertext.size()))
		{
			std::cout << "Server shutdown" << std::endl;
			return;
		}
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
