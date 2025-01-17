#pragma once

#include <iostream>
#include <sys/socket.h>
#include <boost/asio.hpp>
#include <fmt/core.h>
#include <netinet/in.h>
#include <unistd.h>
#include "file_handling.hpp"
#include "encryption.hpp"
#include "config.hpp"

#define WRAP_STRING_LITERAL(str) ([]() constexpr { return StringLiteral<sizeof(str)>(str); }())

class Networking
{
private:
	static bool isPortAvailable(int &port)
	{
		int pavtempsock;
		struct sockaddr_in addr;
		bool available = false;

		pavtempsock = socket(AF_INET, SOCK_STREAM, 0);

		if (pavtempsock < 0)
		{
			std::cerr << "Cannot create socket to test port availability" << std::endl;
			return false;
		}

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_ANY;
		addr.sin_port = htons(port);

		bind(pavtempsock, (struct sockaddr *)&addr, sizeof(addr)) < 0 ? available = false : available = true;

		close(pavtempsock);
		return available;
	}

public:
	static int findAvailablePort()
	{
		int defaultPort = 8080;

		if (isPortAvailable(defaultPort))
			return defaultPort;

		for (int i = 49152; i <= 65535; i++)
		{
			if (isPortAvailable(i))
				return i;
		}

		return -1;
	}

	static int startServerSocket(int port)
	{
		int sockfd = socket(AF_INET, SOCK_STREAM, 0);

		if (sockfd < 0)
		{
			std::cerr << "Error opening server socket" << std::endl;
			exit(EXIT_FAILURE);
		}

		sockaddr_in serverAddress;
		int opt = 1;

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
		{
			perror("setsockopt");
			exit(EXIT_FAILURE);
		}

		serverAddress.sin_family = AF_INET;
		serverAddress.sin_port = htons(port);
		serverAddress.sin_addr.s_addr = INADDR_ANY;

		if (bind(sockfd, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
		{
			std::cout << "Chosen port isn't available" << std::endl;
			exit(EXIT_FAILURE);
		}

		listen(sockfd, 5);
		std::cout << fmt::format("Server listening on port {}", port) << std::endl;

		return sockfd;
	}

	static int startClientSocket(int port, const std::string &serverIpAddress)
	{
		int sockfd = socket(AF_INET, SOCK_STREAM, 0);
		if (sockfd < 0)
		{
			perror("Unable to create socket");
			exit(EXIT_FAILURE);
		}

		struct sockaddr_in serverAddr;
		serverAddr.sin_family = AF_INET;
		serverAddr.sin_port = htons(port);

		if (inet_pton(AF_INET, serverIpAddress.c_str(), &serverAddr.sin_addr) <= 0)
		{
			perror("Invalid address or address not supported");
			exit(EXIT_FAILURE);
		}

		if (connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
		{
			perror("Unable to connect");
			exit(EXIT_FAILURE);
		}

		return sockfd;
	}

	static int acceptClientConnection(int &serverSocket)
	{
		sockaddr_in clientAddress;
		socklen_t clientLen = sizeof(clientAddress);
		return accept(serverSocket, (struct sockaddr *)&clientAddress, &clientLen);
	}
};

template <size_t N>
struct StringLiteral
{
	constexpr StringLiteral(const char (&str)[N])
	{
		std::copy_n(str, N, value);
	}

	char value[N];
};

class Send : public Encrypt
{
protected:
	static void printSSLError(int sslError)
	{
		char buffer[256];
		ERR_error_string_n(sslError, buffer, sizeof(buffer));
		std::cerr << "SSL Error: " << buffer << std::endl;
	}

public:
	template <StringLiteral file, int line>
	static bool sendMessage(SSL *ssl, const char *data, int length)
	{
		int bytesWritten = SSL_write(ssl, data, length);
		if (bytesWritten <= 0)
		{
			int sslError = SSL_get_error(ssl, bytesWritten);
			std::cerr << fmt::format("[{}]:[{}] SSL_write failed: ", file.value, line);
			printSSLError(sslError);
			return false;
		}

		return true;
	}

	static bool broadcastMessage(SSL *ssl, std::string &message)
	{
		std::cout << "In broadcast" << std::endl;
		for (SSL *socket : Server::clientSSLSockets)
		{
			if (socket != ssl)
			{
				if (!sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(socket, message.data(), message.size()))
					return false;
			}
		}
		return true;
	}

	static bool sendAllPublicKeys(SSL *ssl, std::vector<std::string> &publicKeysVector, const std::string &userPublicKey)
	{

		std::string amountOfUsers = std::to_string(publicKeysVector.size() - 1); // -1 for the current user

		if (!sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, amountOfUsers.c_str(), amountOfUsers.size()))
			return false;

		// send the amount of keys before sending vector so client can stop receiving
		if (publicKeysVector.size() <= 1)
		{
			std::cout << fmt::format("Skipping sending all public keys, Only {} public key in vector", publicKeysVector.size()) << std::endl;
			return true;
		}

		for (std::string i : publicKeysVector)
		{
			if (i != userPublicKey)
				if (!sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, i.c_str(), i.size()))
					return false;
		};

		std::cout << "Sent all public keys" << std::endl;
		return true;
	}

	static bool sendEncryptedAESKey(SSL *ssl, std::string &aesKey, int &amountOfKeys)
	{
		std::cout << "Sending encrypted aes key" << std::endl;
		if (!sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, std::to_string(amountOfKeys).data(), std::to_string(amountOfKeys).size()))
			return false;

		if (amountOfKeys <= 0)
			return true;

		std::cout << "Raw key: " << aesKey << std::endl;

		for (int i = 1; i <= amountOfKeys; i++)
		{
			std::string keyPath = fmt::format("../received_keys/client{}PublicKey.pem", i);
			std::string keyContents = ReadFile::ReadPemKeyContents(keyPath);
			EVP_PKEY *loadedPublicKey = LoadKey::LoadPublicKey(keyPath);

			std::string encryptedAesKey = (Encode::base64Encode(Encrypt::encryptDataRSA(loadedPublicKey, aesKey)).append("AESkey")).append(fmt::format(":{}", i - 1));

			std::cout << "Encrypted aes key: " << encryptedAesKey << std::endl;

			if (!sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, encryptedAesKey.data(), encryptedAesKey.size()))
				return false;

			EVP_PKEY_free(loadedPublicKey);
		}

		std::cout << "Sent encrypted aes key to users" << std::endl;
		return true;
	}
};

class Receive : public Send
{
public:
	template <StringLiteral file, int line>
	static std::string receiveMessage(SSL *ssl, int bufferLength = 4096)
	{
		char buffer[bufferLength];
		int bytesRead = SSL_read(ssl, buffer, bufferLength);

		if (bytesRead <= 0)
		{
			int sslError = SSL_get_error(ssl, bytesRead);
			std::cerr << fmt::format("[{}]:[{}] SSL_read failed: ", file.value, line);
			printSSLError(sslError);
			return "";
		}

		buffer[bytesRead] = '\0';
		return std::string(buffer, bytesRead);
	}

	static bool receiveAllPublicKeys(SSL *ssl, int *keyAmount)
	{
		std::string amountOfKeys;
		if ((amountOfKeys = receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
			return false;

		int amount = std::stoi(amountOfKeys);
		*keyAmount = amount;

		if (amount <= 0)
		{
			std::cout << "No client keys to receive" << std::endl;
			return true;
		}

		for (int i = 1; i < amount + 1; i++)
		{
			std::string publicKeyData;
			if ((publicKeyData = receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
				return false;
			SaveFile(fmt::format("../received_keys/client{}PublicKey.pem", i), publicKeyData, std::ios::binary);
		}

		return true;
	}

	static bool broadcastAESencryptedKey(SSL *ssl)
	{
		// std::string amountOfKeys;
		// if ((amountOfKeys = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
		// 	return false;

		// if (std::stoi(amountOfKeys) <= 0)
		// 	return true;

		std::cout << "HEREE" << std::endl;

		std::string encryptedAesKey;
		if ((encryptedAesKey = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
			return false;
		std::cout << "HEREE" << std::endl;

		if (!Send::broadcastMessage(ssl, encryptedAesKey))
		{
			return false;
		}
		std::cout << "HEREE" << std::endl;
		// for (int i = 0; i <= std::stoi(amountOfKeys); i++)
		// {
		// std::string keyData;
		// if ((keyData = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
		// 	return false;

		// if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(keyToSockets[keyData], encryptedAesKey.data(), encryptedAesKey.size()))
		// return false;
		// }

		return true;
	}
};