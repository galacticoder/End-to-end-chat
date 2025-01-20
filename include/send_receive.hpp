#pragma once

#include <iostream>
#include "encryption.hpp"
#include "file_handling.hpp"
#include "keys.hpp"
#include "config.hpp"

#define WRAP_STRING_LITERAL(str) ([]() constexpr { return StringLiteral<sizeof(str)>(str); }())

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

	class Server
	{
	public:
		static bool broadcastMessage(SSL *ssl, std::string &message)
		{
			std::cout << "In broadcast" << std::endl;
			for (SSL *socket : ServerStorage::clientSSLSockets)
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
	};

	class Client
	{
	public:
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

				std::string encryptedAesKey = (Encode::base64Encode(Encrypt::encryptDataRSA(loadedPublicKey, aesKey))).append("AESkey").append(fmt::format(":{}", i - 1));

				std::cout << "Encrypted aes key: " << encryptedAesKey << std::endl;

				if (!sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, encryptedAesKey.data(), encryptedAesKey.size()))
					return false;

				EVP_PKEY_free(loadedPublicKey);
			}

			std::cout << "Sent encrypted aes key to users" << std::endl;
			return true;
		}
	};
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

	class Client
	{
	public:
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
	};

	class Server
	{
	public:
		static bool receiveAndSendEncryptedAesKey(SSL *ssl)
		{
			std::string amountOfUsers;
			if ((amountOfUsers = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
				return false;

			if (std::stoi(amountOfUsers) > 0)
			{
				for (int i = 0; i < std::stoi(amountOfUsers); i++)
				{
					std::string encryptedAesKey;
					if ((encryptedAesKey = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
						return false;

					std::cout << "Public key data: " << encryptedAesKey << std::endl;

					int extractedIndex = stoi(encryptedAesKey.substr(encryptedAesKey.find(":") + 1));

					std::cout << fmt::format("Sending aes key to client SSL socket index: {}", extractedIndex) << std::endl;

					if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ServerStorage::clientSSLSockets[extractedIndex], encryptedAesKey.data(), encryptedAesKey.size()))
						return false;

					std::cout << fmt::format("Sent aes key to client SSL socket index: {}", extractedIndex) << std::endl;
				}

				std::cout << "Sent all aes keys" << std::endl;
			}

			return true;
		}
	};
};