#pragma once

#include <iostream>
#include "encryption.hpp"
#include "keys.hpp"

#define WRAP_STRING_LITERAL(str) ([] { return StringLiteral<sizeof(str)>(str); }())

template <size_t N>
struct StringLiteral
{
	constexpr StringLiteral(const char (&str)[N]) : value{}
	{
		std::copy(str, str + N, value.begin());
	}
	std::array<char, N> value;
};

namespace SSLerrors
{
	static void printSSLError(int sslError)
	{
		char buffer[256];
		ERR_error_string_n(sslError, buffer, sizeof(buffer));
		std::cerr << "SSL Error: " << buffer << std::endl;
	}

	static bool checkBytesError(SSL *ssl, int &bytes, const std::string &file, int line, std::string operation)
	{
		if (bytes <= 0)
		{
			int sslError = SSL_get_error(ssl, bytes);
			std::cerr << fmt::format("[{}]:[{}] SSL_{} failed: ", file, line, operation);
			SSLerrors::printSSLError(sslError);
			return false;
		}
		return true;
	}

}

namespace Send
{
	template <StringLiteral file, int line>
	static bool sendMessage(SSL *ssl, const char *data, int length)
	{
		int bytesWritten = SSL_write(ssl, data, length);
		if (!SSLerrors::checkBytesError(ssl, bytesWritten, std::string(file.value.data()), line, "write"))
			return false;
		return true;
	}

	struct Server
	{
		static bool broadcastMessageToClients(SSL *ssl, std::string &message, std::vector<SSL *> &clientSSLSockets)
		{
			std::cout << "Broadcasting message: " << message << std::endl;
			for (SSL *socket : clientSSLSockets)
				if (socket != ssl)
					if (!sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(socket, message.data(), message.size()))
						return false;
			return true;
		}

		static void broadcastClientExitMessage(SSL *ssl, const std::string &clientUsername, std::map<std::string, std::string> &clientPublicKeys, std::vector<SSL *> &clientSSLSockets, const std::string &signalString)
		{
			std::string exitMessage = fmt::format("{} has left the chat", clientUsername);
			for (auto const &[key, val] : clientPublicKeys)
			{
				if (key != clientUsername)
				{
					EVP_PKEY *loadKey = LoadKey::loadPublicKeyInMemory(val);

					std::string encryptedExitMessage = Encode::base64Encode(Encrypt::encryptDataRSA(loadKey, exitMessage)).append(signalString);

					EVP_PKEY_free(loadKey);

					for (SSL *socket : clientSSLSockets)
						if (socket != ssl)
							if (!sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(socket, encryptedExitMessage.data(), encryptedExitMessage.size()))
								return;
				}
			}
		}

		static bool sendAllPublicKeys(SSL *ssl, const std::string &currentClientUsername, std::map<std::string, std::string> &clientPublicKeys)
		{
			std::string amountOfUsers = std::to_string(clientPublicKeys.size() - 1); // -1 for the current user

			if (!sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, amountOfUsers.c_str(), amountOfUsers.size()))
				return false;

			if (clientPublicKeys.size() <= 1)
				return true;

			for (auto const &[key, val] : clientPublicKeys)
				if (key != currentClientUsername)
					if (!sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, val.c_str(), val.size()))
						return false;

			return true;
		}
	};

	struct Client
	{
		static bool sendEncryptedAESKey(SSL *ssl, std::string &aesKey, const std::string &signalString, std::vector<std::string> &publicKeys, int &amountOfUsers)
		{
			if (!sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, std::to_string(amountOfUsers).data(), std::to_string(amountOfUsers).size()))
				return false;

			if (amountOfUsers <= 0)
				return true;

			for (int i = 0; i < amountOfUsers; i++)
			{
				EVP_PKEY *loadedPublicKey = LoadKey::loadPublicKeyInMemory(publicKeys[i]);
				std::string encryptedAesKey = (Encode::base64Encode(Encrypt::encryptDataRSA(loadedPublicKey, aesKey))).append(signalString + fmt::format(":{}", i));

				if (!sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, encryptedAesKey.data(), encryptedAesKey.size()))
					return false;

				EVP_PKEY_free(loadedPublicKey);
			}

			return true;
		}
	};
};

namespace Receive
{
	template <StringLiteral file, int line>
	static std::string receiveMessage(SSL *ssl, int bufferLength = 4096)
	{
		char buffer[bufferLength];
		int bytesRead = SSL_read(ssl, buffer, bufferLength);

		if (!SSLerrors::checkBytesError(ssl, bytesRead, std::string(file.value.data()), line, "write"))
			return "";

		buffer[bytesRead] = '\0';
		return std::string(buffer, bytesRead);
	}

	struct Server
	{
		static bool receiveAndSendEncryptedAesKey(SSL *ssl, std::map<std::string, std::string> &publicKeys, std::vector<SSL *> &clientSSLSockets)
		{
			std::string amountOfUsers;
			if (amountOfUsers = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl); amountOfUsers.empty())
				return false;

			if (stoi(amountOfUsers) >= 1)
			{
				std::cout << "Sending aes encrypted keys" << std::endl;

				for (int i = 0; i < stoi(amountOfUsers); i++)
				{
					std::string encryptedAesKey;
					if (encryptedAesKey = receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl); encryptedAesKey.empty())
						return false;

					std::cout << "Encrypted AES Key: " << encryptedAesKey << std::endl;

					int extractedIndex = stoi(encryptedAesKey.substr(encryptedAesKey.find(":") + 1));
					std::string encryptedKey = encryptedAesKey.substr(0, encryptedAesKey.find(":"));

					if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(clientSSLSockets[extractedIndex], encryptedKey.data(), encryptedKey.size()))
						return false;
				}
				std::cout << "Sent aes encrypted keys" << std::endl;
			}

			return true;
		}
	};

	struct Client
	{
		static bool receiveAllRSAPublicKeys(SSL *ssl, std::vector<std::string> &publicKeys, int *keysAmount)
		{
			std::string amountOfKeys;
			if (amountOfKeys = receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl); amountOfKeys.empty())
				return false;

			*keysAmount = std::stoi(amountOfKeys);

			if (std::stoi(amountOfKeys) <= 0)
				return true;

			for (int i = 0; i < std::stoi(amountOfKeys); i++)
			{
				std::string publicKeyData;
				if (publicKeyData = receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl); publicKeyData.empty())
					return false;
				publicKeys.push_back(publicKeyData);
			}
			return true;
		}
	};
};