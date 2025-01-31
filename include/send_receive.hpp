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

namespace Receive
{
	template <StringLiteral file, int line>
	static std::string receiveMessage(SSL *ssl);
}

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

		static void broadcastClientJoinOrExitMessage(SSL *ssl, const std::string &clientUsername, std::map<std::string, std::string> &clientPublicKeys, std::vector<SSL *> &clientSSLSockets, const std::string &signalString, const bool isJoining)
		{
			std::string message = fmt::format("{} has {} the chat", clientUsername, isJoining ? "joined" : "left");
			std::cout << fmt::format("Broadcasting client {} message: {}", isJoining ? "join" : "exit", message) << std::endl;

			for (auto const &[key, val] : clientPublicKeys)
			{
				if (key != clientUsername)
				{
					EVP_PKEY *loadKey = LoadKey::loadPublicKeyInMemory(val);

					std::string encryptedMessage = Encode::base64Encode(Encrypt::encryptDataRSA(loadKey, message)).append(signalString);

					EVP_PKEY_free(loadKey);

					for (SSL *socket : clientSSLSockets)
						if (socket != ssl)
							if (!sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(socket, encryptedMessage.data(), encryptedMessage.size()))
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
		static bool sendEncryptedAESKey(SSL *ssl, std::string &aesKey, const std::string &signalString, std::vector<std::string> &publicKeys)
		{
			std::string amountOfUsers;
			if (amountOfUsers = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl); amountOfUsers.empty())
				return false;

			if (stoi(amountOfUsers) <= 0)
				return true;

			for (int i = 0; i < stoi(amountOfUsers); i++)
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
	static std::string receiveMessage(SSL *ssl)
	{
		char buffer[4096];
		int bytesRead = SSL_read(ssl, buffer, 4096);

		if (!SSLerrors::checkBytesError(ssl, bytesRead, std::string(file.value.data()), line, "write"))
			return "";

		buffer[bytesRead] = '\0';
		return std::string(buffer, bytesRead);
	}

	struct Server
	{
		static bool receiveAndSendEncryptedAesKey(SSL *ssl, std::vector<SSL *> &clientSSLSockets, std::map<std::string, std::string> &clientPublicKeys)
		{
			std::string amountOfUsers = std::to_string(clientPublicKeys.size() - 1); // -1 for the current user
			if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, amountOfUsers.c_str(), amountOfUsers.size()))
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
		static bool receiveAllRSAPublicKeys(SSL *ssl, std::vector<std::string> &publicKeys)
		{
			std::string amountOfUsers;
			if (amountOfUsers = receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl); amountOfUsers.empty())
				return false;

			if (std::stoi(amountOfUsers) <= 0)
				return true;

			for (int i = 0; i < std::stoi(amountOfUsers); i++)
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