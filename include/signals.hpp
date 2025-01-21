#pragma once

#include <iostream>
#include <vector>
#include <csignal>
#include <algorithm>
#include <fmt/core.h>
#include "send_receive.hpp"
#include "encryption.hpp"

namespace Signals
{
	enum class SignalType
	{
		KEYLOADERR,
		KEYEXISTERR,
		CORRECTPASSWORD,
		INCORRECTPASSWORD,
		NAMEEXISTSERR,
		RATELIMITED,
		SERVERLIMIT,
		PASSWORDNEEDED,
		PASSWORDNOTNEEDED,
		INVALIDNAME,
		INVALIDNAMELENGTH,
		BLACKLISTED,
		UNKNOWN
	};

	class SignalManager
	{
	protected:
		static inline std::vector<size_t> signalStringSizes;

		static inline std::vector<std::string> signalStringsVector = {
			"KEYLOADERROR", "KEYEXISTERR", "CORRECTPASSWORD", "INCORRECTPASSWORD", "NAMEEXISTSERR", "RATELIMITED", "USERLIMITREACHED", "PASSWORDNEEDED", "PASSWORDNOTNEEDED", "INVALIDNAMECHARS", "INVALIDNAMELENGTH", "BLACKLISTED"};

		static inline std::vector<std::string> serverMessages = {
			"Public key could not be loaded on the server.",
			"Username already exists. You have been kicked.",
			"Correct password entered.",
			"Wrong password. You have been kicked.",
			"Username already exists on server.",
			"Rate limit reached. Try again later.",
			"User limit reached. Exiting.",
			"Enter the server password to join.",
			"Welcome to the server.",
			"Username contains invalid characters.",
			"", // invalid name length is set later
			"You are blacklisted from the server."};

	public:
		SignalManager()
		{
			for (size_t i = 0; i < signalStringsVector.size(); i++)
				signalStringSizes.push_back((signalStringsVector[i]).length());

			std::cout << fmt::format("signalStringSize vector filled with sizes of strings. vector size: {}", signalStringSizes.size()) << std::endl;
		}

		static std::string getPreloadedMessage(SignalType signalType)
		{
			size_t index = static_cast<size_t>(signalType);

			if (index < serverMessages.size())
				return serverMessages[index];

			std::cerr << fmt::format("Invalid signal type: {}", static_cast<int>(signalType)) << std::endl;
			return "";
		}

		static std::string getSignalAsString(SignalType signalType)
		{
			if (static_cast<size_t>(signalType) < signalStringsVector.size())
				return signalStringsVector[static_cast<size_t>(signalType)];

			std::cerr << fmt::format("Invalid signal type: {}", static_cast<size_t>(signalType)) << std::endl;
			return "";
		}

		static SignalType getSignalTypeFromMessage(const std::string &message)
		{
			if (message.empty()) // instead of sending an okay signal
				return Signals::SignalType::UNKNOWN;

			for (size_t i = 0; i < signalStringsVector.size(); i++)
			{
				if (message.find(signalStringsVector[i]) != std::string::npos)
					return static_cast<SignalType>(i);
			}

			return SignalType::UNKNOWN;
		}
	};
}

class HandleSignal : private Signals::SignalManager
{
private:
	static std::string printSignalMessage(Signals::SignalType signalType, const std::string &message)
	{
		std::cout << Decode::base64Decode(message.substr(0, message.size() - signalStringSizes[static_cast<size_t>(signalType)])) << std::endl;
	};

	static inline std::string serverPublicKeyPath = "../received_keys/serverPublicKey.pem";

public:
	HandleSignal(Signals::SignalType signalType, const std::string &message, SSL *ssl)
	{

		if (signalType == Signals::SignalType::UNKNOWN)
			return;

		switch (signalType)
		{
		case Signals::SignalType::PASSWORDNOTNEEDED:
		case Signals::SignalType::CORRECTPASSWORD:
			printSignalMessage(signalType, message);
			break;
		case Signals::SignalType::KEYLOADERR:
		case Signals::SignalType::KEYEXISTERR:
		case Signals::SignalType::INCORRECTPASSWORD:
		case Signals::SignalType::NAMEEXISTSERR:
		case Signals::SignalType::RATELIMITED:
		case Signals::SignalType::SERVERLIMIT:
		case Signals::SignalType::INVALIDNAME:
		case Signals::SignalType::INVALIDNAMELENGTH:
		case Signals::SignalType::BLACKLISTED:
		case Signals::SignalType::UNKNOWN:
			printSignalMessage(signalType, message);
			raise(SIGINT); // handled by the shutdownHandler
			break;

		case Signals::SignalType::PASSWORDNEEDED:
			EVP_PKEY *serverPublicKey = LoadKey::LoadPublicKey(serverPublicKeyPath);

			if (!serverPublicKey)
			{
				std::cout << "Cannot load server's public key. Exiting." << std::endl;
				raise(SIGINT);
			}

			std::string password;
			std::getline(std::cin, password);

			std::string encryptedPassword = Encode::base64Encode(Encrypt::encryptDataRSA(serverPublicKey, password));

			EVP_PKEY_free(serverPublicKey);

			if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, encryptedPassword.c_str(), encryptedPassword.size()))
				raise(SIGINT);

			std::cout << "Verifying password.." << std::endl;

			std::string passwordVerification;

			if ((passwordVerification = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
				raise(SIGINT);

			printSignalMessage(Signals::SignalManager::getSignalTypeFromMessage(passwordVerification), message);

			if (Signals::SignalManager::getSignalTypeFromMessage(passwordVerification) != Signals::SignalType::CORRECTPASSWORD)
				raise(SIGINT);

			break;
		}
	}
};