#pragma once

#include <iostream>
#include <vector>
#include <csignal>
#include <algorithm>
#include <fmt/core.h>
#include "encryption.hpp"
#include "file_handling.hpp"
#include "keys.hpp"

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
		NEWAESKEY,
		UNKNOWN
	};

	class SignalManager
	{
	protected:
		static inline std::vector<size_t> signalStringSizes;

		static inline std::vector<std::string> signalStringsVector = {
			"KEYLOADERROR", "KEYEXISTERR", "CORRECTPASSWORD", "INCORRECTPASSWORD", "NAMEEXISTSERR", "RATELIMITED", "USERLIMITREACHED", "PASSWORDNEEDED", "PASSWORDNOTNEEDED", "INVALIDNAMECHARS", "INVALIDNAMELENGTH", "BLACKLISTED", "NEWAESKEY", "UNKNOWN"};

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
			"Username is an invalid length", // invalid name length is set later
			"You are blacklisted from the server.",
			"",	 // no message for new aeskey
			""}; // no message for unknown

	public:
		SignalManager()
		{
			if (signalStringSizes.empty())
				for (size_t i = 0; i < signalStringsVector.size(); i++)
					signalStringSizes.push_back((signalStringsVector[i]).length());
		}

		static std::string getSignalMessage(SignalType signalType)
		{
			if (static_cast<size_t>(signalType) < serverMessages.size())
				return Encode::base64Encode(serverMessages[static_cast<size_t>(signalType)]);

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

		static std::string getSignalMessageWithSignalStringAppended(SignalType signalType)
		{
			if (static_cast<size_t>(signalType) < serverMessages.size())
				return Encode::base64Encode(serverMessages[static_cast<size_t>(signalType)]).append(getSignalAsString(signalType));

			std::cerr << fmt::format("Invalid signal type: {}", static_cast<int>(signalType)) << std::endl;
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

#include "send_receive.hpp"

class HandleSignal : private Signals::SignalManager
{
private:
	static inline std::string serverPublicKeyPath = "../received_keys/serverPublicKey.pem";

	static void printSignalMessage(Signals::SignalType signalType, const std::string &message)
	{
		std::string extractedMessage = message.substr(0, message.size() - signalStringSizes[static_cast<size_t>(signalType)]);
		std::cout << Decode::base64Decode(extractedMessage) << std::endl;
	};

	static void setNewAesKey(std::string &message, CryptoPP::byte *key, size_t &keySize, CryptoPP::byte *iv, size_t &ivSize)
	{
		CryptoPP::GCM<CryptoPP::AES>::Encryption setNewKey;

		message = message.substr(0, message.size() - Signals::SignalManager::getSignalAsString(Signals::SignalType::NEWAESKEY).size());
		message = Decode::base64Decode(message);

		EVP_PKEY *privateKey = LoadKey::LoadPrivateKey(clientPrivateKeyPath);
		message = Decrypt::decryptDataRSA(privateKey, message);

		Decode::deserializeKeyAndIV(message, key, keySize, iv, ivSize);
		setNewKey.SetKeyWithIV(key, keySize, iv, ivSize);

		std::cout << "New key has been set" << std::endl;
	}

	// static bool enterServerPassword(SSL *ssl, const std::string &message)
	// {
	// 	EVP_PKEY *serverPublicKey = LoadKey::LoadPublicKey(serverPublicKeyPath);

	// 	if (!serverPublicKey)
	// 	{
	// 		std::cout << "Cannot load server's public key. Exiting." << std::endl;
	// 		raise(SIGINT);
	// 	}

	// 	std::string password;
	// 	std::getline(std::cin, password);

	// 	std::string encryptedPassword = Encode::base64Encode(Encrypt::encryptDataRSA(serverPublicKey, password));

	// 	EVP_PKEY_free(serverPublicKey);

	// 	if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, encryptedPassword.c_str(), encryptedPassword.size()))
	// 		raise(SIGINT);

	// 	std::cout << "Verifying password.." << std::endl;

	// 	std::string passwordVerification;

	// 	if ((passwordVerification = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
	// 		raise(SIGINT);

	// 	printSignalMessage(Signals::SignalManager::getSignalTypeFromMessage(passwordVerification), message);

	// 	if (Signals::SignalManager::getSignalTypeFromMessage(passwordVerification) != Signals::SignalType::CORRECTPASSWORD)
	// 		raise(SIGINT);

	// 	return true;
	// };

public:
	HandleSignal(Signals::SignalType signalType, std::string &message, CryptoPP::byte *key, size_t keySize, CryptoPP::byte *iv, size_t ivSize)
	{
		switch (signalType)
		{
		case Signals::SignalType::UNKNOWN:
			return;
			break;
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
			printSignalMessage(signalType, message);
			raise(SIGINT); // handled by the shutdownHandler
			break;
		case Signals::SignalType::PASSWORDNEEDED:
			// enterServerPassword(ssl, message); // come back to this later when implementing it
			break;
		case Signals::SignalType::NEWAESKEY:
			setNewAesKey(message, key, keySize, iv, ivSize);
			break;
		}
	}
};