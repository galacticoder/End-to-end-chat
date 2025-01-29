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
		CLIENTMESSAGE,
		SERVERMESSAGE,
		UNKNOWN
	};

	class SignalManager
	{
	protected:
		static inline std::vector<size_t> signalStringSizes;

		static inline std::vector<std::string> signalStringsVector = {
			"CORRECTPASSWORD", "INCORRECTPASSWORD", "NAMEEXISTSERR", "RATELIMITED", "USERLIMITREACHED", "PASSWORDNEEDED", "PASSWORDNOTNEEDED", "INVALIDNAMECHARS", "INVALIDNAMELENGTH", "BLACKLISTED", "NEWAESKEY", "CLIENTMESSAGE", "SERVERMESSAGE", "UNKNOWN"};

		static inline std::vector<std::string> serverSidePrintSignalMessageVector = {"Client entered the correct server password.", "Client entered incorrect server password.", "Client attempted to join with username that already exists.", "Client attempted to join while rate limited.", "Client attempted to join past server user limit set.", "Sent client password needed signal. Waiting for password...", "Server set without password.", "Client username contains invalid characters.", "Client username is an invalid length.", "Blacklisted client attempted to join server."};

		static inline std::vector<std::string> serverMessages = {
			"Correct password entered.", "Wrong password. You have been kicked.", "Username already exists on server.", "Rate limit reached. Try again later.", "User limit reached. Exiting.", "Enter the server password to join.", "Welcome to the server.", "Username contains invalid characters.", "Username is an invalid length", "You are blacklisted from the server.", "", "", "", ""};

	public:
		SignalManager()
		{
			if (signalStringSizes.empty())
				for (size_t i = 0; i < signalStringsVector.size(); i++)
					signalStringSizes.push_back((signalStringsVector[i]).length());
		}

		static void printSignalServerMessage(SignalType signalType)
		{
			if (static_cast<size_t>(signalType) <= serverSidePrintSignalMessageVector.size())
				std::cout << serverSidePrintSignalMessageVector[static_cast<size_t>(signalType)] << std::endl;

			if (static_cast<size_t>(signalType) > signalStringsVector.size())
				std::cerr << fmt::format("[{}] Invalid signal type: {}", __FUNCTION__, static_cast<int>(signalType)) << std::endl;
		}

		static std::string getSignalMessage(SignalType signalType)
		{
			if (static_cast<size_t>(signalType) <= serverMessages.size())
				return Encode::base64Encode(serverMessages[static_cast<size_t>(signalType)]);

			std::cerr << fmt::format("Invalid signal type: {}", static_cast<int>(signalType)) << std::endl;
			return "";
		}

		static std::string getSignalAsString(SignalType signalType)
		{
			if (static_cast<size_t>(signalType) <= signalStringsVector.size())
				return signalStringsVector[static_cast<size_t>(signalType)];

			std::cerr << fmt::format("Invalid signal type: {}", static_cast<size_t>(signalType)) << std::endl;
			return "";
		}

		static std::string getSignalMessageWithSignalStringAppended(SignalType signalType)
		{
			if (static_cast<size_t>(signalType) <= serverMessages.size())
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

class HandleSignal : private Signals::SignalManager
{
private:
	static void printSignalMessage(Signals::SignalType signalType, const std::string &message)
	{
		std::string extractedMessage = message.substr(0, message.size() - signalStringSizes[static_cast<size_t>(signalType)]);
		std::cout << Decode::base64Decode(extractedMessage) << std::endl;
	};

	static void printServerMessage(std::string &message)
	{
		message = message.substr(0, message.size() - signalStringSizes[static_cast<size_t>(Signals::SignalType::SERVERMESSAGE)]);
		message = Decode::base64Decode(message);

		EVP_PKEY *privateKey = LoadKey::loadPrivateKey(FilePaths::clientPrivateKeyPath, false);
		message = Decrypt::decryptDataRSA(privateKey, message);
		EVP_PKEY_free(privateKey);

		std::cout << message << std::endl;
	}

	static void printClientMessage(std::string &message, CryptoPP::byte *key, size_t &keySize, CryptoPP::byte *iv, size_t &ivSize)
	{
		message = message.substr(0, message.size() - signalStringSizes[static_cast<size_t>(Signals::SignalType::CLIENTMESSAGE)]);
		std::string username = message.substr(message.find("|") + 1);
		message = message.substr(0, message.find("|"));
		Decode::deserializeIV(message, iv, ivSize);
		std::string decryptedMessage = Decrypt::decryptDataAESGCM(message, key, keySize, iv, ivSize);
		std::cout << fmt::format("{}: {}", username, decryptedMessage) << std::endl;
	}

	static void setNewAesKey(std::string &message, CryptoPP::byte *key, size_t &keySize, CryptoPP::byte *iv, size_t &ivSize)
	{
		CryptoPP::GCM<CryptoPP::AES>::Encryption setNewKey;

		message = message.substr(0, message.size() - Signals::SignalManager::getSignalAsString(Signals::SignalType::NEWAESKEY).size());
		message = Decode::base64Decode(message);

		EVP_PKEY *privateKey = LoadKey::loadPrivateKey(FilePaths::clientPrivateKeyPath, false);
		message = Decrypt::decryptDataRSA(privateKey, message);
		EVP_PKEY_free(privateKey);

		Decode::deserializeKeyAndIV(message, key, keySize, iv, ivSize);
		setNewKey.SetKeyWithIV(key, keySize, iv, ivSize);
	}

public:
	HandleSignal(Signals::SignalType signalType, std::string &message, CryptoPP::byte *key = NULLPTR, size_t keySize = 0, CryptoPP::byte *iv = NULLPTR, size_t ivSize = 0)
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
			break;
		case Signals::SignalType::NEWAESKEY:
			setNewAesKey(message, key, keySize, iv, ivSize);
			break;
		case Signals::SignalType::CLIENTMESSAGE:
			printClientMessage(message, key, keySize, iv, ivSize);
			break;
		case Signals::SignalType::SERVERMESSAGE:
			printServerMessage(message);
			break;
		}
	}
};