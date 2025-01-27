#pragma once

#include <iostream>
#include "config.hpp"
#include "file_handling.hpp"
#include "signals.hpp"
#include "send_receive.hpp"
#include "encryption.hpp"
#include "bcrypt.h"

class Validate
{
public:
	class Server
	{
	private:
		static bool checkServerUserLimit(SSL *ssl)
		{
			std::string signalMessage;

			if (ServerStorage::clientSSLSockets.size() >= ServerConfig::SERVER_USER_LIMIT)
				signalMessage = Signals::SignalManager::getSignalMessageWithSignalStringAppended(Signals::SignalType::SERVERLIMIT);

			Signals::SignalManager::printSignalServerMessage(Signals::SignalManager::getSignalTypeFromMessage(signalMessage));

			if (!signalMessage.empty())
				if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, signalMessage.data(), signalMessage.size()))
					return false;

			return signalMessage.empty() ? true : false;
		}

		static bool checkAndVerifyServerPassword(SSL *ssl)
		{
			std::string signalMessage = Signals::SignalManager::getSignalMessageWithSignalStringAppended(ServerConfig::SERVER_HASHED_PASSWORD.empty() ? Signals::SignalType::PASSWORDNOTNEEDED : Signals::SignalType::PASSWORDNEEDED);

			Signals::SignalManager::printSignalServerMessage(Signals::SignalManager::getSignalTypeFromMessage(signalMessage));

			if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, signalMessage.data(), signalMessage.size()))
				return false;

			if (ServerConfig::SERVER_HASHED_PASSWORD.empty() && !ServerConfig::PASSWORD_REQUIRED) // check if server even has a password then it exits with true if not
				return true;

			std::string receivedPassword;
			if ((receivedPassword = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
				return false;

			std::cout << "Hashed password received: " << receivedPassword << std::endl;

			EVP_PKEY *serverPrivateKey = LoadKey::LoadPrivateKey(FilePaths::serverPrivateKeyPath);

			if (!serverPrivateKey)
				return false;

			receivedPassword = Decrypt::decryptDataRSA(serverPrivateKey, Decode::base64Decode(receivedPassword));

			EVP_PKEY_free(serverPrivateKey);

			std::cout << "Validating password sent by client" << std::endl;

			if (!bcrypt::validatePassword(receivedPassword, ServerConfig::SERVER_HASHED_PASSWORD))
				signalMessage = Signals::SignalManager::getSignalMessageWithSignalStringAppended(Signals::SignalType::INCORRECTPASSWORD);
			else
				signalMessage = Signals::SignalManager::getSignalMessageWithSignalStringAppended(Signals::SignalType::CORRECTPASSWORD);

			Signals::SignalManager::printSignalServerMessage(Signals::SignalManager::getSignalTypeFromMessage(signalMessage));

			if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, signalMessage.data(), signalMessage.size()))
				return false;

			return Signals::SignalManager::getSignalTypeFromMessage(signalMessage) == Signals::SignalType::INCORRECTPASSWORD ? false : true;
		}

	public:
		static bool checkClientUsernameValidity(SSL *ssl, const std::string &clientUsername)
		{
			std::string signalMessage;

			// checks if username already exists
			if (ServerStorage::clientPublicKeys.find(clientUsername) != ServerStorage::clientPublicKeys.end())
				signalMessage = Signals::SignalManager::getSignalMessageWithSignalStringAppended(Signals::SignalType::NAMEEXISTSERR);

			// check if client username is invalid in length
			if (clientUsername.size() <= ServerConfig::MIN_USERNAME_LENGTH || clientUsername.size() > ServerConfig::MAX_USERNAME_LENGTH)
				signalMessage = Signals::SignalManager::getSignalMessageWithSignalStringAppended(Signals::SignalType::INVALIDNAMELENGTH);

			// check if client username contains unallowed characters
			for (char i : clientUsername)
				if (ServerConfig::UNALLOWED_CHARACTERS.find(i) != std::string::npos)
					signalMessage = Signals::SignalManager::getSignalMessageWithSignalStringAppended(Signals::SignalType::INVALIDNAME);

			if (signalMessage.empty())
				signalMessage = Signals::SignalManager::getSignalMessageWithSignalStringAppended(Signals::SignalType::UNKNOWN);

			Signals::SignalManager::printSignalServerMessage(Signals::SignalManager::getSignalTypeFromMessage(signalMessage));

			if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, signalMessage.data(), signalMessage.size()))
				return false;

			return Signals::SignalManager::getSignalTypeFromMessage(signalMessage) == Signals::SignalType::UNKNOWN ? true : false;
		}

		static bool handleClientPreChecks(SSL *ssl)
		{
			if (!checkServerUserLimit(ssl))
				return false;
			if (!checkAndVerifyServerPassword(ssl))
				return false;

			return true;
		}
	};

	class Client
	{
	public:
		static void sendServerPassword(SSL *ssl)
		{
			EVP_PKEY *serverPublicKey = LoadKey::LoadPublicKey(FilePaths::clientServerPublicKeyPath);

			if (!serverPublicKey)
				raise(SIGINT);

			std::string password;
			std::getline(std::cin, password);

			password = Encode::base64Encode(Encrypt::encryptDataRSA(serverPublicKey, bcrypt::generateHash(password)));

			EVP_PKEY_free(serverPublicKey);

			if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, password.data(), password.size()))
				raise(SIGINT);

			std::cout << "Verifying password.." << std::endl;

			std::string isPasswordVerified;
			if ((isPasswordVerified = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
				raise(SIGINT);

			HandleSignal(Signals::SignalManager::getSignalTypeFromMessage(isPasswordVerified), isPasswordVerified, NULLPTR, 0, NULLPTR, 0, ssl);
		}
	};
};

class SetServerPassword
{
private:
	void printPasswordMenu() const
	{
		std::cout << "=== Password Menu ===" << std::endl;
		std::cout << "1: Set a password for the server" << std::endl;
		std::cout << "2: Do not set a password for the server" << std::endl;
		std::cout << "0: Exit" << std::endl;
		std::cout << "Enter your choice: ";
	}

	std::string trimPassword(std::string &password) const
	{
		password.erase(password.begin(), std::find_if(password.begin(), password.end(), [](unsigned char ch)
													  { return !std::isspace(ch); }));
		password.erase(std::find_if(password.rbegin(), password.rend(), [](unsigned char ch)
									{ return !std::isspace(ch); })
						   .base(),
					   password.end());

		return password;
	}

	void handleSetPassword() const
	{
		std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
		std::cout << "Enter password to set: ";
		std::string password;
		std::getline(std::cin, password);

		password = trimPassword(password);

		if (password.empty())
		{
			std::cout << "Password cannot be empty. Exiting." << std::endl;
			exit(EXIT_FAILURE);
		}

		ServerConfig::PASSWORD_REQUIRED = true;
		ServerConfig::SERVER_HASHED_PASSWORD = bcrypt::generateHash(password);

		password.clear();
		std::cout << "Server password has been set. Password Hash: " << ServerConfig::SERVER_HASHED_PASSWORD << std::endl;
	}

	void handleNoPassword() const
	{
		ServerConfig::PASSWORD_REQUIRED = false;
		std::cout << "Server has started up without a password." << std::endl;
	}

	int getValidatedChoice() const
	{
		int choice;
		std::cin >> choice;

		if (std::cin.fail())
		{
			std::cout << "Invalid input. Exiting." << std::endl;
			exit(EXIT_FAILURE);
		}

		return choice;
	}

public:
	SetServerPassword()
	{
		printPasswordMenu();
		int choice = getValidatedChoice();

		switch (choice)
		{
		case 1:
			handleSetPassword();
			break;
		case 2:
			handleNoPassword();
			break;
		case 0:
			std::cout << "Exiting the setup menu." << std::endl;
			break;
		default:
			std::cout << "Invalid choice. Exiting." << std::endl;
			exit(EXIT_FAILURE);
		}
	}
};
