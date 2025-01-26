#pragma once

#include <iostream>
#include "config.hpp"
#include "signals.hpp"
#include "send_receive.hpp"
#include "encryption.hpp"
#include "bcrypt.h"

class ValidateClient
{
public:
	static bool checkClientUsernameValidity(SSL *ssl, const std::string &clientUsername)
	{
		std::string signalMessage;

		// checks if username already exists
		if (ServerStorage::clientPublicKeys.find(clientUsername) != ServerStorage::clientPublicKeys.end())
		{
			std::cout << "Client with the same username detected has attempted to join." << std::endl;
			signalMessage = Signals::SignalManager::getSignalMessageWithSignalStringAppended(Signals::SignalType::NAMEEXISTSERR);
		}

		// check if client username is invalid in length
		if (clientUsername.size() <= ServerConfig::MIN_USERNAME_LENGTH || clientUsername.size() > ServerConfig::MAX_USERNAME_LENGTH)
		{
			std::cout << "Client with invalid username length has attempted to join." << std::endl;
			signalMessage = Signals::SignalManager::getSignalMessageWithSignalStringAppended(Signals::SignalType::INVALIDNAMELENGTH);
		}

		// check if client username contains unallowed characters
		for (char i : clientUsername)
		{
			if (ServerConfig::unallowedCharacters.find(i) != std::string::npos)
			{
				std::cout << "Client username contains invalid chars." << std::endl;
				signalMessage = Signals::SignalManager::getSignalMessageWithSignalStringAppended(Signals::SignalType::INVALIDNAME);
			}
		}

		if (!signalMessage.empty())
		{
			if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, signalMessage.data(), signalMessage.size()))
				;
			return false;
		}
		else
		{
			signalMessage = Signals::SignalManager::getSignalMessageWithSignalStringAppended(Signals::SignalType::UNKNOWN);

			if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, signalMessage.data(), signalMessage.size()))
				return false;
		}

		return true;
	}

	static bool checkServerUserLimit(SSL *ssl)
	{
		std::string signalMessage;

		signalMessage = Signals::SignalManager::getSignalMessageWithSignalStringAppended(ServerStorage::clientSSLSockets.size() >= ServerConfig::SERVER_USER_LIMIT ? Signals::SignalType::SERVERLIMIT : Signals::SignalType::UNKNOWN);

		if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, signalMessage.data(), signalMessage.size()))
			return false;

		return Signals::SignalManager::getSignalTypeFromMessage(signalMessage) == Signals::SignalType::SERVERLIMIT ? false : true;
	}

	static bool checkAndVerifyServerPassword(SSL *ssl, const std::string &serverHashedPassword)
	{
		std::cout << "Waiting to receive password from client.." << std::endl;

		std::string signalMessage = Signals::SignalManager::getSignalMessageWithSignalStringAppended(serverHashedPassword.empty() ? Signals::SignalType::PASSWORDNOTNEEDED : Signals::SignalType::PASSWORDNEEDED);

		if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, signalMessage.data(), signalMessage.size()))
			return false;

		if (serverHashedPassword.empty())
			return true;

		std::string receivedPassword;
		if ((receivedPassword = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl)).empty())
			return false;

		std::cout << "Hashed password received: " << receivedPassword << std::endl;

		EVP_PKEY *serverPrivateKey = LoadKey::LoadPrivateKey(ServerPrivateKeyPath);

		if (!serverPrivateKey)
		{
			std::cout << "Could not load server private key for decryption. Killing server." << std::endl;
			return false;
		}

		receivedPassword = Decode::base64Decode(receivedPassword);
		receivedPassword = Decrypt::decryptDataRSA(serverPrivateKey, receivedPassword);

		EVP_PKEY_free(serverPrivateKey);

		std::cout << "Validating password sent by client" << std::endl;
		if (!bcrypt::validatePassword(receivedPassword, serverHashedPassword))
		{
			signalMessage = Signals::SignalManager::getSignalMessageWithSignalStringAppended(Signals::SignalType::INCORRECTPASSWORD);
			if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, signalMessage.data(), signalMessage.size()))
				return false;
			return false;
		}

		signalMessage = Signals::SignalManager::getSignalMessageWithSignalStringAppended(Signals::SignalType::CORRECTPASSWORD);
		if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, signalMessage.data(), signalMessage.size()))
			return false;

		return true;
	}
};