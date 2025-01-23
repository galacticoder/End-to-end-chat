#pragma once

#include <iostream>
#include "config.hpp"
#include "signals.hpp"

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
			signalMessage = Signals::SignalManager::getSignalMessage(Signals::SignalType::NAMEEXISTSERR);
			signalMessage.append(Signals::SignalManager::getSignalAsString(Signals::SignalType::NAMEEXISTSERR));
		}

		// check if client username is invalid in length
		if (clientUsername.size() <= ServerConfig::MIN_USERNAME_LENGTH || clientUsername.size() > ServerConfig::MAX_USERNAME_LENGTH)
		{
			std::cout << "Client with invalid username length has attempted to join." << std::endl;
			signalMessage = Signals::SignalManager::getSignalMessage(Signals::SignalType::INVALIDNAMELENGTH);
			signalMessage.append(Signals::SignalManager::getSignalAsString(Signals::SignalType::INVALIDNAMELENGTH));
		}

		// check if client username contains unallowed characters
		for (char i : clientUsername)
		{
			if (ServerConfig::unallowedCharacters.find(i) != std::string::npos)
			{
				std::cout << "Client username contains invalid chars." << std::endl;
				signalMessage = Signals::SignalManager::getSignalMessage(Signals::SignalType::INVALIDNAME);
				signalMessage.append(Signals::SignalManager::getSignalAsString(Signals::SignalType::INVALIDNAME));
			}
		}

		if (!signalMessage.empty())
		{
			if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, signalMessage.data(), signalMessage.size()))
				return false;
			return false;
		}
		else
		{
			signalMessage = Signals::SignalManager::getSignalMessage(Signals::SignalType::UNKNOWN);
			signalMessage.append(Signals::SignalManager::getSignalAsString(Signals::SignalType::UNKNOWN));

			if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, signalMessage.data(), signalMessage.size()))
				return false;
			return true;
		}

		return true;
	}
};