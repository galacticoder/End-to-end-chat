#pragma once

#include <iostream>
#include "config.hpp"
#include "file_handling.hpp"
#include "signals.hpp"
#include "send_receive.hpp"
#include "encryption.hpp"

class Validate
{
private:
	static bool checkServerUserLimit(SSL *ssl)
	{
		std::string signalMessage;

		if (ClientManagement::clientSSLSockets.size() >= ServerConfig::SERVER_USER_LIMIT)
			signalMessage = Signals::SignalManager::getSignalMessageWithSignalStringAppended(Signals::SignalType::SERVERLIMIT);
		else
			signalMessage = Signals::SignalManager::getSignalMessageWithSignalStringAppended(Signals::SignalType::UNKNOWN);

		Signals::SignalManager::printSignalServerMessage(Signals::SignalManager::getSignalTypeFromMessage(signalMessage));

		if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, signalMessage.data(), signalMessage.size()))
			return false;

		return Signals::SignalManager::getSignalTypeFromMessage(signalMessage) == Signals::SignalType::UNKNOWN ? true : false;
	}

	static bool checkClientUsernameValidity(SSL *ssl, const std::string &clientUsername)
	{
		std::string signalMessage;

		// checks if username already exists
		if (ClientManagement::clientPublicKeys.find(clientUsername) != ClientManagement::clientPublicKeys.end())
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

public:
	static bool handleClientPreChecks(SSL *ssl)
	{
		if (!checkServerUserLimit(ssl))
			return false;

		return true;
	}

	static bool validateAndSetupClient(SSL *ssl, const std::string &clientUsername)
	{
		if (!checkClientUsernameValidity(ssl, clientUsername))
			return false;

		std::string clientPublicKey;
		if (clientPublicKey = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl); clientPublicKey.empty())
			return false;

		ClientManagement::clientPublicKeys[clientUsername] = clientPublicKey;
		std::cout << "Public key: " << clientPublicKey;

		if (!Send::Server::sendAllPublicKeys(ssl, clientUsername, ClientManagement::clientPublicKeys))
			return false;

		if (!Receive::Server::receiveAndSendEncryptedAesKey(ssl, ClientManagement::clientSSLSockets, ClientManagement::clientPublicKeys))
			return false;

		return true;
	}
};