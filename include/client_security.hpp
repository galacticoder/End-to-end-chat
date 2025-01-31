#pragma once

#include <iostream>
#include <csignal>
#include <openssl/ssl.h>
#include "encryption.hpp"
#include "file_handling.hpp"
#include "keys.hpp"
#include "send_receive.hpp"
#include "bcrypt.h"
#include "signals.hpp"
#include "client_input.hpp"

extern std::string username;

class ClientValidation
{
private:
	static bool validateUsernameAndSetKeyPaths(SSL *ssl)
	{
		std::cout << "Enter username: ";
		std::getline(std::cin, username);

		if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, username.data(), username.size()))
			return false;

		std::string validateUsername;
		if (validateUsername = Receive::receiveMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl); validateUsername.empty())
			return false;

		Signals::SignalType getSignal = Signals::SignalManager::getSignalTypeFromMessage(validateUsername);
		HandleSignal(getSignal, validateUsername);

		FilePaths::setKeyPaths(username);
		return true;
	}

	static bool makeAndSendKeys(SSL *ssl, CryptoPP::byte *key, size_t keySize, CryptoPP::byte *iv, size_t ivSize, std::vector<std::string> &publicKeys)
	{
		GenerateKeys::generateRSAKeys(FilePaths::clientPrivateKeyPath, FilePaths::clientPublicKeyPath);

		const std::string publicKeyData = FileIO::readFileContents(FilePaths::clientPublicKeyPath);
		if (!Send::sendMessage<WRAP_STRING_LITERAL(__FILE__), __LINE__>(ssl, publicKeyData.data(), publicKeyData.size()))
			return false;

		CryptoPP::GCM<CryptoPP::AES>::Encryption setKey;
		GenerateKeys::generateKeyAESGCM(key, iv);
		setKey.SetKeyWithIV(key, keySize, iv, ivSize);

		std::string serializedKeyAndIv = Encode::serializeKeyAndIV(key, keySize, iv, ivSize);

		if (!Receive::Client::receiveAllRSAPublicKeys(ssl, publicKeys))
			return false;

		if (!Send::Client::sendEncryptedAESKey(ssl, serializedKeyAndIv, Signals::SignalManager::getSignalAsString(Signals::SignalType::NEWAESKEY), publicKeys))
			return false;

		return true;
	}

public:
	static bool clientAuthenticationAndKeyExchange(SSL *ssl, CryptoPP::byte *key, size_t keySize, CryptoPP::byte *iv, size_t ivSize, std::vector<std::string> &publicKeys)
	{
		if (!validateUsernameAndSetKeyPaths(ssl) || !makeAndSendKeys(ssl, key, keySize, iv, ivSize, publicKeys))
			return false;

		return true;
	}
};