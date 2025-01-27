#pragma once

#include <iostream>
#include <csignal>
#include <openssl/ssl.h>
#include "encryption.hpp"
#include "keys.hpp"
#include "send_receive.hpp"
#include "bcrypt.h"
#include "signals.hpp"

class ClientValidation
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

		HandleSignal(Signals::SignalManager::getSignalTypeFromMessage(isPasswordVerified), isPasswordVerified);
	}
};