#pragma once

#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>

namespace SSLSetup
{
	void initOpenssl()
	{
		SSL_library_init();
		OpenSSL_add_all_algorithms();
		SSL_load_error_strings();
		ERR_load_crypto_strings();
	}

	SSL_CTX *createCTX(const SSL_METHOD *methodType)
	{
		const SSL_METHOD *method = methodType;
		SSL_CTX *ctx = SSL_CTX_new(method);
		if (!ctx)
		{
			perror("Unable to create SSL context");
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}
		return ctx;
	}

	void configureCTX(SSL_CTX *ctx, const std::string &certPath, const std::string &privateKeyPath)
	{
		if (SSL_CTX_use_certificate_file(ctx, certPath.c_str(), SSL_FILETYPE_PEM) <= 0)
		{
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}
		if (SSL_CTX_use_PrivateKey_file(ctx, privateKeyPath.c_str(), SSL_FILETYPE_PEM) <= 0)
		{
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}
		if (!SSL_CTX_check_private_key(ctx))
		{
			std::cerr << "Private key does not match the certificate public key" << std::endl;
			exit(EXIT_FAILURE);
		}
	}
};