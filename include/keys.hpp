#pragma once

#include <iostream>
#include <fmt/core.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/hex.h>
#include <vector>

#define KEYSIZE 4096

class GenerateKeys
{
public:
	static void generateCertAndPrivateKey(const std::string &privateKeySavePath, const std::string &certSavePath)
	{
		EVP_PKEY *pkey = nullptr;
		X509 *x509 = nullptr;
		EVP_PKEY_CTX *pctx = nullptr;
		BIO *bio = nullptr;

		OpenSSL_add_all_algorithms();
		ERR_load_crypto_strings();

		pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
		if (!pctx)
		{
			ERR_print_errors_fp(stderr);
			return;
		}

		if (EVP_PKEY_keygen_init(pctx) <= 0 ||
			EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, KEYSIZE) <= 0 ||
			EVP_PKEY_keygen(pctx, &pkey) <= 0)
		{
			ERR_print_errors_fp(stderr);
			EVP_PKEY_CTX_free(pctx);
			return;
		}
		EVP_PKEY_CTX_free(pctx);

		x509 = X509_new();
		if (!x509)
		{
			ERR_print_errors_fp(stderr);
			EVP_PKEY_free(pkey);
			return;
		}

		ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
		X509_gmtime_adj(X509_get_notBefore(x509), 0);
		X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
		X509_set_pubkey(x509, pkey);

		X509_NAME *name = X509_get_subject_name(x509);
		X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
		X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"organization", -1, -1, 0);
		X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"common name", -1, -1, 0);

		X509_set_issuer_name(x509, name);
		if (X509_sign(x509, pkey, EVP_sha3_512()) == 0)
		{
			ERR_print_errors_fp(stderr);
			EVP_PKEY_free(pkey);
			X509_free(x509);
			return;
		}

		bio = BIO_new_file(privateKeySavePath.c_str(), "w");
		if (!bio)
		{
			ERR_print_errors_fp(stderr);
			EVP_PKEY_free(pkey);
			X509_free(x509);
			return;
		}
		if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1)
		{
			ERR_print_errors_fp(stderr);
		}
		BIO_free_all(bio);

		bio = BIO_new_file(certSavePath.c_str(), "w");
		if (!bio)
		{
			ERR_print_errors_fp(stderr);
			EVP_PKEY_free(pkey);
			X509_free(x509);
			return;
		}
		if (PEM_write_bio_X509(bio, x509) != 1)
		{
			ERR_print_errors_fp(stderr);
		}

		BIO_free_all(bio);
		EVP_PKEY_free(pkey);
		X509_free(x509);

		std::cout << "Generated cert and private key" << std::endl;
	}

	static void generateRSAKeys(const std::string &privateKeyFile, const std::string &publicKeyFile, int bits = KEYSIZE)
	{
		std::cout << "Generating keys.." << std::endl;
		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
		if (!ctx)
		{
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}

		if (EVP_PKEY_keygen_init(ctx) <= 0)
		{
			ERR_print_errors_fp(stderr);
			EVP_PKEY_CTX_free(ctx);
			exit(EXIT_FAILURE);
		}

		if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
		{
			ERR_print_errors_fp(stderr);
			EVP_PKEY_CTX_free(ctx);
			exit(EXIT_FAILURE);
		}

		EVP_PKEY *pkey = NULL;
		if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
		{
			ERR_print_errors_fp(stderr);
			EVP_PKEY_CTX_free(ctx);
			exit(EXIT_FAILURE);
		}

		EVP_PKEY_CTX_free(ctx);

		BIO *privateKeyBio = BIO_new_file(privateKeyFile.c_str(), "w+");
		PEM_write_bio_PrivateKey(privateKeyBio, pkey, NULL, NULL, 0, NULL, NULL);
		BIO_free_all(privateKeyBio);

		BIO *publicKeyBio = BIO_new_file(publicKeyFile.c_str(), "w+");
		PEM_write_bio_PUBKEY(publicKeyBio, pkey);
		BIO_free_all(publicKeyBio);

		EVP_PKEY_free(pkey);

		std::cout << "Generated RSA Keys" << std::endl;
	}

	static void generateKeyAESGCM(CryptoPP::byte *key, CryptoPP::byte *iv)
	{
		CryptoPP::AutoSeededRandomPool prng;
		prng.GenerateBlock(key, 32);
		prng.GenerateBlock(iv, 16);
	}
};

class LoadKey
{
public:
	static EVP_PKEY *LoadPrivateKey(const std::string &privateKeyFile, const bool echo = true)
	{
		BIO *bio = BIO_new_file(privateKeyFile.c_str(), "r");
		if (!bio)
		{
			std::cerr << "Error loading private rsa key: ";
			ERR_print_errors_fp(stderr);
			return nullptr;
		}

		EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
		BIO_free(bio);

		if (!pkey)
		{
			std::cerr << "Error loading private rsa key: ";
			ERR_print_errors_fp(stderr);
			return nullptr;
		}

		if (echo)
			std::cout << fmt::format("Loaded RSA Private key file ({}) successfully", privateKeyFile) << std::endl;

		return pkey;
	}

	static EVP_PKEY *LoadPublicKey(const std::string &publicKeyFile, const bool echo = true)
	{
		BIO *bio = BIO_new_file(publicKeyFile.c_str(), "r");
		if (!bio)
		{
			ERR_print_errors_fp(stderr);
			std::cerr << fmt::format("Error loading public rsa key from path {}", publicKeyFile) << std::endl;
			return nullptr;
		}

		EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
		BIO_free(bio);

		if (!pkey)
		{
			std::cerr << fmt::format("Error loading public rsa key from path {}", publicKeyFile) << std::endl;
			return nullptr;
		}

		if (echo)
			std::cout << fmt::format("Loaded RSA Public key file ({}) successfully", publicKeyFile) << std::endl;

		return pkey;
	}
};