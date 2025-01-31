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

namespace ClientKeys
{
	static inline std::string clientPrivateKeyString;
	static inline std::string clientPublicKeyString;

	void setKeys(const std::string &privateKeyString, const std::string &publicKeyString)
	{
		clientPrivateKeyString = privateKeyString;
		clientPublicKeyString = publicKeyString;
		std::cout << "Set RSA keys" << std::endl;
	}
}

class GenerateKeys
{
public:
	static void generateCertAndPrivateKey(const std::string &privateKeySavePath, const std::string &certSavePath)
	{
		std::cout << "Generating cert and private key..." << std::endl;

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

	static std::string generateRSAPrivateKey(int bits = KEYSIZE)
	{
		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
		if (!ctx)
		{
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}

		if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
		{
			ERR_print_errors_fp(stderr);
			EVP_PKEY_CTX_free(ctx);
			exit(EXIT_FAILURE);
		}

		EVP_PKEY *pkey = nullptr;
		if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
		{
			ERR_print_errors_fp(stderr);
			EVP_PKEY_CTX_free(ctx);
			exit(EXIT_FAILURE);
		}

		EVP_PKEY_CTX_free(ctx);

		BIO *bio = BIO_new(BIO_s_mem());
		if (!bio)
		{
			EVP_PKEY_free(pkey);
			exit(EXIT_FAILURE);
		}

		if (!PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL))
		{
			ERR_print_errors_fp(stderr);
			BIO_free(bio);
			EVP_PKEY_free(pkey);
			exit(EXIT_FAILURE);
		}

		char *buffer;
		long len = BIO_get_mem_data(bio, &buffer);
		std::string privateKey(buffer, len);

		BIO_free(bio);
		EVP_PKEY_free(pkey);

		return privateKey;
	}

	static std::string generateRSAPublicKey(EVP_PKEY *pkey)
	{
		BIO *bio = BIO_new(BIO_s_mem());
		if (!bio)
		{
			exit(EXIT_FAILURE);
		}

		if (!PEM_write_bio_PUBKEY(bio, pkey))
		{
			ERR_print_errors_fp(stderr);
			BIO_free(bio);
			exit(EXIT_FAILURE);
		}

		char *buffer;
		long len = BIO_get_mem_data(bio, &buffer);
		std::string publicKey(buffer, len);

		BIO_free(bio);
		return publicKey;
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
	static EVP_PKEY *loadPublicKeyInMemory(const std::string &keyData)
	{
		BIO *bio = BIO_new_mem_buf(keyData.data(), static_cast<int>(keyData.size()));
		if (!bio)
		{
			std::cerr << "Failed to create BIO for key data" << std::endl;
			BIO_free(bio);
			return nullptr;
		}

		EVP_PKEY *publicKey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
		if (!publicKey)
		{
			std::cerr << "Failed to load public key from BIO" << std::endl;
			BIO_free(bio);
			EVP_PKEY_free(publicKey);
			ERR_print_errors_fp(stderr);
			return nullptr;
		}

		BIO_free(bio);
		return publicKey;
	}

	static EVP_PKEY *loadPrivateKeyInMemory(const std::string &privateKeyStr)
	{
		BIO *bio = BIO_new_mem_buf(privateKeyStr.c_str(), -1);
		if (!bio)
		{
			std::cerr << "Failed to create BIO buffer." << std::endl;
			return nullptr;
		}

		EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
		BIO_free(bio);

		if (!pkey)
		{
			std::cerr << "Failed to load private key from string." << std::endl;
			ERR_print_errors_fp(stderr);
		}

		return pkey;
	}
};