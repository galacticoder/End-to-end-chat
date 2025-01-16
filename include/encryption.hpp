#pragma once

#include <iostream>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/hex.h>
#include <openssl/err.h>
#include <openssl/pem.h>

class Serialize
{
public:
	static std::string serializeKeyAndIV(const CryptoPP::byte *key, size_t keySize, const CryptoPP::byte *iv, size_t ivSize)
	{
		std::string serializedKey, serializedIV;

		CryptoPP::HexEncoder encoderKey(new CryptoPP::StringSink(serializedKey));
		encoderKey.Put(key, keySize);
		encoderKey.MessageEnd();

		CryptoPP::HexEncoder encoderIV(new CryptoPP::StringSink(serializedIV));
		encoderIV.Put(iv, ivSize);
		encoderIV.MessageEnd();

		return serializedKey + ":" + serializedIV;
	}

	static std::string serializeIV(const CryptoPP::byte *iv, size_t ivSize)
	{
		std::string serializedIV;

		CryptoPP::HexEncoder encoderIV(new CryptoPP::StringSink(serializedIV));
		encoderIV.Put(iv, ivSize);
		encoderIV.MessageEnd();

		return serializedIV;
	}
};

class Deserialize
{
public:
	static void deserializeKeyAndIV(const std::string &serializedData, CryptoPP::byte *key, size_t keySize, CryptoPP::byte *iv, size_t ivSize)
	{
		auto separatorPos = serializedData.find(':');
		std::string serializedKey = serializedData.substr(0, separatorPos);
		std::string serializedIV = serializedData.substr(separatorPos + 1);

		CryptoPP::HexDecoder decoderKey;
		decoderKey.Put((const CryptoPP::byte *)serializedKey.data(), serializedKey.size());
		decoderKey.MessageEnd();
		decoderKey.Get(key, keySize);

		CryptoPP::HexDecoder decoderIV;
		decoderIV.Put((const CryptoPP::byte *)serializedIV.data(), serializedIV.size());
		decoderIV.MessageEnd();
		decoderIV.Get(iv, ivSize);
	}

	static void deserializeIV(const std::string &serializedData, CryptoPP::byte *iv, size_t ivSize)
	{
		std::string serializedIvString = serializedData.substr(0, serializedData.find(":"));

		CryptoPP::HexDecoder decoderIV;
		decoderIV.Put((const CryptoPP::byte *)serializedIvString.data(), serializedIvString.size());
		decoderIV.MessageEnd();
		decoderIV.Get(iv, ivSize);
	}
};

class Encrypt
{
protected:
	static std::string base64Encode(const std::string &input)
	{
		std::string encoded;
		CryptoPP::StringSource(input, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));
		return encoded;
	}

public:
	static std::string encryptDataAESGCM(const std::string &data, const CryptoPP::byte *key, size_t keySize)
	{
		std::string ciphertext;

		CryptoPP::GCM<CryptoPP::AES>::Encryption encryption;
		CryptoPP::AutoSeededRandomPool prng;

		CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = {0x00};
		prng.GenerateBlock(iv, 16);

		encryption.SetKeyWithIV(key, keySize, iv, sizeof(iv));

		CryptoPP::StringSource(data, true,
							   new CryptoPP::AuthenticatedEncryptionFilter(encryption,
																		   new CryptoPP::StringSink(ciphertext)));

		ciphertext = base64Encode(ciphertext);

		std::string serializedIv = Serialize::serializeIV(iv, sizeof(iv)) += ":";
		ciphertext = serializedIv += ciphertext;

		return ciphertext;
	}

	static std::string encryptDataRSA(EVP_PKEY *publicKey, const std::string &data)
	{
		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(publicKey, nullptr);
		if (!ctx)
		{
			ERR_print_errors_fp(stderr);
			return "";
		}

		if (EVP_PKEY_encrypt_init(ctx) <= 0)
		{
			ERR_print_errors_fp(stderr);
			EVP_PKEY_CTX_free(ctx);
			return "";
		}

		size_t out_len;
		if (EVP_PKEY_encrypt(ctx, nullptr, &out_len, reinterpret_cast<const unsigned char *>(data.c_str()), data.size()) <= 0)
		{
			ERR_print_errors_fp(stderr);
			EVP_PKEY_CTX_free(ctx);
			return "";
		}

		std::string out(out_len, '\0');
		if (EVP_PKEY_encrypt(ctx, reinterpret_cast<unsigned char *>(&out[0]), &out_len, reinterpret_cast<const unsigned char *>(data.c_str()), data.size()) <= 0)
		{
			ERR_print_errors_fp(stderr);
			EVP_PKEY_CTX_free(ctx);
			return "err";
		}

		EVP_PKEY_CTX_free(ctx);
		out.resize(out_len);
		return out;
	}
};

class Decrypt
{
protected:
	static std::string base64Decode(const std::string &input)
	{
		std::string decoded;
		CryptoPP::StringSource(input, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
		return decoded;
	}

public:
	static std::string decryptDataAESGCM(const std::string &ciphertext, const CryptoPP::byte *key, size_t keySize, const CryptoPP::byte *iv, size_t ivSize)
	{
		std::string extractedCiphertext = ciphertext.substr(ciphertext.find(":") + 1);
		extractedCiphertext = base64Decode(extractedCiphertext);

		CryptoPP::GCM<CryptoPP::AES>::Decryption decryption;
		std::string recovered;

		decryption.SetKeyWithIV(key, keySize, iv, ivSize);
		CryptoPP::StringSource(extractedCiphertext, true,
							   new CryptoPP::AuthenticatedDecryptionFilter(decryption,
																		   new CryptoPP::StringSink(recovered)));

		return recovered;
	}

	static std::string decryptDataRSA(EVP_PKEY *privateKey, const std::string &encryptedData)
	{
		std::string ciphertext = base64Decode(encryptedData);

		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privateKey, nullptr);
		if (!ctx)
		{
			ERR_print_errors_fp(stderr);
			return "";
		}

		if (EVP_PKEY_decrypt_init(ctx) <= 0)
		{
			ERR_print_errors_fp(stderr);
			EVP_PKEY_CTX_free(ctx);
			return "";
		}

		size_t out_len;
		if (EVP_PKEY_decrypt(ctx, nullptr, &out_len, reinterpret_cast<const unsigned char *>(ciphertext.c_str()), ciphertext.size()) <= 0)
		{
			ERR_print_errors_fp(stderr);
			EVP_PKEY_CTX_free(ctx);
			return "";
		}

		std::string out(out_len, '\0');
		if (EVP_PKEY_decrypt(ctx, reinterpret_cast<unsigned char *>(&out[0]), &out_len, reinterpret_cast<const unsigned char *>(ciphertext.c_str()), ciphertext.size()) <= 0)
		{
			ERR_print_errors_fp(stderr);
			EVP_PKEY_CTX_free(ctx);
			return "";
		}

		EVP_PKEY_CTX_free(ctx);
		out.resize(out_len);
		return out;
	}
};