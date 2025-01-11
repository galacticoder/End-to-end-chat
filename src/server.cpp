#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <fstream>
#include <vector>
#include "../include/keys.hpp"
#include "../include/ssl.hpp"
#include "../include/file_handling.hpp"
#include "../include/networking.hpp"
#include "../include/config.hpp"
#include "../include/encryption.hpp"

std::function<void(int)> shutdownHandler;
void signalHandle(int signal) { shutdownHandler(signal); }

void handleClient(SSL *ssl)
{
	char buffer[4096];
	int bytes;

	if ((bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1)) <= 0)
	{
		std::cerr << "Error: Failed to read key and IV from client." << std::endl;
		return;
	}
	buffer[bytes] = '\0';
	std::string serialized(buffer);

	std::cout << "Received serialized key and IV: " << serialized << std::endl;

	CryptoPP::GCM<CryptoPP::AES>::Encryption encryption;
	CryptoPP::byte key[CryptoPP::AES::MAX_KEYLENGTH];
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];

	Deserialize::deserializeKeyAndIV(serialized, key, sizeof(key), iv, sizeof(iv));
	encryption.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

	if ((bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1)) <= 0)
	{
		std::cerr << "Error: Failed to read ciphertext from client." << std::endl;
		return;
	}
	buffer[bytes] = '\0';
	std::string ciphertext(buffer);

	std::cout << "Received ciphertext: " << ciphertext << std::endl;

	CryptoPP::byte ivDecoded[CryptoPP::AES::BLOCKSIZE];
	Deserialize::deserializeIV(ciphertext, ivDecoded, sizeof(ivDecoded));

	std::string decryptedMessage = Decrypt::decryptDataAESGCM(ciphertext, key, sizeof(key), ivDecoded, sizeof(ivDecoded));
	std::cout << "Decrypted message: " << decryptedMessage << std::endl;
}

int main()
{
	SSLSetup::initOpenssl();

	CreateDirectory makeKeysDir(keysDirectory);
	GenerateKeys::generateCertAndPrivateKey(serverPrivateKeyPath, serverCertPath);

	SSL_CTX *ctx = SSLSetup::createCTX(TLS_server_method());
	SSLSetup::configureCTX(ctx, serverCertPath, serverPrivateKeyPath);

	int serverSocket = Networking::startServerSocket(Networking::findAvailablePort());

	shutdownHandler = [&](int signal)
	{
		std::cout << fmt::format("\nSignal {} caught. Killing server", strsignal(signal)) << std::endl;
		close(serverSocket);
		SSL_CTX_free(ctx);
		DeletePath deleteDirectory(keysDirectory);
		exit(signal);
	};

	std::signal(SIGINT, signalHandle);

	while (1)
	{
		int clientSocket = Networking::acceptClientConnection(serverSocket);

		SSL *ssl = SSL_new(ctx);
		SSL_set_fd(ssl, clientSocket);

		SSL_accept(ssl) <= 0 ? ERR_print_errors_fp(stderr) : handleClient(ssl);

		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(clientSocket);
		std::cout << "Cleaned up client" << std::endl;
	}

	close(serverSocket);
	SSL_CTX_free(ctx);
	DeletePath deleteDirectory(keysDirectory);

	std::cout << "Cleaned up server" << std::endl;
	return 0;
}