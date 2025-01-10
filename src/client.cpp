#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fstream>
#include <vector>
#include "../include/ssl.hpp"
#include "../include/keys.hpp"
#include "../include/file_handling.hpp"
#include "../include/networking.hpp"

std::function<void(int)> shutdownHandler;
void signalHandle(int signal) { shutdownHandler(signal); }

void sendMessage(SSL *ssl)
{
	char msg[1024];
	while (1)
	{
		std::cout << "Enter message: ";
		std::cin.getline(msg, sizeof(msg));

		if (SSL_write(ssl, msg, strlen(msg)) <= 0)
		{
			std::cerr << "Error sending message" << std::endl;
			break;
		}

		int bytes = SSL_write(ssl, msg, sizeof(msg) - 1);
		if (bytes <= 0)
		{
			std::cerr << "Error receiving message" << std::endl;
			break;
		}

		msg[bytes] = '\0';
		std::cout << "Server response: " << msg << std::endl;
	}
}

int main()
{
	SSLSetup::initOpenssl();

	CreateDirectory makeKeysDir(keysDirectory);
	GenerateKeys::generateCertAndPrivateKey(clientPrivateKeyPath, clientCertPath);

	SSL_CTX *ctx = SSLSetup::createCTX(TLS_client_method());
	SSLSetup::configureCTX(ctx, clientCertPath, clientPrivateKeyPath);

	const std::string serverIpAddress = "127.0.0.1";
	const int port = 8080;

	int socketfd = Networking::startClientSocket(port, serverIpAddress);

	shutdownHandler = [&](int signal)
	{
		std::cout << fmt::format("\nSignal {} caught. Exiting.", strsignal(signal)) << std::endl;
		close(socketfd);
		SSL_CTX_free(ctx);
		DeletePath deleteDirectory(keysDirectory);
		exit(signal);
	};

	std::signal(SIGINT, signalHandle);

	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, socketfd);

	SSL_connect(ssl) <= 0 ? ERR_print_errors_fp(stderr) : sendMessage(ssl);

	SSL_shutdown(ssl);
	SSL_free(ssl);
	DeletePath deleteDirectory(keysDirectory);
	close(socketfd);

	SSL_CTX_free(ctx);
	return 0;
}
