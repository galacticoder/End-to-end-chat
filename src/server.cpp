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

std::function<void(int)> shutdownHandler;
void signalHandle(int signal) { shutdownHandler(signal); }

void handleClient(SSL *ssl)
{
	char buf[1024];
	int bytes;

	while ((bytes = SSL_read(ssl, buf, sizeof(buf))) > 0)
	{
		buf[bytes] = 0;
		std::cout << "Received: " << buf << std::endl;
		SSL_write(ssl, buf, bytes);
	}
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