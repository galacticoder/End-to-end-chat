#pragma once

#include <iostream>
#include <sys/socket.h>
#include <boost/asio.hpp>
#include <fmt/core.h>
#include <netinet/in.h>
#include <unistd.h>

class Networking
{
private:
	static bool isPortAvailable(int &port)
	{
		int pavtempsock;
		struct sockaddr_in addr;
		bool available = false;

		pavtempsock = socket(AF_INET, SOCK_STREAM, 0);

		if (pavtempsock < 0)
		{
			std::cerr << "Cannot create socket to test port availability" << std::endl;
			return false;
		}

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_ANY;
		addr.sin_port = htons(port);

		bind(pavtempsock, (struct sockaddr *)&addr, sizeof(addr)) < 0 ? available = false : available = true;

		close(pavtempsock);
		return available;
	}

public:
	static int findAvailablePort()
	{
		int defaultPort = 8080;

		if (isPortAvailable(defaultPort))
			return defaultPort;

		for (int i = 49152; i <= 65535; i++)
		{
			if (isPortAvailable(i))
				return i;
		}

		return -1;
	}

	static int startServerSocket(int port)
	{
		int sockfd = socket(AF_INET, SOCK_STREAM, 0);

		if (sockfd < 0)
		{
			std::cerr << "Error opening server socket" << std::endl;
			exit(EXIT_FAILURE);
		}

		sockaddr_in serverAddress;
		int opt = 1;

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
		{
			perror("setsockopt");
			exit(EXIT_FAILURE);
		}

		serverAddress.sin_family = AF_INET;
		serverAddress.sin_port = htons(port);
		serverAddress.sin_addr.s_addr = INADDR_ANY;

		if (bind(sockfd, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
		{
			std::cout << "Chosen port isn't available" << std::endl;
			exit(EXIT_FAILURE);
		}

		listen(sockfd, 5);
		std::cout << fmt::format("Server listening on port {}", port) << std::endl;

		return sockfd;
	}

	static int startClientSocket(int port, const std::string &serverIpAddress)
	{
		int sockfd = socket(AF_INET, SOCK_STREAM, 0);
		if (sockfd < 0)
		{
			perror("Unable to create socket");
			exit(EXIT_FAILURE);
		}

		struct sockaddr_in serverAddr;
		serverAddr.sin_family = AF_INET;
		serverAddr.sin_port = htons(port);

		if (inet_pton(AF_INET, serverIpAddress.c_str(), &serverAddr.sin_addr) <= 0)
		{
			perror("Invalid address or address not supported");
			exit(EXIT_FAILURE);
		}

		if (connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
		{
			perror("Unable to connect");
			exit(EXIT_FAILURE);
		}

		return sockfd;
	}

	static int acceptClientConnection(int &serverSocket)
	{
		sockaddr_in clientAddress;
		socklen_t clientLen = sizeof(clientAddress);
		return accept(serverSocket, (struct sockaddr *)&clientAddress, &clientLen);
	}
};

class Receive
{
private:
public:
}