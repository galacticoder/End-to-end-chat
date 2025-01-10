#pragma once

#include <iostream>
#include <filesystem>
#include <vector>
#include <fstream>
#include <fmt/core.h>
#include <openssl/ssl.h>

const std::string keysDirectory = "../keys/";

const std::string serverPrivateKeyPath = keysDirectory + "serverPrivateKey.key";
const std::string serverCertPath = keysDirectory + "serverCert.crt";

const std::string clientPrivateKeyPath = keysDirectory + "clientPrivateKey.key";
const std::string clientCertPath = keysDirectory + "clientCert.crt";

class FileTransferManager
{
private:
	static inline const size_t chunkSize = 51200;

	static std::streamsize getFileSize(std::ifstream &file)
	{
		file.seekg(0, std::ios::end);
		std::streamsize fileSize = file.tellg();
		file.seekg(0, std::ios::beg);

		return fileSize;
	}

public:
	static void sendFile(SSL *ssl, const std::string &fileName)
	{
		std::ifstream file(fileName, std::ios::binary);
		if (!file.is_open())
		{
			std::cerr << fmt::format("Failed to open file: {}", fileName) << std::endl;
			return;
		}

		// send file size
		std::streamsize fileSize = getFileSize(file);
		SSL_write(ssl, &fileSize, sizeof(fileSize));

		std::vector<char> buffer(chunkSize);

		while (file.read(buffer.data(), chunkSize))
			SSL_write(ssl, buffer.data(), chunkSize);

		if (file.gcount() > 0)
			SSL_write(ssl, buffer.data(), file.gcount());

		file.close();
		std::cout << "File sent successfully!" << std::endl;
	}

	static bool receiveFile(SSL *ssl, const std::string &outputFileName)
	{
		std::streamsize fileSize = 0;
		SSL_read(ssl, &fileSize, sizeof(fileSize));

		if (fileSize <= 0)
			return false;

		std::ofstream outputFile(outputFileName, std::ios::binary);
		if (!outputFile.is_open())
		{
			std::cerr << "Failed to open output file: " << outputFileName << "\n";
			return false;
		}

		const size_t chunkSize = 1024;
		std::vector<char> buffer(chunkSize);
		std::streamsize bytesReceived = 0;

		while (bytesReceived < fileSize)
		{
			size_t bytesToReceive = std::min(chunkSize, static_cast<size_t>(fileSize - bytesReceived));
			SSL_read(ssl, buffer.data(), bytesToReceive);
			outputFile.write(buffer.data(), bytesToReceive);
			bytesReceived += bytesToReceive;
		}

		outputFile.close();
		std::cout << "File received successfully!" << std::endl;
		return true;
	}
};

struct CreateDirectory
{
	CreateDirectory() = default;
	CreateDirectory(const std::string directoryName)
	{
		if (std::filesystem::exists(directoryName))
			return;

		if (!std::filesystem::create_directories(directoryName))
			std::cout << fmt::format("Couldnt create directory: {}", directoryName) << std::endl;

		exit(EXIT_FAILURE);
	}
};

struct DeletePath
{
	DeletePath(const std::string &path)
	{
		std::error_code errorCode;

		if (std::filesystem::is_directory(path))
			std::filesystem::remove_all(path, errorCode) ? std::cout << fmt::format("Deleted all files in path: {}", path) << std::endl : std::cout << "Could not delete all files in directory: " << errorCode.message() << std::endl;

		if (std::filesystem::remove(path, errorCode))
		{
			std::cout << fmt::format("Could not delete path: {}", errorCode.message()) << std::endl;
			return;
		}

		std::cout << fmt::format("Deleted path: {}", path) << std::endl;
	}
};