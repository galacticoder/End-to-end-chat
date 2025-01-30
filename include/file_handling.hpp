#pragma once

#include <iostream>
#include <filesystem>
#include <vector>
#include <fstream>
#include <fmt/core.h>
#include <openssl/ssl.h>

namespace FilePaths
{
	inline const std::string keysDirectory = "../keys/";
	inline const std::string receivedKeysDirectory = "../received_keys/";
	inline const std::string serverPrivateKeyPath = keysDirectory + "serverPrivateKey.key";
	inline const std::string serverPublicKeyPath = keysDirectory + "serverPublicKey.key";
	inline const std::string serverCertPath = keysDirectory + "serverCert.crt";
	inline const std::string clientPrivateKeyCertPath = keysDirectory + "clientPrivateKeyCert.key";
	inline const std::string clientCertPath = keysDirectory + "clientCert.crt";
	inline const std::string clientServerPublicKeyPath = receivedKeysDirectory + "serverPublicKey.pem";

	inline std::string clientPrivateKeyPath;
	inline std::string clientPublicKeyPath;

	inline void setKeyPaths(const std::string &username)
	{
		clientPrivateKeyPath = fmt::format("{}{}PrivateKey.pem", keysDirectory, username);
		clientPublicKeyPath = fmt::format("{}{}PublicKey.pem", keysDirectory, username);
	}
}

namespace FileSystem
{
	inline void createDirectory(const std::string &directoryName)
	{
		if (!std::filesystem::exists(directoryName) && !std::filesystem::create_directories(directoryName))
		{
			std::cerr << fmt::format("Failed to create directory: {}", directoryName) << std::endl;
		}
	}

	inline void deletePath(const std::string &path)
	{
		std::error_code errorCode;

		if (std::filesystem::is_directory(path))
		{
			if (std::filesystem::remove_all(path, errorCode))
				std::cout << fmt::format("Deleted directory: {}", path) << std::endl;
			else
				std::cerr << fmt::format("Failed to delete directory {}: {}", path, errorCode.message()) << std::endl;
		}
		else if (std::filesystem::remove(path, errorCode))
		{
			std::cout << fmt::format("Deleted file: {}", path) << std::endl;
		}
		else
		{
			std::cerr << fmt::format("Failed to delete {}: {}", path, errorCode.message()) << std::endl;
		}
	}
}

namespace FileIO
{
	inline bool saveToFile(const std::string &filePath, const std::string &contents, std::ios_base::openmode mode = std::ios_base::out)
	{
		std::ofstream file(filePath, mode);
		if (!file)
		{
			std::cerr << fmt::format("Could not open file '{}' for writing", filePath) << std::endl;
			return false;
		}

		file << contents;
		return true;
	}

	inline std::string readFileContents(const std::string &filePath)
	{
		std::ifstream file(filePath);
		if (!file)
		{
			std::cerr << fmt::format("Could not open file: {}", filePath) << std::endl;
			return "";
		}

		return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
	}
}

class FileTransferManager
{
private:
	static constexpr size_t chunkSize = 51200;

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
		if (!file)
		{
			std::cerr << fmt::format("Failed to open file: {}", fileName) << std::endl;
			return;
		}

		std::streamsize fileSize = getFileSize(file);
		SSL_write(ssl, &fileSize, sizeof(fileSize));

		std::vector<char> buffer(chunkSize);
		while (file.read(buffer.data(), chunkSize))
			SSL_write(ssl, buffer.data(), chunkSize);

		if (file.gcount() > 0)
			SSL_write(ssl, buffer.data(), file.gcount());

		std::cout << "File sent successfully!" << std::endl;
	}

	static bool receiveFile(SSL *ssl, const std::string &outputFileName)
	{
		std::streamsize fileSize = 0;
		if (SSL_read(ssl, &fileSize, sizeof(fileSize)) <= 0 || fileSize <= 0)
		{
			std::cerr << "Failed to receive file size or invalid size." << std::endl;
			return false;
		}

		std::ofstream outputFile(outputFileName, std::ios::binary);
		if (!outputFile)
		{
			std::cerr << fmt::format("Failed to open output file: {}", outputFileName) << std::endl;
			return false;
		}

		std::vector<char> buffer(1024);
		std::streamsize bytesReceived = 0;

		while (bytesReceived < fileSize)
		{
			size_t bytesToReceive = std::min<size_t>(buffer.size(), fileSize - bytesReceived);
			int received = SSL_read(ssl, buffer.data(), bytesToReceive);

			if (received <= 0)
			{
				std::cerr << "Error receiving file data." << std::endl;
				return false;
			}

			outputFile.write(buffer.data(), received);
			bytesReceived += received;
		}

		std::cout << "File received successfully!" << std::endl;
		return true;
	}
};
