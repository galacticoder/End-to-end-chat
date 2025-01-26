#pragma once

#include <iostream>
#include <filesystem>
#include <vector>
#include <fstream>
#include <fmt/core.h>
#include <openssl/ssl.h>

struct FilePaths
{
	static const inline std::string keysDirectory = "../keys/";
	static const inline std::string receivedKeysDirectory = "../received_keys/";
	static const inline std::string serverPrivateKeyPath = keysDirectory + "serverPrivateKey.key"; // overwrite this with a new key
	static const inline std::string serverPublicKeyPath = keysDirectory + "serverPublicKey.key";
	static const inline std::string serverCertPath = keysDirectory + "serverCert.crt";
	static const inline std::string clientPrivateKeyCertPath = keysDirectory + "clientPrivateKeyCert.key";
	static const inline std::string clientCertPath = keysDirectory + "clientCert.crt";
	static const inline std::string clientServerPublicKeyPath = receivedKeysDirectory + "serverPublicKey.pem";

	static inline std::string clientPrivateKeyPath;
	static inline std::string clientPublicKeyPath;

	static void setKeyPaths(std::string &username)
	{
		clientPrivateKeyPath = fmt::format("{}{}PrivateKey.pem", keysDirectory, username);
		clientPublicKeyPath = fmt::format("{}{}PublicKey.pem", keysDirectory, username);
	}
};

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
	}
};

struct DeletePath
{
	DeletePath(const std::string &path)
	{
		std::error_code errorCode;

		if (std::filesystem::is_directory(path))
			std::filesystem::remove_all(path, errorCode) ? std::cout << fmt::format("Deleted all files in path: {}", path) << std::endl : std::cout << "Could not delete all files in directory: " << errorCode.message() << std::endl;

		std::filesystem::remove(path);

		std::cout << fmt::format("Deleted path: {}", path) << std::endl;
	}
};

struct SaveFile
{
	SaveFile(const std::string &filePath, const std::string &contentsToWrite, std::ios_base::openmode fileMode = std::ios_base::out)
	{
		std::ofstream file(filePath, fileMode);

		if (file.is_open())
		{
			file << contentsToWrite;
			return;
		}

		if (!std::filesystem::is_regular_file(filePath))
		{
			std::cout << fmt::format("Could not open file '{}' to write data: {}", filePath, contentsToWrite);
			exit(EXIT_FAILURE);
		}
	}
};

struct ReadFile
{
	ReadFile() = default;
	static std::string ReadPemKeyContents(const std::string &pemKeyPath)
	{
		std::ifstream keyFile(pemKeyPath);
		if (keyFile.is_open())
		{
			std::string pemKey((std::istreambuf_iterator<char>(keyFile)), std::istreambuf_iterator<char>());
			keyFile.close();
			return pemKey;
		}

		std::cout << "Could not open pem file: " << pemKeyPath << std::endl;
		return "";
	}
};