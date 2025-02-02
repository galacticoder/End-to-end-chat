#pragma once

#include <iostream>
#include <filesystem>
#include <vector>
#include <fstream>
#include <fmt/core.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <cstdint>
#include <string>
#include <random>
#include <algorithm>
#include <iomanip>
#include "send_receive.hpp"
#include "encryption.hpp"

namespace FilePaths
{
	inline const std::string keysDirectory = "../keys/";
	inline const std::string serverPrivateKeyPath = keysDirectory + "serverPrivateKey.key";
	inline const std::string serverCertPath = keysDirectory + "serverCert.crt";
	inline const std::string clientPrivateKeyCertPath = keysDirectory + "clientPrivateKeyCert.key";
	inline const std::string clientCertPath = keysDirectory + "clientCert.crt";
}

namespace FileSystem
{
	inline void createDirectory(const std::string &directoryName)
	{
		if (!std::filesystem::exists(directoryName) && !std::filesystem::create_directories(directoryName))
			std::cerr << fmt::format("Failed to create directory: {}", directoryName) << std::endl;
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
			std::cout << fmt::format("Deleted file: {}", path) << std::endl;
		else
			std::cerr << fmt::format("Failed to delete {}: {}", path, errorCode.message()) << std::endl;
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