#pragma once

#include <iostream>
#include <vector>
#include <algorithm>

namespace SignalMessages
{
	enum class SignalType
	{
		LOADERR,
		KEYEXISTERR,
		VERIFIED,
		NOTVERIFIED,
		NAMEEXISTSERR,
		REQUESTNEEDED,
		RATELIMITED,
		SERVERLIMIT,
		ACCEPTED,
		NOTACCEPTED,
		CLIENTREJOIN,
		PASSWORDNEEDED,
		PASSWORDNOTNEEDED,
		INVALIDNAME,
		INVALIDNAMELENGTH,
		OKAYSIGNAL,
		SERVERJOINREQUESTDENIED,
		SERVERJOINREQUESTACCEPTED,
		CONNECTIONSIGNAL,
		STATUSCHECKSIGNAL,
		PINGBACK,
		PING,
		BLACKLISTED,
		UNKNOWN
	};

	class Manager
	{
	private:
		static inline std::vector<std::string> signalStringsVector = {
			"KEYLOADERROR", "KEYEXISTERR", "PASSWORDVERIFIED", "PASSWORDNOTVERIFIED", "NAMEEXISTSERR",
			"SERVERNEEDSREQUEST", "RATELIMITED", "USERLIMITREACHED", "USERACCEPTED", "USERNOTACCEPTED",
			"CLIENTREJOIN", "PASSWORDNEEDED", "PASSWORDNOTNEEDED", "INVALIDNAMECHARS", "INVALIDNAMELENGTH",
			"OKAYSIGNAL", "SERVERJOINREQUESTDENIED", "SERVERJOINREQUESTACCEPTED", "CONNECTIONSIGNAL",
			"STATUSCHECKSIGNAL", "PINGBACK", "PING", "BLACKLISTED"};

		static inline std::vector<std::string> serverMessages = {
			"Public key could not be loaded on the server.",
			"Username already exists. You have been kicked.",
			"Correct password entered.",
			"Wrong password. You have been kicked.",
			"Username already exists on server.",
			"Server requires join request approval.",
			"Rate limit reached. Try again later.",
			"User limit reached. Exiting.",
			"Join request accepted.",
			"Join request not accepted.",
			"", // client rejoin has no message
			"Enter the server password to join.",
			"Welcome to the server.",
			"Username contains invalid characters.",
			"", // invalid name length is set later
			"", // ok signal has no message
			"Join request denied.",
			"Join request accepted.",
			"", // connection signal has no message
			"", // status check signal has no message
			"", // ping back signal has no message
			"", // ping signal has no message
			"You are blacklisted from the server."};

	public:
		Manager() {}

		static std::string getPreloadedMessage(SignalType type)
		{
			size_t index = static_cast<size_t>(type);

			if (index < serverMessages.size())
				return serverMessages[index];

			std::cerr << "Invalid signal type: " << static_cast<int>(type) << std::endl;
			return "";
		}
	};
}

// class SignalHandling
// {
// public:
// 	static void handleSignal(SignalType signal, const std::string &msg)
// 	{
// 		if (signal == SignalType::UNKNOWN)
// 			return;

// 		const std::string decodedMessage = decodeMessage(msg);
// 		std::cout << decodedMessage << std::endl;

// 		if (signal != SignalType::VERIFIED && signal != SignalType::ACCEPTED &&
// 			signal != SignalType::OKAYSIGNAL && signal != SignalType::PASSWORDNOTNEEDED &&
// 			signal != SignalType::PASSWORDNEEDED && signal != SignalType::REQUESTNEEDED &&
// 			signal != SignalType::SERVERJOINREQUESTACCEPTED)
// 		{
// 			raise(SIGINT);
// 		}
// 	}

// 	static SignalType getSignalType(const std::string &msg)
// 	{
// 		const std::string decodedMessage = decodeMessage(msg);

// 		for (size_t i : signalsVector.size())
// 		{
// 			if (decodedMessage.find(signalsVector[i]) != std::string::npos)
// 			{
// 				return static_cast<SignalType>(i);
// 			}
// 		}
// 		return SignalType::UNKNOWN;
// 	}

// 	static std::string getSignalAsString(SignalType signalType)
// 	{
// 		if (static_cast<size_t>(signalType) < signalsVector.size())
// 			return signalsVector[static_cast<size_t>(signalType)];

// 		std::cerr << "Invalid signal type." << std::endl;
// 		return "";
// 	}
// };
