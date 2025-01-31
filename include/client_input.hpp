#pragma once

#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>

namespace ClientSync
{
	std::atomic<bool> threadRunning{true};
	std::atomic<bool> shutdownRequested{false};
	std::mutex ssl_mutex;
	std::condition_variable ssl_cv;
};

namespace ClientInput
{
	int pipefd[2];
	pid_t child_pid;

	void trimWhitespaces(std::string &str)
	{
		str.erase(0, str.find_first_not_of(" \t\n\r"));
		str.erase(str.find_last_not_of(" \t\n\r") + 1);
	}

	void messageInput(int writePipe)
	{
		std::string line;
		while (ClientSync::threadRunning && std::getline(std::cin, line))
		{
			if (!ClientSync::threadRunning)
				break;

			if (write(writePipe, line.c_str(), line.size()) == -1 ||
				write(writePipe, "\n", 1) == -1)
			{
				perror("Child: write error");
				break;
			}
		}
		close(writePipe);
		_exit(0);
	}

	void startMessageInput()
	{
		if (pipe(pipefd) == -1)
		{
			perror("pipe");
			return;
		}

		child_pid = fork();
		if (child_pid == -1)
		{
			perror("fork");
			close(pipefd[0]);
			close(pipefd[1]);
			return;
		}

		if (child_pid == 0)
		{
			close(pipefd[0]);
			messageInput(pipefd[1]);
		}
		else
		{
			close(pipefd[1]);
		}
	}

	std::string typeAndReceiveMessageBack()
	{
		char buffer[256] = {0};
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(pipefd[0], &readfds);

		timeval timeout = {0, 0};
		int retval = select(pipefd[0] + 1, &readfds, nullptr, nullptr, &timeout);

		if (retval == -1)
		{
			if (errno != EINTR)
			{
				perror("select error");
				ClientSync::threadRunning = false;
			}
			return "";
		}

		if (retval > 0)
		{
			ssize_t bytesRead = read(pipefd[0], buffer, sizeof(buffer) - 1);
			if (bytesRead > 0)
			{
				buffer[bytesRead] = '\0';
				return std::string(buffer);
			}
			ClientSync::threadRunning = (bytesRead != 0);
		}
		return "";
	}

	void cleanUpProcesses()
	{
		kill(child_pid, SIGINT);
		shutdown(pipefd[1], SHUT_WR);
		waitpid(child_pid, nullptr, WNOHANG);
		close(pipefd[0]);
	}
};
