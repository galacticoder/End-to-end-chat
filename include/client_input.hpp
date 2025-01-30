#pragma once

#include <iostream>
#include <string>
#include <thread>
#include <unistd.h>
#include <cstring>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <atomic>
#include <sys/select.h>
#include <errno.h>
#include <future>
#include <signal.h>

extern std::atomic<bool> threadRunning;

int pipefd[2];
pid_t child_pid;

namespace ClientInput
{
	void messageInput(int writePipe)
	{
		while (threadRunning)
		{
			std::string line;

			if (!std::getline(std::cin, line))
				break;

			if (!threadRunning)
				break;

			if (write(writePipe, line.c_str(), line.size()) == -1)
			{
				perror("Child: write");
				break;
			}
			if (write(writePipe, "\n", 1) == -1)
			{
				perror("Child: write newline");
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

	std::string receiveMessage()
	{
		char buffer[256];
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(pipefd[0], &readfds);

		struct timeval timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = 0;

		int retval = select(pipefd[0] + 1, &readfds, NULL, NULL, &timeout);

		if (retval == -1)
		{
			if (errno == EINTR)
				return "";
			perror("select");
			threadRunning = false;
			return "";
		}
		else if (retval > 0)
		{
			ssize_t bytesRead = read(pipefd[0], buffer, sizeof(buffer) - 1);
			if (bytesRead > 0)
			{
				buffer[bytesRead] = '\0';
				return std::string(buffer);
			}
			else if (bytesRead == 0)
			{
				threadRunning = false;
				return "";
			}
			else
			{
				perror("Parent read");
				threadRunning = false;
				return "";
			}
		}
		else
		{
			return "";
		}
	}

	void cleanUpProcesses()
	{
		kill(child_pid, SIGINT);
		shutdown(pipefd[1], SHUT_WR);
		int status;
		waitpid(child_pid, &status, WNOHANG);
		close(pipefd[0]);
	}
};