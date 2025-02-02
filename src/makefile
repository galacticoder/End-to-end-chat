CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++20 -g
LIBS = -lfmt -lssl -lcrypto -lcryptopp

TARGETS = server client

all: $(TARGETS)

server: server.cpp
	$(CXX) $(CXXFLAGS) -o server server.cpp $(LIBS)

client: client.cpp
	$(CXX) $(CXXFLAGS) -o client client.cpp $(LIBS)

clean:
	rm -f $(TARGETS)

.PHONY: all clean