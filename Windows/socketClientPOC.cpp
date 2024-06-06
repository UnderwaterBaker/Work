#include <winsock2.h>
#include <ws2tcpip.h>
#include <print>

#pragma comment(lib, "Ws2_32.lib")

#define DEFAULT_PORT "4444"
const int DEFAULT_BUFLEN{ 512 };

int main(int argc, char *argv[])
{
	WSADATA wsaData;

	// Initialize Winsock
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0)
	{
		std::print("WSAStartup failed: {}\n", iResult);
		return 1;
	}

	struct addrinfo hints, *result = NULL;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	iResult = getaddrinfo(argv[1], DEFAULT_PORT, &hints, &result);
	if (iResult != 0)
	{
		std::print("getaddrinfo failed: {}\n", iResult);
		WSACleanup();
		return 1;
	}

	SOCKET ConnectSocket = INVALID_SOCKET;

	// Attempt to connect to the first address returned by getaddrinfo
	// Create a SOCKET for connecting to server
	ConnectSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (ConnectSocket == INVALID_SOCKET)
	{
		std::print("socket failed: {}\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	// Connect to server
	iResult = connect(ConnectSocket, result->ai_addr, static_cast<int>(result->ai_addrlen));
	if (iResult == SOCKET_ERROR)
	{
		closesocket(ConnectSocket);
		ConnectSocket = INVALID_SOCKET;
	}

	// Should try next address returned by getaddrinfo if connect failed, but here we keep it simple

	freeaddrinfo(result);

	if (ConnectSocket == INVALID_SOCKET)
	{
		std::print("Unable to connect to server\n");
		WSACleanup();
		return 1;
	}

	const char* sendbuf = "this is a test";
	char recvbuf[DEFAULT_BUFLEN];

	// Send an initial buffer
	iResult = send(ConnectSocket, sendbuf, static_cast<int>(strlen(sendbuf)), 0);
	if (iResult == SOCKET_ERROR)
	{
		std::print("Send failed: {}\n", WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}

	std::print("Bytes sent: {}\n", iResult);

	// Shutdown the connection for sending since no more data will be sent
	// the client can still use the ConnectSocket for receiving data
	iResult = shutdown(ConnectSocket, SD_SEND);
	if (iResult == SOCKET_ERROR)
	{
		std::print("shutdown failed: {}\n", WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}

	// Receive data until the server closes the connection
	do
	{
		iResult = recv(ConnectSocket, recvbuf, DEFAULT_BUFLEN, 0);
		if (iResult > 0)
			std::print("Bytes received: {}\n", iResult);
		else if (iResult == 0)
			std::print("Connection closed\n");
		else
			std::print("revc failed: {}\n", WSAGetLastError());
	} while (iResult > 0);

	// Cleanup
	closesocket(ConnectSocket);
	WSACleanup();

	return 0;
}
