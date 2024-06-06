#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#define PORT "4444"
const int BACKLOG = 10;

int main()
{
	int sockfd, client_fd;
	struct addrinfo hints, *servinfo;
	socklen_t sin_size;
	int yes = 1;
	int rv;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	rv = getaddrinfo(NULL, PORT, &hints, &servinfo);
	if (rv != 0)
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
	if (sockfd == -1)
	{
		perror("socket");
		return 1;
	}

	rv = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
	if (rv == -1)
	{
		perror("setsockopt");
		return 1;
	}
	
	rv = bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen);
	if (rv == -1)
	{
		perror("bind");
		return 1;
	}

	freeaddrinfo(servinfo);

	rv = listen(sockfd, BACKLOG);
	if (rv == -1)
	{
		perror("listen");
		return 1;
	}

	client_fd = accept(sockfd, NULL, NULL);
	if (client_fd == -1)
	{
		perror("accept");
		return 1;
	}

	char recvbuf[512];
	int iSendResult;

	do
	{
		rv = recv(client_fd, recvbuf, 512, 0);
		if (rv > 0)
		{
			printf("Bytesreceived: %d\n", rv);
			iSendResult = send(client_fd, recvbuf, rv, 0);
			if (iSendResult == -1)
			{
				perror("send");
				return 1;
			}
			printf("Bytes sent: %d\n", iSendResult);
		}
		else if (rv == 0)
		{
			printf("Connection closing...\n");
		}
		else
		{
			perror("recv");
			return 1;
		}
	} while (rv > 0);

	return 0;
}
