// Replace PUT_USERID_HERE with your actual BYU CS user id, which you can find
// by running `id -u` on a CS lab machine.
#define USERID 1823703642

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

int verbose = 0;

void print_bytes(unsigned char *bytes, int byteslen);
int parse_sockaddr(const struct sockaddr *addr, char *ip, unsigned short *port);
int populate_sockaddr(struct sockaddr *addr, sa_family_t addr_fam, const char *ip, unsigned short port);

int main(int argc, char *argv[])
{
	if (argc != 5)
	{
		fprintf(stderr, "the number of argument is not right");
		exit(1);
	}

	// ex) ./treasure_hunter server port level seed
	char *server = argv[1];
	char *port_str = argv[2];
	char *level_str = argv[3];
	char *seed_str = argv[4];

	// atoi converts string to int
	int level = atoi(level_str);
	int seed = atoi(seed_str);

	// create buf that is 8 bytes
	unsigned char buf[8];

	// set buff to 0
	bzero(buf, 8);

	// bytes 0:0, bytes 1:level, bytes 2-5:userid, bytes 6-7:seed
	buf[0] = 0;
	buf[1] = level;

	// htonl is use for int and it makes it big-indian order
	// normally 12 34 56 78, but htol makes it 78 56 34 12
	unsigned int id = htonl(USERID);
	unsigned short seed_short = htons(seed);

	memcpy(&buf[2], &id, 4);
	memcpy(&buf[6], &seed_short, 2);

	// setting up socket
	// AF_INET is IPv4 Internet Protocol, SOCK_DGRAM is UDP,
	struct addrinfo hints;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;

	// getaddrinfo takes *server, *port with *hints and **result is where it gets stored.
	struct addrinfo *result;
	int s;
	s = getaddrinfo(server, port_str, &hints, &result);
	if (s != 0)
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}

	// socket creates an endpoint of communication and return file descriptor.
	// socket(int domain, int type, int protocol) and domain is AF_INET and type is SOCK_DGRAM for this case
	int sfd;
	sfd = socket(hints.ai_family, hints.ai_socktype, 0);
	if (sfd < 0)
	{
		fprintf(stderr, "socket failed");
		exit(EXIT_FAILURE);
	}

	// cerating two lines here bc it has to be struct sockaddr to pass in, and don't want to cast each time
	// use remote_addr for passing in
	struct sockaddr_storage remote_addr_ss;
	struct sockaddr *remote_addr = (struct sockaddr *)&remote_addr_ss;

	// ai_addr is the struct sockaddr_storage that holds the IPv4 or IPv6 address and port.
	memcpy(remote_addr, result->ai_addr, sizeof(struct sockaddr_storage));

	// created to store ip and port
	char remote_ip[INET6_ADDRSTRLEN];
	unsigned short remote_port;

	parse_sockaddr(remote_addr, remote_ip, &remote_port);
	populate_sockaddr(remote_addr, remote_addr->sa_family, remote_ip, remote_port);

	// use local_addr for passing in
	struct sockaddr_storage local_addr_ss;
	struct sockaddr *local_addr = (struct sockaddr *)&local_addr_ss;
	char local_ip[INET6_ADDRSTRLEN];
	unsigned short local_port;

	socklen_t addr_len = sizeof(struct sockaddr_storage);
	s = getsockname(sfd, local_addr, &addr_len);
	parse_sockaddr(local_addr, local_ip, &local_port);

	ssize_t bytes_sent = sendto(sfd, buf, 8, 0, remote_addr, addr_len);
	if (bytes_sent == -1)
	{
		perror("sendto failed");
		exit(EXIT_FAILURE);
	}
	else if (bytes_sent != 8)
	{
		fprintf(stderr, "sendto() did not send the entire buffer\n");
		exit(EXIT_FAILURE);
	}

	unsigned char receive_buffer[256];
	ssize_t bytes_received = recvfrom(sfd, receive_buffer, 256, 0, local_addr, &addr_len);
	if (bytes_received == -1)
	{
		perror("recvfrom failed");
		exit(EXIT_FAILURE);
	}
	// printf("%ld\n", bytes_received);
	// print_bytes(receive_buffer, (int)bytes_received);

	// checkpoint 3
	char combined_buffer[1024];
	bzero(combined_buffer, 1024);

	unsigned int nonce;
	while (1)
	{
		unsigned char chunklen;
		unsigned char opcode;
		unsigned short opparam;

		chunklen = receive_buffer[0];
		char chunk[128];

		if (chunklen == 0)
		{
			// printf("Hunt is over. All chunks of the treasure have been received.\n");
			printf("%s\n", combined_buffer);
			exit(EXIT_SUCCESS);
		}
		// when chunklen is 1 to 127
		else if (chunklen <= 127)
		{
			memcpy(chunk, &receive_buffer[1], chunklen);
			chunk[chunklen] = '\0';
			// the last value passing in below represents the max number of characters
			// that can be appended to in combined_buffer w/o causing overflow.
			strncat(combined_buffer, chunk, sizeof(combined_buffer) - strlen(combined_buffer) - 1);
		}

		// when chunklen is 128 +
		else
		{
			printf("Server encountered an error with code: %d\n", chunklen);
			exit(EXIT_FAILURE);
		}

		opcode = receive_buffer[chunklen + 1];

		memcpy(&nonce, &receive_buffer[chunklen + 4], sizeof(unsigned int));

		if (opcode == 1)
		{
			memcpy(&opparam, &receive_buffer[chunklen + 2], sizeof(unsigned short));
			opparam = ntohs(opparam);

			remote_port = opparam;
			populate_sockaddr(remote_addr, remote_addr->sa_family, remote_ip, remote_port);
		}

		else if (opcode == 2)
		{
			memcpy(&opparam, &receive_buffer[chunklen + 2], sizeof(unsigned short));
			opparam = ntohs(opparam);

			close(sfd);

			sfd = socket(hints.ai_family, hints.ai_socktype, 0);
			if (sfd < 0)
			{
				fprintf(stderr, "socket failed");
				exit(EXIT_FAILURE);
			}

			local_port = opparam;
			populate_sockaddr(local_addr, local_addr->sa_family, NULL, local_port);

			if (bind(sfd, local_addr, sizeof(struct sockaddr_storage)) < 0)
			{
				perror("bind()");
				exit(EXIT_FAILURE);
			}
		}

		else if (opcode == 3)
		{
			unsigned short m;
			memcpy(&m, &receive_buffer[chunklen + 2], sizeof(unsigned short));
			m = htons(m);

			struct sockaddr_storage recvfrom_addr_ss;
			struct sockaddr *recvfrom_addr = (struct sockaddr *)&recvfrom_addr_ss;

			unsigned int sum = 0;
			for (unsigned short i = 0; i < m; i++)
			{
				unsigned char tempbuff[0];
				ssize_t recv_bytes = recvfrom(sfd, tempbuff, 0, 0, recvfrom_addr, &addr_len);
				if (recv_bytes == -1)
				{
					perror("recvfrom failed");
					exit(EXIT_FAILURE);
				}

				unsigned short new_remote_port;
				char new_remote_ip[INET6_ADDRSTRLEN];
				parse_sockaddr(recvfrom_addr, new_remote_ip, &new_remote_port);

				sum += new_remote_port;
			}

			nonce = sum;
			nonce = htonl(nonce);
		}
		// where my mistake was
		// memcpy(&nonce, &receive_buffer[chunklen + 4], sizeof(unsigned int));
		nonce = ntohl(nonce);

		/*
		printf("%x\n", chunklen);
		printf("%s\n", chunk);
		printf("%x\n", opcode);
		printf("%x\n", opparam);
		printf("%x\n", nonce);
		*/

		unsigned int noncePlusOne = ++nonce;

		// printf("%x\n", noncePlusOne);

		noncePlusOne = htonl(noncePlusOne);

		bytes_sent = sendto(sfd, &noncePlusOne, 4, 0, remote_addr, addr_len);
		if (bytes_sent == -1)
		{
			perror("sendto failed");
			exit(EXIT_FAILURE);
		}
		else if (bytes_sent != 4)
		{
			fprintf(stderr, "sendto() did not send the entire buffer\n");
			exit(EXIT_FAILURE);
		}

		bytes_received = recvfrom(sfd, receive_buffer, 256, 0, local_addr, &addr_len);
		if (bytes_received == -1)
		{
			perror("recvfrom failed");
			exit(EXIT_FAILURE);
		}

		// printf("%ld\n", bytes_received);
		// print_bytes(receive_buffer, (int)bytes_received);
	}
}

void print_bytes(unsigned char *bytes, int byteslen)
{
	int i, j, byteslen_adjusted;

	if (byteslen % 8)
	{
		byteslen_adjusted = ((byteslen / 8) + 1) * 8;
	}
	else
	{
		byteslen_adjusted = byteslen;
	}
	for (i = 0; i < byteslen_adjusted + 1; i++)
	{
		if (!(i % 8))
		{
			if (i > 0)
			{
				for (j = i - 8; j < i; j++)
				{
					if (j >= byteslen_adjusted)
					{
						printf("  ");
					}
					else if (j >= byteslen)
					{
						printf("  ");
					}
					else if (bytes[j] >= '!' && bytes[j] <= '~')
					{
						printf(" %c", bytes[j]);
					}
					else
					{
						printf(" .");
					}
				}
			}
			if (i < byteslen_adjusted)
			{
				printf("\n%02X: ", i);
			}
		}
		else if (!(i % 4))
		{
			printf(" ");
		}
		if (i >= byteslen_adjusted)
		{
			continue;
		}
		else if (i >= byteslen)
		{
			printf("   ");
		}
		else
		{
			printf("%02X ", bytes[i]);
		}
	}
	printf("\n");
}

int parse_sockaddr(const struct sockaddr *addr, char *ip, unsigned short *port)
{
	sa_family_t addr_fam = addr->sa_family;
	if (addr_fam == AF_INET)
	{
		// We are using IPv4.
		struct sockaddr_in *ipv4addr = (struct sockaddr_in *)addr;

		// Populate ip with the presentation format of the IPv4
		// address.
		inet_ntop(addr_fam, &ipv4addr->sin_addr, ip, INET6_ADDRSTRLEN);

		// Populate port with the value of the port, converted to host
		// byte order.
		*port = ntohs(ipv4addr->sin_port);
	}
	else if (addr_fam == AF_INET6)
	{
		// We are using IPv6.
		struct sockaddr_in6 *ipv6addr = (struct sockaddr_in6 *)addr;

		// Populate ip with the presentation format of the IPv6
		// address.
		inet_ntop(addr_fam, &ipv6addr->sin6_addr,
				  ip, INET6_ADDRSTRLEN);

		// Populate port with the value of the port, converted to host
		// byte order.
		*port = ntohs(ipv6addr->sin6_port);
	}
	else
	{
		// TODO account for other address families
		return -1;
	}
	return 0;
}

int populate_sockaddr(struct sockaddr *addr, sa_family_t addr_fam,
					  const char *ip, unsigned short port)
{
	if (addr_fam == AF_INET)
	{
		// We are using IPv4.
		struct sockaddr_in *ipv4addr = (struct sockaddr_in *)addr;

		// Populate ipv4addr->sin_family with the address family
		// associated with the socket.
		ipv4addr->sin_family = addr_fam;
		if (ip == NULL)
		{
			// By default, bind to all local IPv4 addresses
			// (i.e., the IPv4 "wildcard" address)
			ip = "0.0.0.0";
		}

		// Use inet_pton() to populate ipv4addr->sin_addr.s_addr with
		// the bytes comprising the IPv4 address contained in ip.
		if (inet_pton(addr_fam, ip, &ipv4addr->sin_addr.s_addr) <= 0)
		{
			fprintf(stderr, "Error: invalid IPv4 address "
							"passed to bind_from_str(): %s\n",
					ip);
			exit(EXIT_FAILURE);
		}

		// Populate ipv4addr->sin_port with the specified port, in
		// network byte order.
		ipv4addr->sin_port = htons(port);
	}
	else if (addr_fam == AF_INET6)
	{
		// We are using IPv6.
		struct sockaddr_in6 *ipv6addr = (struct sockaddr_in6 *)addr;

		// Populate ipv6addr->sin6_family with the address family
		// associated with the socket.
		ipv6addr->sin6_family = addr_fam;
		if (ip == NULL)
		{
			// By default, bind to all local IPv6 addresses
			// (i.e., the IPv4 "wildcard" address)
			ip = "::";
		}

		// Use inet_pton() to populate ipv6addr->sin6_addr.s6_addr with
		// the bytes comprising the IPv6 address contained in ip.
		if (inet_pton(addr_fam, ip, &ipv6addr->sin6_addr.s6_addr) <= 0)
		{
			fprintf(stderr, "Error: invalid IPv6 address "
							"passed to bind_from_str(): %s\n",
					ip);
			exit(EXIT_FAILURE);
		}

		// Populate ipv6addr->sin6_port with the specified port, in
		// network byte order.
		ipv6addr->sin6_port = htons(port);
	}
	else
	{
		// TODO account for other address families
		return -1;
	}
	return 0;
}