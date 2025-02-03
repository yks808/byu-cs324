#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <string.h>
#include <netdb.h>

/* Recommended max object size */
#define MAX_OBJECT_SIZE 102400
#define MAX_EVENTS 10
#define MAX_CLIENTS 100
#define BUFFER_SIZE 16384
#define REQUEST_SIZE 2048

#define READ_REQUEST 1
#define SEND_REQUEST 2
#define READ_RESPONSE 3
#define SEND_RESPONSE 4

struct request_info
{
	int client_to_proxy_fd;
	int proxy_to_server_fd;
	int state;
	char buffer[BUFFER_SIZE];
	ssize_t total_bytes_client_read;
	ssize_t total_bytes_server_write;
	char response_buffer[BUFFER_SIZE];
	ssize_t response_len;
	char new_request[REQUEST_SIZE];
	int offset;
};

static const char *user_agent_hdr = "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:97.0) Gecko/20100101 Firefox/97.0";

int complete_request_received(char *);
int parse_request(char *, char *, char *, char *, char *);
void test_parser();
void print_bytes(unsigned char *, int);
int open_sfd(int port);
void handle_new_clients(int sfd, int epoll_fd);
void handle_client(struct request_info *req_info, int epoll_fd);

int main(int argc, char *argv[])
{
	int port, sfd, epoll_fd, n_events;
	struct epoll_event event, events[MAX_EVENTS];

	if (argc != 2)
	{
		fprintf(stderr, "Usage: %s <port>\n", argv[0]);
		return 1;
	}

	port = atoi(argv[1]);
	sfd = open_sfd(port);

	epoll_fd = epoll_create1(0);
	if (epoll_fd == -1)
	{
		perror("epoll_create1 failed");
		exit(EXIT_FAILURE);
	}

	event.events = EPOLLIN | EPOLLET;
	// need to change - new request info, not fd but member
	// event.data.fd = sfd;
	struct request_info request;
	request.client_to_proxy_fd = sfd;
	event.data.ptr = &request;

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sfd, &event) == -1)
	{
		perror("epoll_ctl failed");
		exit(EXIT_FAILURE);
	}

	while (1)
	{
		n_events = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
		if (n_events == -1)
		{
			perror("epoll_wait failed");
			exit(EXIT_FAILURE);
		}

		for (int i = 0; i < n_events; i++)
		{
			struct request_info *req_info = (struct request_info *)events[i].data.ptr;
			if (req_info->client_to_proxy_fd == sfd)
			{
				handle_new_clients(sfd, epoll_fd);
			}
			else
			{
				handle_client(req_info, epoll_fd);
			}
		}
	}

	close(sfd);
	close(epoll_fd);

	printf("%s\n", user_agent_hdr);
	return 0;
}

int complete_request_received(char *request)
{
	char *end_of_headers = strstr(request, "\r\n\r\n");

	if (end_of_headers != NULL)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

int parse_request(char *request, char *method, char *hostname, char *port, char *path)
{
	// Extract method
	char *end_of_method = strstr(request, " ");
	if (end_of_method != NULL)
	{
		strncpy(method, request, end_of_method - request);
		method[end_of_method - request] = '\0';
	}
	else
	{
		printf("Method failed\n");
		return 0;
	}

	// Extract URL
	char *start_of_url = strstr(request, "http://");
	if (start_of_url != NULL)
	{
		char *end_of_url = strstr(start_of_url, " ");
		if (end_of_url != NULL)
		{
			int url_length = end_of_url - start_of_url;
			//+ 1 for '0'
			char url[url_length + 1];
			strncpy(url, start_of_url, url_length);
			url[url_length] = '\0';

			// get hostname, port, and path from the URL
			// skip "http://"
			char *start_of_hostname = start_of_url + 7;
			char *end_of_hostname = strchr(start_of_hostname, ':');
			char *end_of_path = strchr(start_of_hostname, '/');

			if (end_of_hostname != NULL && (end_of_path == NULL || end_of_path > end_of_hostname))
			{
				int hostname_length = end_of_hostname - start_of_hostname;
				strncpy(hostname, start_of_hostname, hostname_length);
				hostname[hostname_length] = '\0';

				int port_length;
				if (end_of_path != NULL)
				{
					port_length = end_of_path - end_of_hostname - 1;
				}
				else
				{
					port_length = start_of_url + url_length - end_of_hostname - 1;
				}

				strncpy(port, end_of_hostname + 1, port_length);
				port[port_length] = '\0';
			}
			else
			{
				strcpy(port, "80");
				int hostname_length;
				if (end_of_path != NULL)
				{
					hostname_length = end_of_path - start_of_hostname;
				}
				else
				{
					hostname_length = start_of_url + url_length - start_of_hostname;
				}
				strncpy(hostname, start_of_hostname, hostname_length);
				hostname[hostname_length] = '\0';
			}

			if (end_of_path != NULL)
			{
				int path_length = start_of_url + url_length - end_of_path;
				strncpy(path, end_of_path, path_length);
				path[path_length] = '\0';
			}
			else
			{
				printf("Path extraction failed\n");
				return 0;
			}
			return 1;
		}
		else
		{
			printf("URL failed\n");
			return 0;
		}
	}
	else
	{
		printf("URL cannot find\n");
		return 0;
	}
}

void test_parser()
{
	int i;
	char method[16], hostname[64], port[8], path[64];

	char *reqs[] = {
		"GET http://www.example.com/index.html HTTP/1.0\r\n"
		"Host: www.example.com\r\n"
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\r\n"
		"Accept-Language: en-US,en;q=0.5\r\n\r\n",

		"GET http://www.example.com:8080/index.html?foo=1&bar=2 HTTP/1.0\r\n"
		"Host: www.example.com:8080\r\n"
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\r\n"
		"Accept-Language: en-US,en;q=0.5\r\n\r\n",

		"GET http://localhost:1234/home.html HTTP/1.0\r\n"
		"Host: localhost:1234\r\n"
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\r\n"
		"Accept-Language: en-US,en;q=0.5\r\n\r\n",

		"GET http://www.example.com:8080/index.html HTTP/1.0\r\n",

		NULL};

	for (i = 0; reqs[i] != NULL; i++)
	{
		printf("Testing %s\n", reqs[i]);
		if (parse_request(reqs[i], method, hostname, port, path))
		{
			printf("METHOD: %s\n", method);
			printf("HOSTNAME: %s\n", hostname);
			printf("PORT: %s\n", port);
			printf("PATH: %s\n", path);
		}
		else
		{
			printf("REQUEST INCOMPLETE\n");
		}
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

int open_sfd(int port)
{
	// create socket
	int server_fd;
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd == -1)
	{
		perror("Socket creation failed");
		exit(EXIT_FAILURE);
	}

	// allow to immediately restart your HTTP proxy after failure, rather than having to wait for it to time out.
	int optval = 1;
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)) == -1)
	{
		perror("Setsockopt failed");
		exit(EXIT_FAILURE);
	}

	// Configure client socket for non-blocking I/O
	// retrieves the current file status and set it nonblocking by bitwise OR (|) the retrieved flags with O_NONBLOCK(flag indicating non-blocking mode)
	if (fcntl(server_fd, F_SETFL, fcntl(server_fd, F_GETFL, 0) | O_NONBLOCK) < 0)
	{
		fprintf(stderr, "error setting socket option\n");
		exit(1);
	}

	// bind socket to port
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		perror("Bind failed");
		exit(EXIT_FAILURE);
	}

	// listen for incoming connections
	if (listen(server_fd, 10) < 0)
	{
		perror("Listen failed");
		exit(EXIT_FAILURE);
	}

	return server_fd;
}
void handle_new_clients(int sfd, int epoll_fd)
{
	struct epoll_event event;
	// EPOLLIN (event is ready for reading)
	// EPOLLET (epol event will be triggered only when the state of the file descriptor changes from not ready to ready)
	event.events = EPOLLIN | EPOLLET;
	event.data.ptr = NULL;

	while (1)
	{
		struct sockaddr_in client_addr;
		socklen_t client_len = sizeof(client_addr);
		int client_fd = accept(sfd, (struct sockaddr *)&client_addr, &client_len);

		if (client_fd == -1)
		{
			// no more clients currently pending
			if (errno == EAGAIN || errno == EWOULDBLOCK)
			{
				break;
			}
			else
			{
				perror("accept failed");
				exit(EXIT_FAILURE);
			}
		}

		// Configure client socket for non-blocking I/O
		if (fcntl(client_fd, F_SETFL, fcntl(client_fd, F_GETFL, 0) | O_NONBLOCK) < 0)
		{
			fprintf(stderr, "error setting socket option\n");
			exit(1);
		}

		// Allocate memory for request_info struct and initialize
		struct request_info *req_info = malloc(sizeof(struct request_info));
		if (req_info == NULL)
		{
			perror("malloc failed");
			exit(EXIT_FAILURE);
		}
		memset(req_info, 0, sizeof(struct request_info));
		// initial state
		req_info->state = READ_REQUEST;
		req_info->client_to_proxy_fd = client_fd;
		req_info->offset = 0;

		// register client socket with epoll instance
		event.data.ptr = req_info;

		// adding a new file descriptor(client_fd) to be monitored by the epoll instance(epoll_fd)
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &event) == -1)
		{
			perror("epoll_ctl failed");
			exit(EXIT_FAILURE);
		}

		printf("New client connected: %d\n", client_fd);
	}
}
void handle_client(struct request_info *req_info, int epoll_fd)
{
	int client_socket = req_info->client_to_proxy_fd;
	int state = req_info->state;

	printf("Client socket file descriptor: %d\n", client_socket);
	printf("Current state: %d\n", state);

	switch (state)
	{
	case READ_REQUEST:
		while (1)
		{
			ssize_t bytes_read = read(client_socket, req_info->buffer + req_info->total_bytes_client_read, BUFFER_SIZE - req_info->total_bytes_client_read);
			printf("bytes = %ld\n", bytes_read);
			if (bytes_read == -1)
			{
				if (errno == EAGAIN || errno == EWOULDBLOCK)
				{
					printf("EAGAIN");
					return;
				}
				else
				{
					perror("read failed");
					close(req_info->client_to_proxy_fd);
					free(req_info);
					return;
				}
			}
			// else if (bytes_read == 0)
			// {
			// 	printf("Client closed connection\n");
			// 	close(req_info->client_to_proxy_fd);
			// 	free(req_info);
			// 	return;
			// }
			else
			{
				req_info->total_bytes_client_read += bytes_read;
				printf("%ld\n", req_info->total_bytes_client_read);
				// printf("%s\n", req_info->buffer);
				print_bytes(req_info->buffer, req_info->total_bytes_client_read);

				char *end_of_request = strstr(req_info->buffer, "\r\n\r\n");
				if (end_of_request != NULL)
				{
					printf("in end of request\n");
					*end_of_request = '\0';
					req_info->buffer[req_info->total_bytes_client_read] = '\0';
					printf("Received HTTP request:\n");
					print_bytes((unsigned char *)req_info->buffer, req_info->total_bytes_client_read);

					char method[16], hostname[64], port[8], path[64];
					if (parse_request(req_info->buffer, method, hostname, port, path))
					{

						printf("Method: %s\n", method);
						printf("Hostname: %s\n", hostname);
						printf("Port: %s\n", port);
						printf("Path: %s\n", path);

						char new_request[1024];
						snprintf(new_request, 1024, "%s %s HTTP/1.0\r\nHost: %s:%s\r\nUser-Agent: %s\r\nConnection: close\r\nProxy-Connection: close\r\n\r\n",
								 method, path, hostname, port, user_agent_hdr);
						printf("Created Proxy-to-server HTTP request:\n");
						print_bytes((unsigned char *)new_request, strlen(new_request));
						strcpy(req_info->new_request, new_request);

						printf("Received full request:\n%s\n", req_info->buffer);

						int server_fd = -1;
						struct addrinfo hints, *server_info = NULL;
						memset(&hints, 0, sizeof hints);
						hints.ai_family = AF_INET;
						hints.ai_socktype = SOCK_STREAM;

						int status = getaddrinfo(hostname, port, &hints, &server_info);
						if (status != 0)
						{
							fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
							close(req_info->client_to_proxy_fd);
							free(req_info);
							return;
						}

						struct addrinfo *p;
						for (p = server_info; p != NULL; p = p->ai_next)
						{

							server_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
							if (server_fd == -1)
							{
								perror("Socket creation error");
								continue;
							}

							if (connect(server_fd, p->ai_addr, p->ai_addrlen) == -1)
							{
								close(req_info->client_to_proxy_fd);
								close(server_fd);
								perror("Connect failed");
								continue;
							}
							// successfully connected
							break;
						}

						if (server_fd == -1)
						{
							perror("Failed to connect to server");
							close(req_info->client_to_proxy_fd);
							free(req_info);
							return;
						}

						// unregister client-to-proxy socket from epoll instance
						struct epoll_event event;
						// event.events = EPOLLIN | EPOLLET;
						// event.data.fd = req_info->client_to_proxy_fd;
						if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, req_info->client_to_proxy_fd, NULL) == -1)
						{
							perror("epoll_ctl");
							close(req_info->client_to_proxy_fd);
							free(req_info);
							return;
						}

						// Register server_fd with epoll for writing
						event.events = EPOLLOUT | EPOLLET;
						event.data.ptr = req_info;
						if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event) == -1)
						{
							perror("epoll_ctl");
							close(req_info->client_to_proxy_fd);
							close(server_fd);
							free(req_info);
							return;
						}

						req_info->proxy_to_server_fd = server_fd;
						printf("here\n");
						req_info->state = SEND_REQUEST;
						break;
					}
				}
				printf("if did not happen\n");
				return;
			}
		}
		break;

	case SEND_REQUEST:
		while (1)
		{
			ssize_t bytes_sent = send(req_info->proxy_to_server_fd, req_info->new_request, strlen(req_info->new_request), 0);
			if (bytes_sent < 0)
			{
				if (errno == EAGAIN || errno == EWOULDBLOCK)
				{
					return;
				}
				else
				{
					perror("send failed");
					close(client_socket);
					close(req_info->proxy_to_server_fd);
					free(req_info);
					return;
				}
			}
			else
			{
				printf("HTTP request sent to server\n");

				// Unregister the proxy-to-server socket with the epoll instance for writing.
				struct epoll_event event;
				event.events = EPOLLIN | EPOLLET;
				event.data.fd = req_info->proxy_to_server_fd;
				if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, req_info->proxy_to_server_fd, &event) == -1)
				{
					perror("epoll_ctl");
					close(client_socket);
					close(req_info->proxy_to_server_fd);
					free(req_info);
					return;
				}

				// Register the proxy-to-server socket with the epoll instance for reading.
				event.events = EPOLLIN | EPOLLET;
				event.data.ptr = req_info;
				if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, req_info->proxy_to_server_fd, &event) == -1)
				{
					perror("epoll_ctl");
					close(client_socket);
					close(req_info->proxy_to_server_fd);
					free(req_info);
					return;
				}

				req_info->state = READ_RESPONSE;
				break;
			}
		}
		break;

	case READ_RESPONSE:
		ssize_t buffer_index = req_info->response_len;
		while (1)
		{
			ssize_t bytes_received = recv(req_info->proxy_to_server_fd, req_info->response_buffer + buffer_index, sizeof(req_info->response_buffer) - buffer_index, 0);
			if (bytes_received == -1)
			{
				if (errno == EAGAIN || errno == EWOULDBLOCK)
				{
					return;
				}
				else
				{
					perror("read failed");
					close(req_info->client_to_proxy_fd);
					close(req_info->proxy_to_server_fd);
					free(req_info);
					return;
				}
			}
			else if (bytes_received == 0)
			{
				// close the proxy-to-server socket.
				close(req_info->proxy_to_server_fd);

				// use print_bytes() to print out the HTTP response you received.
				printf("Received HTTP response:\n");
				printf("%s\n", req_info->response_buffer);

				// register the client-to-proxy socket with the epoll instance for writing.
				struct epoll_event event;
				event.events = EPOLLOUT | EPOLLET;
				event.data.ptr = req_info;
				if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, req_info->client_to_proxy_fd, &event) == -1)
				{
					perror("epoll_ctl");
					close(req_info->client_to_proxy_fd);
					free(req_info);
					return;
				}

				// change state
				req_info->state = SEND_RESPONSE;
				break;
			}
			else
			{

				buffer_index += bytes_received;
				req_info->response_len = buffer_index;
				printf("%ld\n", buffer_index);
				// Print the received bytes
				// printf("Received HTTP response:\n");
				// print_bytes((unsigned char *)req_info->response_buffer, buffer_index);
			}
		}

	case SEND_RESPONSE:

		while (1)
		{
			ssize_t bytes_sent = write(req_info->client_to_proxy_fd, req_info->response_buffer + req_info->offset, req_info->response_len - req_info->offset);
			if (bytes_sent < 0)
			{
				if (errno == EAGAIN || errno == EWOULDBLOCK)
				{
					return;
				}
				else
				{
					perror("write failed");
					close(req_info->client_to_proxy_fd);
					free(req_info);
					return;
				}
			}
			else if (bytes_sent == 0)
			{
				if (recv(req_info->client_to_proxy_fd, NULL, 0, MSG_PEEK) == 0)
				{
					printf("Client closed connection\n");
				}
				else
				{
					printf("send() returned 0 but connection is still open\n");
				}
				close(req_info->client_to_proxy_fd);
				free(req_info);
				return;
			}
			else
			{
				printf("Sent %zd bytes of HTTP response to client\n", bytes_sent);
				req_info->offset += bytes_sent;

				if (req_info->offset == req_info->response_len)
				{
					close(req_info->client_to_proxy_fd);
					free(req_info);
					printf("Entire HTTP response sent to client\n");
					// print_bytes((unsigned char *)req_info->response_buffer, req_info->response_len);
					return;
				}
			}
		}
		break;
	}
}

